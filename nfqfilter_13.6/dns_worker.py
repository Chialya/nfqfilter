#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
import os
import queue
import socket
import struct
import threading
import time
from datetime import datetime

from logger import log
from cache import decision_cache_key
from ptr_blocklist import PTRBlocklist


from config import (
    DNS_SERVERS, DNS_NAMES, DNS_PORT, DNS_TIMEOUT, DNS_DOWN_TIME,
    TEMP_BLOCK_TTL, DNS_TIMEOUT_DROP_TTL,
    HEALTH_TEST_IP, HEALTH_TEST_PTR, HEALTH_POSITIVE_TTL,
    HEALTH_NEGATIVE_TTL, HEALTH_TIMEOUT, DNS_WORKERS, DNS_ERROR_LOG,
)


class DNSHealthCheck:
    """Ein gemeinsamer, zeitlich begrenzter Test für alle DNS-Worker."""

    def __init__(self, dns_query):
        self.dns_query = dns_query
        self.lock = threading.Lock()
        self.event = None
        self.running = False
        self.result = False
        self.valid_until = 0.0
        self.generation = 0

    def check(self):
        with self.lock:
            now = time.monotonic()
            if not self.running and now < self.valid_until:
                return self.result

            if not self.running:
                self.running = True
                self.generation += 1
                generation = self.generation
                self.event = threading.Event()
                event = self.event
                threading.Thread(
                    target=self._run, args=(generation,), daemon=True
                ).start()
                # Selbst wenn der Test-Thread hängt, weckt dieser Wächter alle.
                timer = threading.Timer(
                    HEALTH_TIMEOUT, self._complete, args=(generation, False)
                )
                timer.daemon = True
                timer.start()
            else:
                event = self.event

        # Zweite Absicherung, falls sogar der Timer-Thread ausfällt.
        event.wait(HEALTH_TIMEOUT + 0.2)
        with self.lock:
            if self.running and self.event is event:
                self._complete_locked(self.generation, False)
            return self.result

    def _run(self, generation):
        try:
            qname = ipaddress.ip_address(HEALTH_TEST_IP).reverse_pointer
            for server in DNS_SERVERS:
                hostname, status, _ = self.dns_query(qname, server)
                if status == "OK" and hostname and hostname.lower().rstrip(".") == HEALTH_TEST_PTR:
                    self._complete(generation, True)
                    return
        except Exception:
            pass
        self._complete(generation, False)

    def _complete(self, generation, result):
        with self.lock:
            self._complete_locked(generation, result)

    def _complete_locked(self, generation, result):
        if not self.running or generation != self.generation:
            return
        self.result = result
        self.valid_until = time.monotonic() + (
            HEALTH_POSITIVE_TTL if result else HEALTH_NEGATIVE_TTL
        )
        self.running = False
        self.event.set()



class DNSWorker:

    def __init__(
        self,
        cache,
        lib,
        nf_drop,
        nf_accept,
        on_decision=None,
        on_result=None
    ):

        self.cache = cache
        self.lib = lib
        self.nf_drop = nf_drop
        self.nf_accept = nf_accept
        self.on_decision = on_decision
        self.on_result = on_result

        # PTR-Blockliste einmal laden und im RAM halten
        self.blocklist = PTRBlocklist()

        self.queue = queue.Queue()

        # IP -> wartende NFQUEUE-Pakete
        self.pending = {}
        self.pending_lock = threading.Lock()

        # Resolververwaltung
        self.resolver_lock = threading.Lock()
        self.resolver_index = 0

        self.resolvers = {
            server: {
                "down_until": 0,
                "last_failure": 0,
            }
            for server in DNS_SERVERS
        }

        self.health = DNSHealthCheck(self._dns_query)

        # Mehrere PTR-Anfragen können unabhängig auf denselben
        # gemeinsamen Gesundheitstest warten.
        self.threads = [
            threading.Thread(target=self._worker, daemon=True)
            for _ in range(DNS_WORKERS)
        ]
        for thread in self.threads:
            thread.start()


    # --------------------------------------------------
    # PTR-Anfrage übernehmen
    # --------------------------------------------------

    def lookup(
        self,
        ip,
        qh,
        packet_id,
        port,
        src_port="-",
        tcp_flags="-"
    ):

        cached = self.cache.get_entry(ip)

        if cached is not None:

            # Pipeline-Modus: DNS trifft KEIN NFQUEUE-Verdict.
            if self.on_result is not None:
                try:
                    self.on_result(ip, qh, packet_id, port, src_port,
                                   tcp_flags, cached)
                except Exception as exc:
                    self.lib.nfq_set_verdict(qh, packet_id, self.nf_drop, 0, None)
                    self._log_error(ip, 'Pipeline-Fehler: ' + str(exc))
                return

            verdict = (
                self.nf_drop
                if cached["decision"] == "DROP"
                else self.nf_accept
            )

            blocked = bool(self.on_decision and self.on_decision(
                ip, port, src_port, tcp_flags, cached['decision']))
            self.lib.nfq_set_verdict(
                qh,
                packet_id,
                self.nf_drop if blocked else verdict,
                0,
                None
            )

            log(
                "DROP"
                if blocked or cached["decision"] == "DROP"
                else "ACPT",
                cached["reason"],
                port,
                ip,
                ptr=cached["ptr"],
                match=cached["match"],
                src_port=src_port,
                tcp_flags=tcp_flags,
                resolver=cached["resolver"],
                detail=cached["detail"]
            )

            return


        packet_info = (
            ip,
            qh,
            packet_id,
            port,
            src_port,
            tcp_flags
        )


        cache_key = decision_cache_key(ip)
        reused = None
        with self.pending_lock:
            if cache_key in self.pending:
                self.pending[cache_key].append(packet_info)
                return
            # Race: ein DNS-Worker kann zwischen erstem Cache-MISS und
            # dem Eintragen in pending fertig geworden sein.
            reused = self.cache.get_entry(ip)
            if reused is None:
                self.pending[cache_key] = [packet_info]
                self.queue.put(ip)
                return
        # Bereits abgeschlossen: ueber regulaeren Cache-Pfad weiter.
        self.lookup(ip, qh, packet_id, port, src_port, tcp_flags)


    # --------------------------------------------------
    # Worker
    # --------------------------------------------------

    def _worker(self):

        while True:

            ip = self.queue.get()

            try:

                self._process(ip)

            except Exception as e:

                message = (
                    "Worker-Fehler: "
                    + str(e)
                )

                self._log_error(
                    ip,
                    message
                )

                self.cache.set(
                    ip,
                    "DROP",
                    ttl=TEMP_BLOCK_TTL,
                    reason="T",
                    resolver="-",
                    detail=message
                )

                self._finish_pending(
                    ip,
                    self.nf_drop,
                    "DROP",
                    "T",
                    resolver="-",
                    detail=message
                )

            finally:

                self.queue.task_done()


    # --------------------------------------------------
    # Entscheidung
    # --------------------------------------------------

    def _process(self, ip):

        hostname, error, resolver = self._ptr_lookup(ip)


        # --------------------------------------------------
        # DNS komplett fehlgeschlagen
        # --------------------------------------------------

        if error:
            healthy = self.health.check()

            if healthy:
                # DNS-Resolver sind erreichbar: Dreifachfehler bleibt DROP.
                decision, verdict, ttl = "DROP", self.nf_drop, DNS_TIMEOUT_DROP_TTL
                detail = error + " | HEALTH OK"
            else:
                # Resolver-Test fehlgeschlagen: DNS hat keine Sperr-Wertung.
                # Die übrigen Filterprüfungen erfolgten bereits im Callback.
                decision, verdict, ttl = "ACPT", self.nf_accept, HEALTH_NEGATIVE_TTL
                detail = error + " | HEALTH FAIL (DNS neutral)"

            self.cache.set(
                ip, decision, ttl=ttl, reason="T", resolver="-", detail=detail
            )
            self._finish_pending(
                ip, verdict, decision, "T", resolver="-", detail=detail
            )
            return

        # --------------------------------------------------
        # PTR vorhanden
        # --------------------------------------------------

        if hostname:

            match = self.blocklist.get_match(
                hostname
            )


            if match:

                self.cache.set(
                    ip,
                    "DROP",
                    reason="B",
                    ptr=hostname,
                    match=match,
                    resolver=resolver
                )

                self._finish_pending(
                    ip,
                    self.nf_drop,
                    "DROP",
                    "B",
                    ptr=hostname,
                    match=match,
                    resolver=resolver
                )

                return


            self.cache.set(
                ip,
                "ACPT",
                reason="-",
                ptr=hostname,
                resolver=resolver
            )

            self._finish_pending(
                ip,
                self.nf_accept,
                "ACPT",
                "-",
                ptr=hostname,
                resolver=resolver
            )

            return


        # --------------------------------------------------
        # Kein PTR / NXDOMAIN / NOERROR ohne PTR
        # IPv6 ohne PTR -> ACPT
        # IPv4 ohne PTR -> DROP
        # --------------------------------------------------

        if ipaddress.ip_address(ip).version == 6:

            self.cache.set(
                ip,
                "ACPT",
                ttl=TEMP_BLOCK_TTL,
                reason="-",
                resolver=resolver
            )

            self._finish_pending(
                ip,
                self.nf_accept,
                "ACPT",
                "-",
                resolver=resolver
            )

            return

        self.cache.set(
            ip,
            "DROP",
            ttl=TEMP_BLOCK_TTL,
            reason="-",
            resolver=resolver
        )

        self._finish_pending(
            ip,
            self.nf_drop,
            "DROP",
            "-",
            resolver=resolver
        )


    # --------------------------------------------------
    # Wartende Pakete abschließen
    # --------------------------------------------------

    def _finish_pending(
        self,
        ip,
        verdict,
        decision,
        reason,
        ptr="-",
        match="-",
        resolver="-",
        detail=None
    ):

        with self.pending_lock:
            packets = self.pending.pop(decision_cache_key(ip), [])

        cached = self.cache.get_entry(ip)
        for (
            source_ip,
            qh,
            packet_id,
            port,
            src_port,
            tcp_flags
        ) in packets:
            if self.on_result is not None:
                # DNS ist nur eine Zwischenpruefung. Die nachfolgende
                # API-/Endentscheidung uebernimmt das Paket.
                try:
                    self.on_result(source_ip, qh, packet_id, port,
                                   src_port, tcp_flags, cached)
                except Exception as exc:
                    self.lib.nfq_set_verdict(qh, packet_id, self.nf_drop, 0, None)
                    self._log_error(source_ip, 'Pipeline-Fehler: ' + str(exc))
                continue

            blocked = bool(self.on_decision and self.on_decision(
                source_ip, port, src_port, tcp_flags, decision))
            self.lib.nfq_set_verdict(
                qh,
                packet_id,
                self.nf_drop if blocked else verdict,
                0,
                None
            )

            log(
                'DROP' if blocked else decision,
                'I' if blocked and decision == 'ACPT' else reason,
                port,
                source_ip,
                ptr=ptr,
                match=match,
                src_port=src_port,
                tcp_flags=tcp_flags,
                resolver=resolver,
                detail=detail
            )


    # --------------------------------------------------
    # PTR Lookup
    # --------------------------------------------------

    def _ptr_lookup(self, ip):

        try:

            qname = ipaddress.ip_address(
                ip
            ).reverse_pointer

        except Exception as e:

            return (
                None,
                "Ungültige IP: " + str(e),
                "-"
            )


        servers = self._get_resolver_order()

        errors = []


        for server in servers:

            resolver = DNS_NAMES.get(
                server,
                "-"
            )

            hostname, status, error = self._dns_query(
                qname,
                server
            )


            # --------------------------------------------------
            # Gültige Antwort
            # --------------------------------------------------

            if status == "OK":

                self._resolver_success(
                    server
                )

                return (
                    hostname,
                    None,
                    resolver
                )


            # --------------------------------------------------
            # NXDOMAIN = gültige Antwort
            # --------------------------------------------------

            if status == "NXDOMAIN":

                self._resolver_success(
                    server
                )

                return (
                    None,
                    None,
                    resolver
                )


            # --------------------------------------------------
            # Resolverfehler
            # --------------------------------------------------

            self._resolver_failure(
                server
            )

            message = (
                resolver
                + " "
                + server
                + " "
                + error
            )

            errors.append(
                message
            )

            self._log_error(
                ip,
                message
            )


        if errors:

            return (
                None,
                " | ".join(errors),
                "-"
            )


        return (
            None,
            "Kein DNS-Resolver verfügbar",
            "-"
        )

    # --------------------------------------------------
    # Resolver-Reihenfolge
    # --------------------------------------------------

    def _get_resolver_order(self):

        now = time.time()


        with self.resolver_lock:

            # Alle drei Resolver müssen bei einem echten Dreifachfehler
            # geprüft werden. DOWN-Resolver stehen am Ende der Reihenfolge.
            start = self.resolver_index % len(DNS_SERVERS)
            ordered = DNS_SERVERS[start:] + DNS_SERVERS[:start]
            self.resolver_index += 1
            return sorted(
                ordered,
                key=lambda server: self.resolvers[server]["down_until"] > now
            )


    # --------------------------------------------------
    # Resolver Health
    # --------------------------------------------------

    def _resolver_success(
        self,
        server
    ):

        with self.resolver_lock:

            self.resolvers[
                server
            ]["down_until"] = 0


    def _resolver_failure(
        self,
        server
    ):

        now = time.time()


        with self.resolver_lock:

            self.resolvers[
                server
            ]["last_failure"] = now

            self.resolvers[
                server
            ]["down_until"] = (
                now
                + DNS_DOWN_TIME
            )


    # --------------------------------------------------
    # DNS-Abfrage
    # --------------------------------------------------

    def _dns_query(
        self,
        qname,
        server
    ):

        transaction_id = (
            time.monotonic_ns()
            & 0xFFFF
        )

        header = struct.pack(
            "!HHHHHH",
            transaction_id,
            0x0100,
            1,
            0,
            0,
            0
        )


        qname_encoded = b""

        for label in qname.split("."):

            qname_encoded += bytes(
                [len(label)]
            )

            qname_encoded += label.encode(
                "ascii"
            )


        qname_encoded += b"\x00"


        question = (
            qname_encoded
            + struct.pack(
                "!HH",
                12,
                1
            )
        )


        packet = (
            header
            + question
        )


        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        sock.settimeout(
            DNS_TIMEOUT
        )


        try:

            sock.connect(
                (
                    server,
                    DNS_PORT
                )
            )

            sock.send(
                packet
            )

            response = sock.recv(
                4096
            )


        except socket.timeout:

            return (
                None,
                "ERROR",
                "DNS timeout"
            )


        except Exception as e:

            return (
                None,
                "ERROR",
                "DNS error: " + str(e)
            )


        finally:

            sock.close()


        if len(response) < 12:

            return (
                None,
                "ERROR",
                "DNS response too short"
            )


        response_id = struct.unpack(
            "!H",
            response[0:2]
        )[0]


        if response_id != transaction_id:

            return (
                None,
                "ERROR",
                "DNS transaction ID mismatch"
            )


        rcode = (
            response[3]
            & 0x0F
        )


        if rcode == 3:

            return (
                None,
                "NXDOMAIN",
                None
            )


        if rcode != 0:

            return (
                None,
                "ERROR",
                "DNS RCODE " + str(rcode)
            )


        answer_count = struct.unpack(
            "!H",
            response[6:8]
        )[0]


        if answer_count == 0:

            return (
                None,
                "OK",
                None
            )


        offset = 12

        offset = self._skip_name(
            response,
            offset
        )


        if offset is None:

            return (
                None,
                "ERROR",
                "DNS question malformed"
            )


        offset += 4


        for _ in range(answer_count):

            offset = self._skip_name(
                response,
                offset
            )


            if offset is None:

                return (
                    None,
                    "ERROR",
                    "DNS answer malformed"
                )


            if offset + 10 > len(response):

                return (
                    None,
                    "ERROR",
                    "DNS answer too short"
                )


            (
                rtype,
                rclass,
                ttl,
                rdlength
            ) = struct.unpack(
                "!HHIH",
                response[
                    offset:
                    offset + 10
                ]
            )


            offset += 10


            if offset + rdlength > len(response):

                return (
                    None,
                    "ERROR",
                    "DNS RDATA too short"
                )


            rdata_offset = offset


            if rtype == 12 and rclass == 1:

                hostname = self._decode_name(
                    response,
                    rdata_offset
                )


                if hostname:

                    return (
                        hostname.rstrip("."),
                        "OK",
                        None
                    )


            offset += rdlength


        return (
            None,
            "OK",
            None
        )


    # --------------------------------------------------
    # DNS Name überspringen
    # --------------------------------------------------

    def _skip_name(
        self,
        packet,
        offset
    ):

        while offset < len(packet):

            length = packet[offset]


            if length == 0:

                return offset + 1


            if length & 0xC0 == 0xC0:

                if offset + 1 >= len(packet):
                    return None

                return offset + 2


            offset += 1


            if offset + length > len(packet):
                return None


            offset += length


        return None


    # --------------------------------------------------
    # DNS Name dekodieren
    # --------------------------------------------------

    def _decode_name(
        self,
        packet,
        offset
    ):

        result = []
        seen = set()


        while offset < len(packet):

            if offset in seen:
                return None

            seen.add(offset)


            length = packet[offset]


            if length == 0:
                break


            if length & 0xC0 == 0xC0:

                if offset + 1 >= len(packet):
                    return None


                pointer = (
                    ((length & 0x3F) << 8)
                    | packet[offset + 1]
                )


                if pointer >= len(packet):
                    return None


                offset = pointer
                continue


            offset += 1


            if offset + length > len(packet):
                return None


            result.append(
                packet[
                    offset:
                    offset + length
                ].decode(
                    "ascii",
                    errors="replace"
                )
            )


            offset += length


        if not result:
            return None


        return ".".join(
            result
        )


    # --------------------------------------------------
    # DNS Fehlerlog
    # --------------------------------------------------

    def _log_error(
        self,
        ip,
        message
    ):

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )


        line = (
            timestamp
            + "\t"
            + ip
            + "\t"
            + message
            + "\n"
        )


        try:

            with open(
                DNS_ERROR_LOG,
                "a",
                encoding="utf-8"
            ) as f:

                f.write(
                    line
                )


        except Exception as e:

            print(
                "Fehler beim Schreiben von dns_errors.log:",
                e
            )
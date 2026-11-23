#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Version 13.6

import ctypes
import fcntl
import os
import ipaddress
import socket
import sys
import time
import signal
import threading
import importlib.util

# Persistenzverzeichnis zentral festlegen, bevor Projektmodule config importieren.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = "/persistent/nfqfilter.data"  # Optional z.B. "/persistent/nfqfilter.data"
if DATA_DIR:
    DATA_DIR = os.path.abspath(DATA_DIR)
else:
    DATA_DIR = os.path.join(BASE_DIR, "data")

CONFIG_FILE = os.path.join(DATA_DIR, "config.py")
if not os.path.isfile(CONFIG_FILE):
    print("NFQfilter: Konfigurationsdatei fehlt: " + CONFIG_FILE, file=sys.stderr)
    raise SystemExit(1)

try:
    _config_spec = importlib.util.spec_from_file_location("config", CONFIG_FILE)
    if _config_spec is None or _config_spec.loader is None:
        raise ImportError("Python konnte keinen Config-Loader erzeugen")
    config = importlib.util.module_from_spec(_config_spec)
    sys.modules["config"] = config
    _config_spec.loader.exec_module(config)
    config.DATA_DIR = DATA_DIR
    config.BASE_DIR = BASE_DIR
except Exception as exc:
    print("NFQfilter: Konfiguration konnte nicht geladen werden (%s): %s" %
          (CONFIG_FILE, exc), file=sys.stderr)
    raise SystemExit(1)

from packet import parse_packet
from firewall_rules import FirewallRuleManager
from dns_worker import DNSWorker
from whitelist import IPWhitelist
from logger import log
from cache import IPCache, TTLSet, LockedSet
from abuseipdb_worker import AbuseIPDBWorker
from helper_client import HelperClient
from state_worker import StateWorker
from ip_flood import IPFloodTracker
from tc_subnet24 import TcSubnet24Worker
from single_ip_filter import SingleIPFilter
from kernel_ip32 import KernelIP32Worker
from config import IP_FLOOD_PORTS, IP_FLOOD_BLOCK_TTL
from config import ABUSEIPDB_ENABLE, ABUSEIPDB_PORTS
from config import (SUBNET24_PORTS, SUBNET24_THRESHOLD, SUBNET24_WINDOW,
                    SUBNET24_BLOCK_TTL, TRUSTED_TTL, BAD_TTL, CACHE_TTL)

lib = ctypes.CDLL(
    "libnetfilter_queue.so.1",
    use_errno=True
)

libc = ctypes.CDLL(None)


NF_DROP = 0
NF_ACCEPT = 1
NFQNL_COPY_PACKET = 2


class PacketHeader(ctypes.Structure):

    _fields_ = [
        ("packet_id", ctypes.c_uint32),
        ("hw_protocol", ctypes.c_uint16),
        ("hook", ctypes.c_uint8),
        ("pad", ctypes.c_uint8),
    ]


NFQHandle = ctypes.c_void_p
NFQQueue = ctypes.c_void_p


lib.nfq_open.restype = NFQHandle


lib.nfq_unbind_pf.argtypes = [
    NFQHandle,
    ctypes.c_uint16
]

lib.nfq_unbind_pf.restype = ctypes.c_int


lib.nfq_bind_pf.argtypes = [
    NFQHandle,
    ctypes.c_uint16
]

lib.nfq_bind_pf.restype = ctypes.c_int


lib.nfq_get_msg_packet_hdr.argtypes = [
    ctypes.c_void_p
]

lib.nfq_get_msg_packet_hdr.restype = ctypes.c_void_p


lib.nfq_get_payload.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p)
]

lib.nfq_get_payload.restype = ctypes.c_int


CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_int,
    NFQQueue,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
)


lib.nfq_create_queue.argtypes = [
    NFQHandle,
    ctypes.c_uint16,
    CALLBACK,
    ctypes.c_void_p
]

lib.nfq_create_queue.restype = NFQQueue


lib.nfq_set_mode.argtypes = [
    NFQQueue,
    ctypes.c_uint8,
    ctypes.c_uint32
]

lib.nfq_set_mode.restype = ctypes.c_int


lib.nfq_fd.argtypes = [
    NFQHandle
]

lib.nfq_fd.restype = ctypes.c_int


lib.nfq_handle_packet.argtypes = [
    NFQHandle,
    ctypes.c_void_p,
    ctypes.c_int
]

lib.nfq_handle_packet.restype = ctypes.c_int


lib.nfq_set_verdict.argtypes = [
    NFQQueue,
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_void_p
]

lib.nfq_set_verdict.restype = ctypes.c_int


lib.nfq_destroy_queue.argtypes = [
    NFQQueue
]

lib.nfq_close.argtypes = [
    NFQHandle
]


libc.recv.argtypes = [
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_int
]

libc.recv.restype = ctypes.c_ssize_t


# --------------------------------------------------
# /24 Angriffserkennung
# --------------------------------------------------



class Subnet24Tracker:

    def __init__(
        self,
        threshold,
        window,
        block_ttl
    ):

        self.threshold = threshold
        self.window = window
        self.block_ttl = block_ttl

        self.observed = {}
        self.blocked = {}

        self.last_cleanup = 0
        self.lock = threading.Lock()
        # Solange tc die Sperre verwaltet, darf nur dessen Worker
        # nach der letzten Zaehlerpruefung /24-Eintraege entfernen.
        self.tc_manages_expiry = False


    def _cleanup(
        self,
        now
    ):

        if (
            now - self.last_cleanup
            < 60
        ):
            return

        self.last_cleanup = now

        expired_observed = [
            network
            for network, entry in self.observed.items()
            if now >= entry["expires"]
        ]

        for network in expired_observed:
            del self.observed[network]

        if not self.tc_manages_expiry:
            expired_blocked = [
                network
                for network, expires in self.blocked.items()
                if now >= expires
            ]

            for network in expired_blocked:
                del self.blocked[network]


    def check(self, src_ip):
        with self.lock:
            return self._check_locked(src_ip)

    def _check_locked(
        self,
        src_ip
    ):

        address = ipaddress.ip_address(
            src_ip
        )

        if address.version != 4:
            return {
                "action": "NONE"
            }

        now = time.time()

        self._cleanup(
            now
        )

        network = str(
            ipaddress.ip_network(
                src_ip + "/24",
                strict=False
            )
        )

        blocked_until = self.blocked.get(
            network
        )

        if blocked_until is not None:

            if now < blocked_until or self.tc_manages_expiry:

                self.blocked[network] = (
                    now
                    + self.block_ttl
                )

                return {
                    "action": "BLOCKED",
                    "network": network
                }

            del self.blocked[network]

        entry = self.observed.get(
            network
        )

        if (
            entry is None
            or now >= entry["expires"]
        ):

            self.observed[network] = {
                "ips": {
                    src_ip
                },
                "first": now,
                "expires": (
                    now
                    + self.window
                )
            }

            return {
                "action": "NONE"
            }

        if src_ip in entry["ips"]:
            return {
                "action": "NONE"
            }

        entry["ips"].add(
            src_ip
        )

        entry["expires"] = (
            now
            + self.window
        )

        count = len(
            entry["ips"]
        )

        if count < self.threshold:
            return {
                "action": "NONE"
            }

        elapsed = (
            now
            - entry["first"]
        )

        self.blocked[network] = (
            now
            + self.block_ttl
        )

        del self.observed[network]

        return {
            "action": "NEW_BLOCK",
            "network": network,
            "count": count,
            "elapsed": elapsed
        }


ip_flood_tracker = IPFloodTracker()
single_ip_filter = SingleIPFilter()

subnet24_tracker = Subnet24Tracker(
    SUBNET24_THRESHOLD,
    SUBNET24_WINDOW,
    SUBNET24_BLOCK_TTL
)


# DNS- und API-Zwischenergebnisse sowie ENDENTSCHEIDUNGEN getrennt.
# Alle drei Entscheidungs-Caches sind bei IPv6 /64-basiert.
cache = IPCache(ttl=CACHE_TTL)
dns_cache = IPCache(ttl=CACHE_TTL)
api_cache = IPCache(ttl=CACHE_TTL)

whitelist = IPWhitelist()


# --------------------------------------------------
# Dynamische Helper-Listen
# --------------------------------------------------


trusted_ips = TTLSet(
    TRUSTED_TTL
)

bad_ips = TTLSet(
    BAD_TTL
)

helper_pending = LockedSet()

# Scrambler nur fuer zuvor ACCEPTierte (nicht statisch gewhitelistete)
# Pakete. Keine Scrambler-Abfrage fuer bereits DROPende Pakete.
def _scrambler_result(ip, port, outcome, generation):
    result = single_ip_filter.result(ip, outcome, generation)
    action = result['action']
    if action == 'STALE':
        return
    log('BLOCK' if action == 'NEW_BLOCK' else action, 'I', port, ip,
        detail='Scrambler ' + result.get('reason', '-'))
    if action in ('WHITE', 'BLACK', 'NEW_BLOCK', 'ERROR'):
        state_worker.request_save()


def _single_ip_decision(ip, dst_port, src_port, tcp_flags, policy):
    """Apply new /32 decision after regular NFQ verdict is known.

    Return True when this SINGLE-IP filter requires DROP.
    No disk, ipset or shell operations occur in this callback.
    """
    if tcp_flags != 'SYN':
        return False
    outcome = single_ip_filter.observe(ip, dst_port, src_port, policy)
    action = outcome['action']
    if action == 'CHECK':
        log('CHECK', 'I', dst_port, ip, src_port=src_port,
            tcp_flags=tcp_flags, detail=outcome['reason'])
        if not helper_client.lookup(ip, dst_port, outcome['generation']):
            fail = single_ip_filter.fail_enqueue(ip, outcome['generation'])
            if fail['action'] != 'STALE':
                log('ERROR', 'I', dst_port, ip,
                    detail='Scrambler-Warteschlange voll')
        state_worker.request_save()
    elif action == 'HIGHLOAD':
        log('HIGHLOAD', 'I', dst_port, ip, src_port=src_port,
            tcp_flags=tcp_flags, detail=outcome['reason'])
    elif action == 'NEW_BLOCK':
        log('BLOCK', 'I', dst_port, ip, src_port=src_port,
            tcp_flags=tcp_flags, detail=outcome['reason'])
        state_worker.request_save()
    return action in ('BLOCKED', 'NEW_BLOCK')


def _dns_single_decision(ip, dst_port, src_port, tcp_flags, decision):
    return _single_ip_decision(ip, dst_port, src_port, tcp_flags,
                               'ACCEPT' if decision == 'ACPT' else 'DROP')


helper_client = HelperClient(
    trusted_ips,
    bad_ips,
    helper_pending,
    on_result=_scrambler_result,
    record_result=False
)


# --------------------------------------------------
# Pruefkette: DNS -> optional AbuseIPDB -> endgueltiges Verdict.
# Nur finale ACPT/DROP-Ergebnisse duerfen den Hauptcache fuellen.
# --------------------------------------------------

def _needs_api(port, dns_entry):
    return (ABUSEIPDB_ENABLE and port in ABUSEIPDB_PORTS
            and dns_entry is not None
            and dns_entry['decision'] == 'ACPT'
            and dns_entry['reason'] == '-')


def _finalize_packet(ip, qh, packet_id, port, src_port, tcp_flags,
                     dns_entry, api_entry=None, cache_hit=False):
    now = time.time()
    decision = dns_entry['decision']
    reason = dns_entry['reason']
    detail = dns_entry.get('detail')
    ttl = max(0, dns_entry['expires'] - now)
    api_score = None
    if api_entry is not None and decision == 'ACPT':
        ttl = min(ttl, max(0, api_entry['expires'] - now))
        if api_entry['reason'] == 'A':
            # 'A' ist nur eine interne API-Kennung, kein sichtbarer Loggrund.
            # Die aus dem DNS-Worker stammende PTR-Domain bleibt erhalten.
            api_score = api_entry.get('score')
            detail = None
            if api_entry['decision'] == 'DROP':
                decision, reason = 'DROP', 'A'
        elif api_entry['reason'] == 'E':
            reason, detail = 'E', api_entry.get('detail')

    # Ein AbuseIPDB-DROP ist portabhaengig. Er darf daher nicht als globaler
    # Endentscheid fuer dasselbe /64 in den portuebergreifenden Hauptcache
    # gelangen; der API-Cache behaelt dafuer den Rohscore.
    api_port_drop = (api_entry is not None and api_entry.get('reason') == 'A'
                     and decision == 'DROP')

    # Kein endgueltiges ACPT im Cache, bevor alle benoetigten Stufen
    # erfolgreich durchlaufen oder mit 5min Fehler-ACPT beendet wurden.
    if ttl > 0 and not api_port_drop:
        cache.set(ip, decision, ttl=ttl, reason=reason,
                  ptr=dns_entry.get('ptr', '-'),
                  match=dns_entry.get('match', '-'),
                  resolver=dns_entry.get('resolver', '-'), detail=detail)

    block_single = _single_ip_decision(ip, port, src_port, tcp_flags,
                                       'DROP' if decision == 'DROP' else 'ACCEPT')
    final_decision = 'DROP' if block_single else decision
    lib.nfq_set_verdict(qh, packet_id,
                        NF_DROP if final_decision == 'DROP' else NF_ACCEPT,
                        0, None)
    log_reason = ('I' if block_single and decision != 'DROP' else
                  ('C' if cache_hit else ('-' if reason == 'A' else reason)))
    log(final_decision, log_reason, port, ip,
        ptr='-' if cache_hit else dns_entry.get('ptr', '-'),
        match=dns_entry.get('match', '-'), src_port=src_port,
        tcp_flags=tcp_flags, resolver=dns_entry.get('resolver', '-'),
        detail=None if cache_hit else detail,
        score=api_score if not cache_hit else None)


def _after_api(packet, api_entry, cache_hit):
    ip, qh, packet_id, port, src_port, tcp_flags, dns_entry = packet
    _finalize_packet(ip, qh, packet_id, port, src_port, tcp_flags,
                     dns_entry, api_entry, cache_hit=cache_hit)


def _after_dns(ip, qh, packet_id, port, src_port, tcp_flags, dns_entry):
    if dns_entry is None:
        # Ein fehlendes DNS-Zwischenergebnis ist ein interner Fehler.
        lib.nfq_set_verdict(qh, packet_id, NF_DROP, 0, None)
        log('DROP', 'T', port, ip, src_port=src_port, tcp_flags=tcp_flags,
            detail='DNS-Zwischenergebnis fehlt')
        return
    if _needs_api(port, dns_entry):
        abuse_worker.lookup(ip, qh, packet_id, port, src_port,
                            tcp_flags, dns_entry)
        return
    _finalize_packet(ip, qh, packet_id, port, src_port, tcp_flags, dns_entry)


def _api_emergency_verdict(packet):
    ip, qh, packet_id, port, src_port, tcp_flags, _ = packet
    # Interner Programmfehler: fehlendes Verdict verhindern.
    lib.nfq_set_verdict(qh, packet_id, NF_DROP, 0, None)
    log('DROP', 'E', port, ip, src_port=src_port, tcp_flags=tcp_flags,
        detail='API-Finalisierung fehlgeschlagen')


dns_worker = DNSWorker(dns_cache, lib, NF_DROP, NF_ACCEPT,
                       on_result=_after_dns)
abuse_worker = AbuseIPDBWorker(api_cache, _after_api,
                               on_error=_api_emergency_verdict)

tc24_worker = TcSubnet24Worker(subnet24_tracker, whitelist, trusted_ips)
ip32_worker = KernelIP32Worker(single_ip_filter, whitelist)



@CALLBACK
def packet_callback(
    qh,
    nfmsg,
    nfdata,
    data
):

    header_ptr = lib.nfq_get_msg_packet_hdr(
        nfdata
    )

    if not header_ptr:
        return 0


    header = ctypes.cast(
        header_ptr,
        ctypes.POINTER(PacketHeader)
    ).contents


    packet_id = socket.ntohl(
        header.packet_id
    )


    payload_ptr = ctypes.c_void_p()

    payload_len = lib.nfq_get_payload(
        nfdata,
        ctypes.byref(payload_ptr)
    )


    if (
        payload_len <= 0
        or not payload_ptr.value
    ):
        return 0


    packet_data = ctypes.cast(
        payload_ptr,
        ctypes.POINTER(
            ctypes.c_ubyte * payload_len
        )
    ).contents


    packet = parse_packet(
        packet_data,
        payload_len
    )


    if not packet:

        lib.nfq_set_verdict(
            qh,
            packet_id,
            NF_ACCEPT,
            0,
            None
        )

        return 0


    src_ip = packet["src_ip"]
    src_port = packet["src_port"]
    dst_port = packet["dst_port"]
    tcp_flags = packet["tcp_flags"]


    # --------------------------------------------------
    # Neu: Einzel-IP-Zaehler erst NACH dem tatsaechlichen Policy-Ergebnis.
    # ACPT W => ausschliesslich HIGHLOAD; kein Scrambler.
    # --------------------------------------------------
    whitelist_match = whitelist.get_match(src_ip)

    # --------------------------------------------------
    # Whitelist
    # --------------------------------------------------

    if whitelist_match is not None:

        _single_ip_decision(src_ip, dst_port, src_port, tcp_flags, 'WHITELIST')
        lib.nfq_set_verdict(
            qh,
            packet_id,
            NF_ACCEPT,
            0,
            None
        )

        log(
            "ACPT",
            "W",
            dst_port,
            src_ip,
            match=whitelist_match,
            src_port=src_port,
            tcp_flags=tcp_flags
        )

        return 0


    # --------------------------------------------------
    # Dynamische Helper-Whitelist
    # --------------------------------------------------

    if (trusted_ips.contains(src_ip) and
        (cache.get_entry(src_ip) or {}).get('decision') != 'DROP'):

        if _single_ip_decision(src_ip, dst_port, src_port, tcp_flags, 'ACCEPT'):
            lib.nfq_set_verdict(qh, packet_id, NF_DROP, 0, None)
            return 0
        lib.nfq_set_verdict(
            qh,
            packet_id,
            NF_ACCEPT,
            0,
            None
        )

        log(
            "ACPT",
            "H",
            dst_port,
            src_ip,
            src_port=src_port,
            tcp_flags=tcp_flags,
            detail="ACCESS"
        )

        return 0


    # --------------------------------------------------
    # Dynamische Helper-Blocklist
    # --------------------------------------------------

    if bad_ips.contains(
        src_ip
    ):

        _single_ip_decision(src_ip, dst_port, src_port, tcp_flags, 'DROP')
        lib.nfq_set_verdict(
            qh,
            packet_id,
            NF_DROP,
            0,
            None
        )

        log(
            "DROP",
            "H",
            dst_port,
            src_ip,
            src_port=src_port,
            tcp_flags=tcp_flags,
            detail="BAD"
        )

        return 0


    # --------------------------------------------------
    # /24 Angriffserkennung
    # --------------------------------------------------

    if (
        dst_port in SUBNET24_PORTS
        and tcp_flags == "SYN"
    ):

        subnet24_result = subnet24_tracker.check(
            src_ip
        )

        if subnet24_result["action"] == "BLOCKED":

            _single_ip_decision(src_ip, dst_port, src_port, tcp_flags, 'DROP')
            lib.nfq_set_verdict(
                qh,
                packet_id,
                NF_DROP,
                0,
                None
            )

            log(
                "DROP",
                "/24",
                dst_port,
                src_ip,
                src_port=src_port,
                tcp_flags=tcp_flags,
                detail=(
                    subnet24_result["network"]
                    + " block +"
                    + str(SUBNET24_BLOCK_TTL)
                    + "s"
                )
            )

            return 0

        if subnet24_result["action"] == "NEW_BLOCK":

            _single_ip_decision(src_ip, dst_port, src_port, tcp_flags, 'DROP')
            state_worker.request_save()
            tc24_worker.notify()  # Keine tc-/Shell-Aufrufe im NFQUEUE-Callback

            lib.nfq_set_verdict(
                qh,
                packet_id,
                NF_DROP,
                0,
                None
            )

            log(
                "BLOCK",
                "/24",
                dst_port,
                src_ip,
                src_port=src_port,
                tcp_flags=tcp_flags,
                detail=(
                    subnet24_result["network"]
                    + " "
                    + str(subnet24_result["count"])
                    + " IPs / "
                    + format(
                        subnet24_result["elapsed"],
                        ".1f"
                    )
                    + "s"
                )
            )

            return 0


    # --------------------------------------------------
    # Einzel-IP-SYN-Flutschutz: vor dem Entscheidungs-Cache
    # --------------------------------------------------
    if tcp_flags == "SYN" and dst_port in IP_FLOOD_PORTS:
        flood = ip_flood_tracker.check(src_ip, dst_port, src_port)
        if flood["action"] != "NONE":
            if flood['action'] == 'NEW_BLOCK':
                state_worker.request_save()
            _single_ip_decision(src_ip, dst_port, src_port, tcp_flags, 'DROP')
            lib.nfq_set_verdict(qh, packet_id, NF_DROP, 0, None)
            detail = ("IP-SYN-Flut +%ds" % IP_FLOOD_BLOCK_TTL
                      if flood["action"] == "BLOCKED"
                      else "%d Ports / %.1fs; block +%ds" % (
                          flood["count"], flood["elapsed"],
                          IP_FLOOD_BLOCK_TTL))
            log("DROP" if flood["action"] == "BLOCKED" else "BLOCK",
                "F", dst_port, src_ip, src_port=src_port,
                tcp_flags=tcp_flags, detail=detail)
            return 0

    # Bereits /128-bzw. /32-SYN-gesperrte Quellen brauchen keine API.
    if tcp_flags == 'SYN' and single_ip_filter.is_blocked(src_ip):
        _single_ip_decision(src_ip, dst_port, src_port, tcp_flags, 'DROP')
        lib.nfq_set_verdict(qh, packet_id, NF_DROP, 0, None)
        log('DROP', 'I', dst_port, src_ip, src_port=src_port,
            tcp_flags=tcp_flags, detail='bestehende Einzel-IP-Sperre')
        return 0

    # --------------------------------------------------
    # Endentscheidungs-Cache (IPv6 immer /64).
    # ACPT C ist nur bei nicht-API-Ports sofort gueltig;
    # bei API-Ports MUSS ein gueltiges API-Teilergebnis vorliegen.
    # --------------------------------------------------
    cached = cache.get_entry(src_ip)
    if cached is not None and cached['decision'] == 'DROP':
        block_single = _single_ip_decision(src_ip, dst_port, src_port,
                                           tcp_flags, 'DROP')
        lib.nfq_set_verdict(qh, packet_id, NF_DROP, 0, None)
        log('DROP', 'C', dst_port, src_ip, src_port=src_port,
            tcp_flags=tcp_flags)
        return 0

    if cached is not None and not _needs_api(dst_port, cached):
        blocked = _single_ip_decision(src_ip, dst_port, src_port,
                                       tcp_flags, 'ACCEPT')
        lib.nfq_set_verdict(qh, packet_id,
                            NF_DROP if blocked else NF_ACCEPT, 0, None)
        log('DROP' if blocked else 'ACPT', 'I' if blocked else 'C',
            dst_port, src_ip, src_port=src_port, tcp_flags=tcp_flags)
        return 0

    # Auch nach einem ACPT C muss bei einem API-Port eine separate
    # gueltige API-Bewertung vorhanden sein. Der API-Worker prueft seinen
    # Cache selbst und fuehrt nur beim MISS eine Netzabfrage aus.
    # DNS-Zwischenergebnis nutzen, oder nur bei Bedarf neu aufloesen.
    # Der DNS-Worker und der API-Worker buendeln wartende SYNs je /64.
    dns_worker.lookup(src_ip, qh, packet_id, dst_port, src_port, tcp_flags)

    return 0


# Periodische Sicherung; Start erst in main() nach dem Laden.
state_worker = StateWorker(cache, trusted_ips, bad_ips, subnet24_tracker,
                           ip_flood_tracker, single_ip_filter,
                           dns_cache=dns_cache, api_cache=api_cache,
                           abuse_worker=abuse_worker)
abuse_worker.on_change = state_worker.request_save
ip32_worker.on_change = state_worker.request_save


def _stop_signal(signum, frame):
    # Der Hauptthread verlaesst den blockierenden recv() sofort.
    raise KeyboardInterrupt



def main():
    signal.signal(signal.SIGTERM, _stop_signal)
    signal.signal(signal.SIGINT, _stop_signal)

    # Die gesamte Laufzeit exklusiv halten: keine zwei Python-Prozesse,
    # die dieselben NFQUEUE-/Firewall-Regeln gegenseitig entfernen.
    lock_path = config.LOCK_FILE
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with open(lock_path, 'a+') as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('NFQfilter laeuft bereits (Instanzsperre).', file=sys.stderr)
            return 1

        h = None
        queue_handle = None
        firewall = None
        state_started = False
        tc_started = False
        ip32_started = False
        try:
            # Die Cache-Daten werden vor dem ersten Paket wiederhergestellt.
            state_worker.load()
            state_worker.start()
            state_started = True

            h = lib.nfq_open()
            if not h:
                raise RuntimeError('nfq_open fehlgeschlagen')

            for family, name in ((socket.AF_INET, 'IPv4'),
                                 (socket.AF_INET6, 'IPv6')):
                ret = lib.nfq_unbind_pf(h, family)
                print(name + ' unbind:', ret)
                ret = lib.nfq_bind_pf(h, family)
                print(name + ' bind:', ret)

            queue_handle = lib.nfq_create_queue(h, 0, packet_callback, None)
            if not queue_handle:
                raise RuntimeError('NFQUEUE 0 konnte nicht erstellt werden')

            ret = lib.nfq_set_mode(queue_handle, NFQNL_COPY_PACKET, 65535)
            print('set_mode:', ret)
            if ret < 0:
                raise RuntimeError('nfq_set_mode fehlgeschlagen')

            # ZUERST den Userspace-Listener oeffnen, DANN die SYNs einhaengen.
            # IPv4/IPv6 benutzen ausschliesslich NFQUEUE 0.
            firewall = FirewallRuleManager()
            firewall.start()

            tc24_worker.start()
            tc_started = True
            ip32_worker.start()
            ip32_started = True

            print('NFQUEUE 0 aktiv; warte auf Pakete ...')
            fd = lib.nfq_fd(h)
            buf = ctypes.create_string_buffer(65536)
            while True:
                n = libc.recv(fd, buf, len(buf), 0)
                if n > 0:
                    lib.nfq_handle_packet(h, buf, n)

        except KeyboardInterrupt:
            print('\nBeende ...')
        except Exception as exc:
            print('NFQfilter Start/Laufzeit-Fehler: %s' % exc,
                  file=sys.stderr)
            return 1
        finally:
            # ZUERST eigene Firewall-Hooks entfernen, DANACH Queue schliessen.
            # Bei einem SIGKILL kann der Kernel keine Python-Cleanup-Methode
            # ausfuehren; der naechste Start bereinigt verwaiste eigene Regeln.
            if firewall is not None:
                try:
                    firewall.stop()
                except Exception as exc:
                    print('NFQfilter Firewall-Cleanup fehlgeschlagen: %s' % exc,
                          file=sys.stderr)
            if ip32_started:
                ip32_worker.stop()
            if tc_started:
                tc24_worker.stop()
            if state_started:
                state_worker.stop_and_save()
            if queue_handle:
                lib.nfq_destroy_queue(queue_handle)
            if h:
                lib.nfq_close(h)

    return 0


if __name__ == '__main__':
    sys.exit(main())

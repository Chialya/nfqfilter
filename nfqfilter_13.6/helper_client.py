#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import queue
import socket
import threading


# --------------------------------------------------
# Konfiguration
# --------------------------------------------------

from config import HELPER_HOST, HELPER_PORT, CONNECT_TIMEOUT, READ_TIMEOUT


# --------------------------------------------------
# Helper Client
# --------------------------------------------------

class HelperClient:

    def __init__(
        self,
        trusted_ips,
        bad_ips,
        pending,
        on_result=None,
        record_result=True
    ):

        self.trusted_ips = trusted_ips
        self.bad_ips = bad_ips
        self.pending = pending
        self.on_result = on_result
        self.record_result = record_result

        self.queue = queue.Queue(maxsize=256)

        self.thread = threading.Thread(
            target=self._worker,
            daemon=True
        )

        self.thread.start()


    # --------------------------------------------------
    # Abfrage einreihen
    # --------------------------------------------------

    def lookup(
        self,
        ip,
        port,
        generation=None
    ):

        # Bereits eine Abfrage für diese IP aktiv
        if not self.pending.add(ip):
            return False

        try:
            self.queue.put_nowait((ip, port, generation))
        except queue.Full:
            self.pending.remove(ip)
            return False
        return True


    # --------------------------------------------------
    # Worker
    # --------------------------------------------------

    def _worker(self):
        while True:
            ip, port, generation = self.queue.get()
            result = None
            try:
                result = self._query(ip, port)
                if self.record_result:
                    if result == "ACCESS":
                        self.bad_ips.remove(ip)
                        self.trusted_ips.add(ip)
                    elif result == "BAD":
                        self.trusted_ips.remove(ip)
                        self.bad_ips.add(ip)
                if self.on_result is not None:
                    self.on_result(ip, port, result, generation)
            except Exception as exc:
                print('Scrambler-Worker:', exc, flush=True)
                if self.on_result is not None:
                    try:
                        self.on_result(ip, port, None, generation)
                    except Exception:
                        pass
            finally:
                self.pending.remove(ip)
                self.queue.task_done()


    # --------------------------------------------------
    # Helper abfragen
    # --------------------------------------------------

    def _query(
        self,
        ip,
        port
    ):

        request = str(ip).encode(
            "ascii"
        )

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(
            CONNECT_TIMEOUT
        )


        try:

            sock.connect(
                (
                    HELPER_HOST,
                    HELPER_PORT
                )
            )

            sock.settimeout(
                READ_TIMEOUT
            )

            sock.sendall(
                request
            )

            response = sock.recv(
                64
            )


        except Exception:

            return None


        finally:

            sock.close()


        try:

            result = response.decode(
                "ascii",
                errors="strict"
            ).strip()

        except Exception:

            return None


        if result not in (
            "ACCESS",
            "BAD",
            "UNKNOWN"
        ):

            return None


        return result
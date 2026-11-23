#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Einzel-IP-SYN-Flutschutz; IPv4 und IPv6

import threading
import time
from collections import deque

from config import (IP_FLOOD_PORTS, IP_FLOOD_WINDOW,
                    IP_FLOOD_MIN_DURATION, IP_FLOOD_BLOCK_TTL)


class IPFloodTracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.observed = {}  # (IP, Zielport) -> deque[(Zeit, Quellport)]
        self.blocked = {}   # IP -> Zeitpunkt (wall-clock)
        self.last_cleanup = 0

    def _cleanup(self, now):
        if now - self.last_cleanup < 60:
            return
        self.last_cleanup = now
        for ip, expiry in list(self.blocked.items()):
            if expiry <= now:
                del self.blocked[ip]
        for key, events in list(self.observed.items()):
            while events and events[0][0] <= now - IP_FLOOD_WINDOW:
                events.popleft()
            if not events:
                del self.observed[key]

    def check(self, ip, dst_port, src_port):
        if dst_port not in IP_FLOOD_PORTS:
            return {'action': 'NONE'}
        now = time.time()
        with self.lock:
            self._cleanup(now)
            if self.blocked.get(ip, 0) > now:
                self.blocked[ip] = now + IP_FLOOD_BLOCK_TTL
                return {'action': 'BLOCKED'}
            if ip in self.blocked:
                del self.blocked[ip]

            key = (ip, dst_port)
            events = self.observed.setdefault(key, deque())
            while events and events[0][0] <= now - IP_FLOOD_WINDOW:
                events.popleft()
            # Derselbe Quellport zaehlt im Fenster nur einmal (SYN-Retransmits).
            if not any(port == src_port for _, port in events):
                events.append((now, src_port))

            count = len(events)
            elapsed = now - events[0][0]
            if (count >= IP_FLOOD_PORTS[dst_port]
                    and elapsed >= IP_FLOOD_MIN_DURATION):
                self.blocked[ip] = now + IP_FLOOD_BLOCK_TTL
                # Alle bisherigen Beobachtungen dieser IP entfernen.
                for k in list(self.observed):
                    if k[0] == ip:
                        del self.observed[k]
                return {'action': 'NEW_BLOCK', 'count': count,
                        'elapsed': elapsed}
            return {'action': 'NONE'}

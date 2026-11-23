#!/usr/bin/env python3

# NFQFILTER - RAM Cache

import time
import threading
import ipaddress
from config import CACHE_TTL


# --------------------------------------------------
# Nur Entscheidungs-Caches auf IPv6 /64; die separaten
# SYN-Flood-/Single-IP-Tracker bleiben unveraendert /128.
# --------------------------------------------------
def decision_cache_key(ip):
    if '/' in str(ip):
        address = ipaddress.ip_network(ip, strict=False).network_address
    else:
        address = ipaddress.ip_address(ip)
    if address.version == 6:
        return str(ipaddress.ip_network((address, 64), strict=False))
    return str(address)


# --------------------------------------------------
# DNS-/API-/Endentscheidungs-Cache
# --------------------------------------------------

class IPCache:

    def __init__(self, ttl=CACHE_TTL):
        self.ttl = ttl
        self.cache = {}
        self.lock = threading.Lock()


    def get(self, ip):

        entry = self.get_entry(ip)

        if entry is None:
            return None

        return entry["decision"]


    def get_entry(self, ip):

        now = time.time()

        with self.lock:

            entry = self.cache.get(decision_cache_key(ip))

            if entry is None:
                return None

            if now >= entry["expires"]:
                del self.cache[decision_cache_key(ip)]
                return None

            return entry.copy()


    def set(
        self,
        ip,
        decision,
        ttl=None,
        reason="C",
        ptr="-",
        match="-",
        resolver="-",
        detail=None,
        score=None
    ):

        if ttl is None:
            ttl = self.ttl

        expires = time.time() + ttl

        entry = {
            "decision": decision,
            "reason": reason,
            "ptr": ptr,
            "match": match,
            "resolver": resolver,
            "detail": detail,
            "expires": expires,
        }

        if score is not None:
            entry['score'] = int(score)
        with self.lock:
            self.cache[decision_cache_key(ip)] = entry


    def delete(self, ip):

        with self.lock:
            self.cache.pop(decision_cache_key(ip), None)


    def clear(self):

        with self.lock:
            self.cache.clear()


    def size(self):

        with self.lock:
            return len(self.cache)


# --------------------------------------------------
# Temporäre IP-Liste mit TTL
# --------------------------------------------------

class TTLSet:

    def __init__(self, ttl):
        self.ttl = ttl
        self.entries = {}
        self.lock = threading.Lock()


    def add(self, ip, ttl=None):

        if ttl is None:
            ttl = self.ttl

        expires = time.time() + ttl

        with self.lock:
            self.entries[ip] = expires


    def contains(self, ip):

        now = time.time()

        with self.lock:

            expires = self.entries.get(ip)

            if expires is None:
                return False

            if now >= expires:
                del self.entries[ip]
                return False

            return True


    def remove(self, ip):

        with self.lock:
            self.entries.pop(ip, None)


    def clear(self):

        with self.lock:
            self.entries.clear()


    def size(self):

        now = time.time()

        with self.lock:

            expired = [
                ip
                for ip, expires in self.entries.items()
                if now >= expires
            ]

            for ip in expired:
                del self.entries[ip]

            return len(self.entries)


# --------------------------------------------------
# Thread-sichere Pending-Liste
# --------------------------------------------------

class LockedSet:

    def __init__(self):
        self.entries = set()
        self.lock = threading.Lock()


    def add(self, ip):

        with self.lock:

            if ip in self.entries:
                return False

            self.entries.add(ip)
            return True


    def remove(self, ip):

        with self.lock:
            self.entries.discard(ip)


    def contains(self, ip):

        with self.lock:
            return ip in self.entries


    def clear(self):

        with self.lock:
            self.entries.clear()


    def size(self):

        with self.lock:
            return len(self.entries)
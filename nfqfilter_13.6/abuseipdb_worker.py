#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AbuseIPDB v2 /check, asynchrone NFQUEUE-Entscheidungsstufe (v13.5).

Die API bewertet genau die erste beobachtete IP eines IPv6-/64-Praefixes.
Cache und wartende Verbindungen werden je /64 zusammengefasst.
"""

import json
import queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime

from cache import decision_cache_key
import config as _config

ABUSEIPDB_API_KEY = _config.ABUSEIPDB_API_KEY
ABUSEIPDB_PORTS = _config.ABUSEIPDB_PORTS
ABUSEIPDB_TIMEOUT = _config.ABUSEIPDB_TIMEOUT
ABUSEIPDB_WORKERS = _config.ABUSEIPDB_WORKERS
ABUSEIPDB_QUEUE_SIZE = _config.ABUSEIPDB_QUEUE_SIZE
ABUSEIPDB_CACHE_TTL = _config.ABUSEIPDB_CACHE_TTL
ABUSEIPDB_ERROR_TTL = _config.ABUSEIPDB_ERROR_TTL
ABUSEIPDB_MAX_AGE_DAYS = _config.ABUSEIPDB_MAX_AGE_DAYS
# Rueckwaertskompatibilitaet fuer eine noch nicht angepasste v13.4-config.py.
_LEGACY_MIN_SCORE = getattr(_config, 'ABUSEIPDB_MIN_SCORE', 50)


def _port_thresholds():
    """Liefert {TCP-Port: Mindestscore}; alte v13.4-Port-Sets bleiben lesbar."""
    raw = ABUSEIPDB_PORTS
    if isinstance(raw, dict):
        values = raw.items()
    elif isinstance(raw, (set, frozenset, list, tuple)):
        # Eine alte Konfiguration {5001} wird mit dem alten globalen Score
        # weiterbetrieben, bis ABUSEIPDB_PORTS auf ein Mapping umgestellt ist.
        values = ((port, _LEGACY_MIN_SCORE) for port in raw)
    else:
        raise ValueError('ABUSEIPDB_PORTS muss ein Mapping Port:Score sein')

    result = {}
    for port, score in values:
        if (isinstance(port, bool) or not isinstance(port, int)
                or not 1 <= port <= 65535):
            raise ValueError('Ungueltiger AbuseIPDB-Port: %r' % (port,))
        if (isinstance(score, bool) or not isinstance(score, int)
                or not 1 <= score <= 100):
            raise ValueError('AbuseIPDB-Mindestscore fuer Port %s muss 1..100 sein' % port)
        result[port] = score
    return result


class AbuseIPDBWorker:
    def __init__(self, cache, on_result, on_change=None, on_error=None):
        # Konfiguration bei Prozessstart validieren. Die Bewertung erfolgt
        # portbezogen, der API-Score selbst bleibt im Cache unveraendert.
        _port_thresholds()
        self.cache = cache
        self.on_result = on_result
        self.on_change = on_change
        self.on_error = on_error
        self.pending = {}
        self.lock = threading.Lock()
        self.pause_until = 0.0
        self.queue = queue.Queue(maxsize=ABUSEIPDB_QUEUE_SIZE)
        self.threads = [threading.Thread(target=self._worker, daemon=True,
                                         name='NFQ-AbuseIPDB-%d' % n)
                        for n in range(ABUSEIPDB_WORKERS)]
        for thread in self.threads:
            thread.start()

    def lookup(self, ip, qh, packet_id, port, src_port, tcp_flags, dns_entry):
        packet = (ip, qh, packet_id, port, src_port, tcp_flags, dns_entry)
        cached = self.cache.get_entry(ip)
        if cached is not None:
            self.on_result(packet, self._effective_entry(cached, port), True)
            return

        key = decision_cache_key(ip)
        reused = None
        full = False
        with self.lock:
            if key in self.pending:
                self.pending[key].append(packet)
                return
            # Zweiter Cache-Check schliesst das Race zwischen Cache-MISS
            # und dem Abschluss einer zeitgleichen Anfrage.
            reused = self.cache.get_entry(ip)
            if reused is None:
                self.pending[key] = [packet]
                try:
                    self.queue.put_nowait((key, ip))
                    return
                except queue.Full:
                    self.pending.pop(key, None)
                    full = True

        if reused is not None:
            self.on_result(packet, self._effective_entry(reused, port), True)
            return
        if full:
            # Bei voller Warteschlange keine SYN-Pakete unbefristet halten.
            error_entry = self._error_entry(ip, 'API-Warteschlange voll')
            self.on_result(packet, error_entry, False)
            if self.on_change is not None:
                self.on_change()

    @staticmethod
    def _effective_entry(entry, port):
        # Der API-Cache speichert den Rohscore je IP bzw. IPv6-/64.
        # Erst hier wird er mit dem Grenzwert des aktuellen Zielports bewertet.
        score = entry.get('score')
        if entry.get('reason') == 'A' and isinstance(score, int):
            thresholds = _port_thresholds()
            threshold = thresholds.get(port)
            if threshold is None:
                raise ValueError('Port %s ist nicht fuer AbuseIPDB konfiguriert' % port)
            entry = dict(entry)
            entry['decision'] = 'DROP' if score >= threshold else 'ACPT'
        return entry

    @staticmethod
    def _retry_seconds(value):
        if value:
            try:
                return max(0, int(float(value)))
            except (TypeError, ValueError):
                try:
                    return max(0, int(parsedate_to_datetime(value).timestamp() - time.time()))
                except (TypeError, ValueError, OverflowError):
                    pass
        return ABUSEIPDB_ERROR_TTL

    def _query(self, ip):
        """Ergebnis: (score, fehler, cooldown_seconds). TLS-Pruefung aktiv."""
        if not ABUSEIPDB_API_KEY.strip():
            return None, 'API-Key fehlt', None

        with self.lock:
            if time.time() < self.pause_until:
                return None, 'HTTP 429: globale API-Pause', None

        params = urllib.parse.urlencode({
            'ipAddress': ip,
            'maxAgeInDays': ABUSEIPDB_MAX_AGE_DAYS,
        })
        request = urllib.request.Request(
            'https://api.abuseipdb.com/api/v2/check?' + params,
            headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
            method='GET',
        )
        try:
            with urllib.request.urlopen(request, timeout=ABUSEIPDB_TIMEOUT) as response:
                payload = json.loads(response.read(65536).decode('utf-8'))
            score = payload['data']['abuseConfidenceScore']
            if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
                raise ValueError('ungueltiger AbuseIPDB-Score')
            return score, None, None
        except urllib.error.HTTPError as error:
            if error.code == 429:
                return None, 'HTTP 429', self._retry_seconds(error.headers.get('Retry-After'))
            return None, 'HTTP %d' % error.code, None
        except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
            return None, 'API-Fehler: %s' % type(error).__name__, None

    def _error_entry(self, ip, detail):
        self.cache.set(ip, 'ACPT', ttl=ABUSEIPDB_ERROR_TTL,
                       reason='E', detail=detail)
        return self.cache.get_entry(ip)

    def _worker(self):
        while True:
            key, ip = self.queue.get()
            try:
                score, error, cooldown = self._query(ip)
                if cooldown is not None:
                    with self.lock:
                        self.pause_until = max(self.pause_until, time.time() + cooldown)
                if error is not None:
                    entry = self._error_entry(ip, error)
                else:
                    # Rohscore speichern; keine portbezogene Entscheidung im
                    # gemeinsamen /64-Cache festschreiben. Das verhindert, dass
                    # ein DROP auf Port 443 irrtuemlich Port 5001 mitblockiert.
                    self.cache.set(ip, 'ACPT', ttl=ABUSEIPDB_CACHE_TTL,
                                   reason='A', score=score)
                    entry = self.cache.get_entry(ip)
                if self.on_change is not None:
                    self.on_change()
                with self.lock:
                    packets = self.pending.pop(key, [])
                for index, packet in enumerate(packets):
                    try:
                        # Nur der erste wartende SYN bekommt den neuen API-Logeintrag.
                        # Alle weiteren Pakete erhalten ein Cache-Verdict (C).
                        self.on_result(packet, self._effective_entry(entry, packet[3]), index > 0)
                    except Exception as exc:
                        self._failed_packet(packet, exc)
            except Exception as exc:
                from logger import log
                log('ERROR', 'E', 0, ip,
                    detail='API-Worker: %s' % type(exc).__name__)
                entry = self._error_entry(ip, 'interner API-Worker-Fehler')
                with self.lock:
                    packets = self.pending.pop(key, [])
                for index, packet in enumerate(packets):
                    try:
                        # Nur der erste wartende SYN bekommt den neuen API-Logeintrag.
                        # Alle weiteren Pakete erhalten ein Cache-Verdict (C).
                        self.on_result(packet, self._effective_entry(entry, packet[3]), index > 0)
                    except Exception as final_error:
                        self._failed_packet(packet, final_error)
            finally:
                self.queue.task_done()

    def _failed_packet(self, packet, exc):
        from logger import log
        log('ERROR', 'E', packet[3], packet[0],
            detail='API-Finalisierung: %s' % type(exc).__name__)
        if self.on_error is not None:
            self.on_error(packet)

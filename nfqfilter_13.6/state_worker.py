#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# NFQfilter 12.6 - RAM-Zustand bereinigen und sichern

import json
import os
import threading
import time

from config import STATE_FILE, STATE_SAVE_INTERVAL, STATE_SAVE_DEBOUNCE
from cache import decision_cache_key


class StateWorker:
    def __init__(self, cache, trusted_ips, bad_ips, subnet24_tracker,
                 ip_flood_tracker=None, single_ip_tracker=None,
                 dns_cache=None, api_cache=None, abuse_worker=None):
        self.cache = cache
        self.dns_cache = dns_cache
        self.api_cache = api_cache
        self.abuse_worker = abuse_worker
        self.trusted_ips = trusted_ips
        self.bad_ips = bad_ips
        self.subnet24 = subnet24_tracker
        self.ip_flood = ip_flood_tracker
        self.single_ip = single_ip_tracker
        self.stop_event = threading.Event()
        self.save_event = threading.Event()
        self.save_lock = threading.Lock()
        self.thread = None
        self.last_save_monotonic = 0

    @staticmethod
    def _prune_expired(entries, now):
        """Abgelaufene Eintraege direkt im RAM entfernen (Lock bereits gehalten)."""
        for key, entry in list(entries.items()):
            expires = entry['expires'] if isinstance(entry, dict) else entry
            if expires <= now:
                del entries[key]

    def _snapshot(self):
        now = time.time()
        def snapshot_decisions(store):
            if store is None:
                return {}
            with store.lock:
                self._prune_expired(store.cache, now)
                return {ip: dict(item) for ip, item in store.cache.items()}
        decisions = snapshot_decisions(self.cache)
        dns_decisions = snapshot_decisions(self.dns_cache)
        api_decisions = snapshot_decisions(self.api_cache)
        if self.abuse_worker is not None:
            with self.abuse_worker.lock:
                abuse_pause = self.abuse_worker.pause_until
        else:
            abuse_pause = 0.0
        with self.trusted_ips.lock:
            self._prune_expired(self.trusted_ips.entries, now)
            trusted = dict(self.trusted_ips.entries)
        with self.bad_ips.lock:
            self._prune_expired(self.bad_ips.entries, now)
            bad = dict(self.bad_ips.entries)
        with self.subnet24.lock:
            # Bei aktiver tc-Verwaltung entscheidet der tc-Worker nach
            # der letzten Zaehlerpruefung ueber den Ablauf.
            if not self.subnet24.tc_manages_expiry:
                self._prune_expired(self.subnet24.blocked, now)
            self._prune_expired(self.subnet24.observed, now)
            blocked = dict(self.subnet24.blocked)
            observed = {net: {'ips': sorted(entry['ips']),
                              'first': entry['first'], 'expires': entry['expires']}
                        for net, entry in self.subnet24.observed.items()}
        flood_blocked = {}
        flood_observed = {}
        if self.ip_flood is not None:
            with self.ip_flood.lock:
                self.ip_flood._cleanup(now)
                flood_blocked = dict(self.ip_flood.blocked)
                flood_observed = [
                    [ip, port, list(events)]
                    for (ip, port), events in self.ip_flood.observed.items()
                ]
        return {'version': 2, 'saved_at': now, 'cache': decisions,
                'dns_cache': dns_decisions, 'api_cache': api_decisions,
                'abuse_pause_until': abuse_pause,
                'trusted_ips': trusted, 'bad_ips': bad,
                'subnet24_blocked': blocked, 'subnet24_observed': observed,
                'ip_flood_blocked': flood_blocked,
                'ip_flood_observed': flood_observed,
                'single_ip': self.single_ip.snapshot(now) if self.single_ip else {}}

    def save(self):
        with self.save_lock:
            tmp_file = STATE_FILE + '.tmp'
            try:
                data = self._snapshot()
                os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
                with open(tmp_file, 'w', encoding='utf-8') as file:
                    json.dump(data, file, separators=(',', ':'), ensure_ascii=True)
                    file.flush()
                    os.fsync(file.fileno())
                os.replace(tmp_file, STATE_FILE)
                # fsync directory too so rename survives sudden power loss.
                try:
                    dir_fd = os.open(os.path.dirname(STATE_FILE), os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except OSError:
                    pass
                self.last_save_monotonic = time.monotonic()
                return True
            except Exception as exc:
                # Avoid a tight retry loop when the filesystem is full/read-only.
                self.last_save_monotonic = time.monotonic()
                print('Cache-Sicherung fehlgeschlagen:', exc, flush=True)
                return False

    def load(self):
        try:
            with open(STATE_FILE, 'r', encoding='utf-8') as file:
                data = json.load(file)
            if data.get('version') not in (1, 2):
                raise ValueError('Unbekanntes Cache-Dateiformat')
            now = time.time()
            def not_expired(entries):
                return {key: value for key, value in entries.items()
                        if isinstance(value, (int, float)) and value > now}
            def restore_decisions(entries):
                result = {}
                for ip, entry in entries.items():
                    if not isinstance(entry, dict) or not isinstance(entry.get('expires'), (int, float)):
                        continue
                    if entry['expires'] <= now:
                        continue
                    try:
                        key = decision_cache_key(ip)
                    except ValueError:
                        continue
                    previous = result.get(key)
                    # Falls mehrere alte /128 IPv6-Adressen auf dasselbe /64
                    # fallen, hat ein noch gueltiges DROP Vorrang.
                    if (previous is None or
                        (entry.get('decision') == 'DROP' and previous.get('decision') != 'DROP') or
                        (entry.get('decision') == previous.get('decision') and
                         entry['expires'] > previous['expires'])):
                        result[key] = entry
                return result

            decisions = restore_decisions(data.get('cache', {}))
            # API-Endentscheidungen nicht blind nach Konfigurationswechsel
            # uebernehmen (Schwellwert oder API-Schalter kann geaendert sein).
            # DNS- und API-Zwischenwerte bleiben erhalten.
            decisions = {key: value for key, value in decisions.items()
                         if value.get('reason') not in ('A', 'E')}
            # V13.1 enthielt ausschliesslich DNS-Pipeline-Entscheidungen.
            legacy = data.get('version') == 1
            dns_decisions = (dict(decisions) if legacy else
                             restore_decisions(data.get('dns_cache', {})))
            api_decisions = {} if legacy else restore_decisions(data.get('api_cache', {}))
            trusted = not_expired(data['trusted_ips'])
            bad = not_expired(data['bad_ips'])
            blocked = not_expired(data['subnet24_blocked'])
            observed = {net: {'ips': set(entry['ips']),
                              'first': entry['first'], 'expires': entry['expires']}
                        for net, entry in data['subnet24_observed'].items()
                        if isinstance(entry, dict) and
                        isinstance(entry.get('expires'), (int, float)) and
                        entry['expires'] > now}
            with self.cache.lock:
                self.cache.cache = decisions
            if self.dns_cache is not None:
                with self.dns_cache.lock:
                    self.dns_cache.cache = dns_decisions
            if self.api_cache is not None:
                with self.api_cache.lock:
                    self.api_cache.cache = api_decisions
            if self.abuse_worker is not None:
                with self.abuse_worker.lock:
                    pause = data.get('abuse_pause_until', 0) if not legacy else 0
                    self.abuse_worker.pause_until = (float(pause) if isinstance(pause, (int, float)) and pause > now else 0)
            with self.trusted_ips.lock:
                self.trusted_ips.entries = trusted
            with self.bad_ips.lock:
                self.bad_ips.entries = bad
            with self.subnet24.lock:
                self.subnet24.blocked = blocked
                self.subnet24.observed = observed
            if self.ip_flood is not None:
                from collections import deque
                from config import IP_FLOOD_WINDOW, IP_FLOOD_PORTS
                with self.ip_flood.lock:
                    self.ip_flood.blocked = not_expired(
                        data.get('ip_flood_blocked', {}))
                    self.ip_flood.observed = {}
                    for item in data.get('ip_flood_observed', []):
                        try:
                            ip, port, events = item
                            if port not in IP_FLOOD_PORTS:
                                continue
                            valid = [(float(ts), int(p)) for ts, p in events
                                     if float(ts) > now - IP_FLOOD_WINDOW
                                     and float(ts) <= now]
                            if valid:
                                self.ip_flood.observed[(ip, port)] = deque(valid)
                        except (ValueError, TypeError):
                            continue
            if self.single_ip is not None:
                self.single_ip.restore(data.get('single_ip', {}), now)
            print('RAM-Cache wiederhergestellt: %d Cache-Praefixe, %d /24-Sperren' %
                  (len(decisions), len(blocked)), flush=True)
        except FileNotFoundError:
            print('Keine bisherige Cache-Sicherung vorhanden.', flush=True)
        except Exception as exc:
            print('Cache-Wiederherstellung fehlgeschlagen:', exc, flush=True)

    def request_save(self):
        """Nonblocking notification from NFQUEUE/helper/kernel worker."""
        self.save_event.set()

    def _run(self):
        while not self.stop_event.is_set():
            age = time.monotonic() - self.last_save_monotonic
            timeout = max(0, STATE_SAVE_INTERVAL - age)
            triggered = self.save_event.wait(timeout)
            self.save_event.clear()
            if self.stop_event.is_set():
                break
            if triggered:
                age = time.monotonic() - self.last_save_monotonic
                # Debounce bursts of new blocks without a disk write per SYN.
                if age < STATE_SAVE_DEBOUNCE:
                    if self.stop_event.wait(STATE_SAVE_DEBOUNCE - age):
                        break
            self.save()

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True,
                                       name='NFQ-State-Backup')
        self.thread.start()

    def stop_and_save(self):
        self.stop_event.set()
        self.save_event.set()
        if self.thread is not None:
            self.thread.join(timeout=2.0)
        self.save()

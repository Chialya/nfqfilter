#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NFQfilter 13.1: per-source SYN recognition, scrambler states and persistence.

All detection operations are RAM-only and safe in the NFQUEUE callback.
The caller is responsible for asynchronously invoking the scrambler and
for applying DROP verdicts / offloading BLOCK entries to the kernel.
"""
import ipaddress
import threading
import time
from collections import deque

from config import (SINGLE_IP_PORTS, SINGLE_FAST_60, SINGLE_FAST_300,
                    SINGLE_REPEAT_COUNT, SINGLE_REPEAT_WINDOW,
                    SINGLE_REPEAT_MIN_SPAN, SINGLE_STATE_TTL,
                    SINGLE_BLOCK_TTL, SINGLE_HIGH_600, SINGLE_HIGH_3600,
                    SINGLE_HIGH_LOG_COOLDOWN, SINGLE_MAX_TRACKED,
                    SINGLE_HIGH_WINDOW)


class SingleIPFilter:
    def __init__(self):
        self.lock = threading.RLock()
        self.records = {}
        self.last_gc = 0
        self.kernel_manages_expiry = False

    @staticmethod
    def _new():
        return {'state': 'NORMAL', 'until': 0.0, 'fast': {},
                'repeat': {}, 'high': deque(maxlen=256),
                'last_high_log': 0.0, 'last_seen': 0.0,
                'generation': 0}

    @staticmethod
    def _prune(q, cutoff):
        while q and q[0] <= cutoff:
            q.popleft()

    @staticmethod
    def _reset_detection(rec):
        rec['fast'].clear()
        rec['repeat'].clear()
        # High-load history deliberately retained across WHITE/BLACK.

    def _gc(self, now):
        if now - self.last_gc < 60:
            return
        self.last_gc = now
        for ip, rec in list(self.records.items()):
            if rec['state'] == 'CHECKING':
                continue
            if rec['state'] != 'NORMAL' and rec['until'] > now:
                continue
            if rec['state'] == 'BLOCK' and self.kernel_manages_expiry:
                # The kernel worker must inspect final counters before expiry.
                continue
            if rec['state'] != 'NORMAL' and rec['until'] <= now:
                rec['state'], rec['until'] = 'NORMAL', 0.0
                self._reset_detection(rec)
            if rec['last_seen'] < now - SINGLE_HIGH_WINDOW:
                del self.records[ip]
        if len(self.records) > SINGLE_MAX_TRACKED:
            evictable = sorted((rec['last_seen'], ip)
                               for ip, rec in self.records.items()
                               if rec['state'] == 'NORMAL')
            for _, ip in evictable[:max(0, len(self.records) - SINGLE_MAX_TRACKED)]:
                del self.records[ip]

    def observe(self, ip, dst_port, src_port, policy, now=None):
        """One SYN after its actual policy decision.

        policy: WHITELIST => only HIGHLOAD;
                ACCEPT => threshold -> scrambler (BLACK/WHITE);
                DROP => threshold -> immediate /32 or /128 BLOCK.
        """
        if dst_port not in SINGLE_IP_PORTS or policy not in ('WHITELIST', 'ACCEPT', 'DROP'):
            return {'action': 'NONE'}
        now = time.time() if now is None else float(now)
        with self.lock:
            self._gc(now)
            rec = self.records.get(ip)
            if rec is None:
                if len(self.records) >= SINGLE_MAX_TRACKED:
                    self._gc(now + 60)  # bounded eviction; preserve protected states
                    if len(self.records) >= SINGLE_MAX_TRACKED:
                        return {'action': 'NONE'}
                rec = self.records[ip] = self._new()
            rec['last_seen'] = now

            # White/black expiry, except kernel-managed BLOCK (see expiry worker).
            if rec['state'] in ('WHITE', 'BLACK', 'ERROR') and rec['until'] <= now:
                rec['state'], rec['until'] = 'NORMAL', 0.0
                self._reset_detection(rec)
            high = rec['high']
            self._prune(high, now - SINGLE_HIGH_WINDOW)
            high.append(now)
            high_600 = sum(t > now - 600 for t in high)
            high_3600 = len(high)
            high_event = None
            if (high_600 >= SINGLE_HIGH_600 or high_3600 >= SINGLE_HIGH_3600):
                if now - rec['last_high_log'] >= SINGLE_HIGH_LOG_COOLDOWN:
                    rec['last_high_log'] = now
                    high_event = {'action': 'HIGHLOAD',
                                  'reason': '%d SYN/10m, %d SYN/1h' %
                                            (high_600, high_3600)}

            # Stateless whitelist: count ONLY high load; no scrambler or IP block.
            if policy == 'WHITELIST':
                return high_event or {'action': 'NONE'}

            if rec['state'] == 'BLOCK':
                if rec['until'] <= now:
                    if self.kernel_manages_expiry:
                        # Pending final kernel counter read before expiry.
                        return {'action': 'BLOCKED'}
                    rec['state'], rec['until'] = 'NORMAL', 0.0
                    self._reset_detection(rec)
                else:
                    rec['until'] = now + SINGLE_BLOCK_TTL
                    return {'action': 'BLOCKED'}

            if rec['state'] == 'CHECKING':
                return high_event or {'action': 'NONE'}

            # Existing ACCEPT is trusted for 1h after Scrambler ACCESS.
            # If the regular NFQ logic now DROPs, WHITE must not hide an attack.
            if policy == 'ACCEPT' and rec['state'] in ('WHITE', 'ERROR'):
                return high_event or {'action': 'NONE'}

            fast = rec['fast'].setdefault(dst_port, deque(maxlen=256))
            self._prune(fast, now - 300)
            fast.append(now)
            f60 = sum(t > now - 60 for t in fast)
            f300 = len(fast)

            key = (src_port, dst_port)
            repeat = rec['repeat'].setdefault(key, deque(maxlen=SINGLE_REPEAT_COUNT))
            self._prune(repeat, now - SINGLE_REPEAT_WINDOW)
            repeat.append(now)
            # Periodically discard empty repeat counters for memory control.
            if len(rec['repeat']) > 512:
                for k, v in list(rec['repeat'].items()):
                    self._prune(v, now - SINGLE_REPEAT_WINDOW)
                    if not v:
                        del rec['repeat'][k]
                if len(rec['repeat']) > 512:
                    # Attack with many unique source ports: fast rule sees it.
                    for k in list(rec['repeat'])[:len(rec['repeat']) - 512]:
                        del rec['repeat'][k]

            reason = None
            if f60 >= SINGLE_FAST_60:
                reason = '%d SYN/%ds dst=%d' % (f60, 60, dst_port)
            elif f300 >= SINGLE_FAST_300:
                reason = '%d SYN/%ds dst=%d' % (f300, 300, dst_port)
            elif (len(repeat) >= SINGLE_REPEAT_COUNT and
                  repeat[-1] - repeat[0] >= SINGLE_REPEAT_MIN_SPAN):
                reason = '%d SYN/%ds src=%d dst=%d span=%.0fs' % (
                    len(repeat), SINGLE_REPEAT_WINDOW, src_port, dst_port,
                    repeat[-1] - repeat[0])

            if reason is None:
                return high_event or {'action': 'NONE'}

            self._reset_detection(rec)
            rec['generation'] += 1
            if policy == 'DROP':
                rec['state'], rec['until'] = 'BLOCK', now + SINGLE_BLOCK_TTL
                return {'action': 'NEW_BLOCK', 'reason': 'already DROP: ' + reason}
            if rec['state'] == 'BLACK':
                rec['state'], rec['until'] = 'BLOCK', now + SINGLE_BLOCK_TTL
                return {'action': 'NEW_BLOCK', 'reason': 'BLACK repeat: ' + reason}
            rec['state'] = 'CHECKING'
            rec['until'] = now + SINGLE_STATE_TTL
            return {'action': 'CHECK', 'reason': reason,
                    'generation': rec['generation']}

    def result(self, ip, outcome, generation=None, now=None):
        now = time.time() if now is None else float(now)
        outcome = outcome if outcome in ('ACCESS', 'BAD', 'UNKNOWN') else 'ERROR'
        with self.lock:
            rec = self.records.get(ip)
            if rec is None or rec['state'] != 'CHECKING':
                return {'action': 'STALE'}
            if generation is not None and generation != rec['generation']:
                return {'action': 'STALE'}
            self._reset_detection(rec)
            if outcome == 'ACCESS':
                rec['state'], rec['until'] = 'WHITE', now + SINGLE_STATE_TTL
                action = 'WHITE'
            elif outcome == 'BAD':
                rec['state'], rec['until'] = 'BLOCK', now + SINGLE_BLOCK_TTL
                action = 'NEW_BLOCK'
            elif outcome == 'UNKNOWN':
                rec['state'], rec['until'] = 'BLACK', now + SINGLE_STATE_TTL
                action = 'BLACK'
            else:
                # Transport failure is NOT the scrambler's UNKNOWN verdict.
                rec['state'], rec['until'] = 'ERROR', now + 300
                action = 'ERROR'
            return {'action': action, 'reason': outcome}

    def fail_enqueue(self, ip, generation, now=None):
        return self.result(ip, None, generation, now)

    def is_blocked(self, ip, now=None):
        """Lesender /128- bzw. /32-Check, bevor externe API startet."""
        now = time.time() if now is None else float(now)
        with self.lock:
            rec = self.records.get(ip)
            return bool(rec and rec['state'] == 'BLOCK' and
                        (rec['until'] > now or self.kernel_manages_expiry))

    def blocked_ips(self):
        with self.lock:
            return {ip: r['until'] for ip, r in self.records.items()
                    if r['state'] == 'BLOCK'}

    def kernel_hit(self, ip, now=None):
        now = time.time() if now is None else float(now)
        with self.lock:
            r = self.records.get(ip)
            if r is not None and r['state'] == 'BLOCK':
                r['until'] = now + SINGLE_BLOCK_TTL
                return True
            return False

    def expire_blocks(self, now=None):
        """Only call after final kernel counter checks; returns expired IPs."""
        now = time.time() if now is None else float(now)
        expired = []
        with self.lock:
            for ip, r in list(self.records.items()):
                if r['state'] == 'BLOCK' and r['until'] <= now:
                    expired.append(ip)
                    r['state'], r['until'] = 'NORMAL', 0
                    self._reset_detection(r)
        return expired

    def snapshot(self, now=None):
        now = time.time() if now is None else float(now)
        with self.lock:
            self._gc(now)
            result = {}
            for ip, r in self.records.items():
                if r['state'] == 'NORMAL' and r['last_seen'] < now - SINGLE_HIGH_WINDOW:
                    continue
                result[ip] = {
                    'state': 'NORMAL' if r['state'] == 'CHECKING' else r['state'],
                    'until': r['until'], 'last_seen': r['last_seen'],
                    'fast': [[port, list(ts)] for port, ts in r['fast'].items()],
                    'repeat': [[src, dst, list(ts)] for (src, dst), ts in r['repeat'].items()],
                    'high': list(r['high']),
                    'last_high_log': r['last_high_log'],
                    'generation': r['generation']}
            return result

    def restore(self, payload, now=None):
        now = time.time() if now is None else float(now)
        with self.lock:
            self.records.clear()
            if not isinstance(payload, dict):
                return
            for ip, entry in list(payload.items())[:SINGLE_MAX_TRACKED]:
                try:
                    ipaddress.ip_address(ip)
                    r = self._new()
                    r['state'] = str(entry.get('state', 'NORMAL'))
                    if r['state'] not in ('NORMAL', 'WHITE', 'BLACK', 'BLOCK', 'ERROR'):
                        r['state'] = 'NORMAL'
                    r['until'] = float(entry.get('until', 0))
                    r['last_seen'] = float(entry.get('last_seen', 0))
                    r['last_high_log'] = float(entry.get('last_high_log', 0))
                    r['generation'] = int(entry.get('generation', 0))
                    if r['state'] != 'NORMAL' and r['until'] <= now:
                        r['state'], r['until'] = 'NORMAL', 0
                    if r['state'] == 'NORMAL' and r['last_seen'] < now - SINGLE_HIGH_WINDOW:
                        continue
                    for dst, ts in entry.get('fast', [])[:32]:
                        dst = int(dst)
                        if dst in SINGLE_IP_PORTS:
                            r['fast'][dst] = deque((float(t) for t in ts
                                if now - 300 < float(t) <= now), maxlen=256)
                    for src, dst, ts in entry.get('repeat', [])[:512]:
                        src, dst = int(src), int(dst)
                        if 0 <= src <= 65535 and dst in SINGLE_IP_PORTS:
                            r['repeat'][(src, dst)] = deque((float(t) for t in ts
                                if now - SINGLE_REPEAT_WINDOW < float(t) <= now),
                                maxlen=SINGLE_REPEAT_COUNT)
                    r['high'] = deque((float(t) for t in entry.get('high', [])
                        if now - SINGLE_HIGH_WINDOW < float(t) <= now), maxlen=256)
                    self.records[ip] = r
                except (ValueError, TypeError, KeyError, AttributeError):
                    continue

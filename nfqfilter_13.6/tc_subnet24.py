#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NFQfilter 12.8: /24 SYN-Kernel-DROP via tc ingress.

Nur bekannte, bereits in Subnet24Tracker.blocked enthaltene IPv4-Netze.
Die Regelinstallation und das Auslesen der Statistik erfolgen ausserhalb
von NFQUEUE in genau einem Worker-Thread. Kein SYN wird zum Testen freigegeben.
"""

import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time

from config import (SUBNET24_PORTS, TC24_ENABLE, TC24_INTERFACE,
                    TC24_POLL_INTERVAL, TC24_SYNC_INTERVAL,
                    TC24_STATE_FILE, TC24_PREF_START, TC24_PREF_END,
                    TC24_MAX_NETWORKS)

_PKT_RE = re.compile(r'\bSent\s+\d+\s+bytes\s+(\d+)\s+pkt\b')


class TcSubnet24Worker:
    def __init__(self, tracker, whitelist, trusted_ips):
        self.tracker = tracker
        self.whitelist = whitelist
        self.trusted_ips = trusted_ips
        self.entries = {}
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()
        self.thread = None
        self.available = False
        self.created_qdisc = False
        self.tc = shutil.which('tc')
        self.last_poll = time.time()
        self.last_warn = set()
        self.retry_after = {}

    def _run_tc(self, args, check=True):
        if not self.tc:
            raise RuntimeError('tc-Befehl fehlt')
        result = subprocess.run([self.tc] + list(args), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=8, check=False)
        if check and result.returncode:
            raise RuntimeError('tc %s: %s' % (' '.join(args),
                               (result.stderr or result.stdout).strip()))
        return result

    def _warn(self, tag, message):
        if tag not in self.last_warn:
            print('TC24:', message, flush=True)
            self.last_warn.add(tag)

    def _load(self):
        try:
            with open(TC24_STATE_FILE, 'r', encoding='utf-8') as file:
                state = json.load(file)
            if state.get('version') != 1 or state.get('interface') != TC24_INTERFACE:
                raise ValueError('Fremde oder veraltete TC24-Statusdatei')
            for net, rec in state.get('entries', {}).items():
                network = ipaddress.ip_network(net, strict=True)
                if network.version != 4 or network.prefixlen != 24:
                    continue
                prefs = {int(port): int(pref)
                         for port, pref in rec['prefs'].items()}
                if set(prefs) != set(SUBNET24_PORTS):
                    continue
                if (len(set(prefs.values())) != len(prefs)
                    or any(p < TC24_PREF_START or p > TC24_PREF_END
                           for p in prefs.values())):
                    continue
                counters = {int(port): int(cnt)
                            for port, cnt in rec.get('counters', {}).items()}
                self.entries[str(network)] = {'prefs': prefs,
                                              'counters': counters}
        except FileNotFoundError:
            pass
        except Exception as exc:
            self._warn('load', 'Statusdatei konnte nicht geladen werden: %s' % exc)

    def _save(self):
        data = {'version': 1, 'interface': TC24_INTERFACE,
                'entries': {net: {'prefs': {str(p): n for p, n in e['prefs'].items()},
                                  'counters': {str(p): n for p, n in e['counters'].items()}}
                            for net, e in self.entries.items()}}
        tmp = TC24_STATE_FILE + '.tmp'
        try:
            os.makedirs(os.path.dirname(TC24_STATE_FILE), exist_ok=True)
            with open(tmp, 'w', encoding='utf-8') as file:
                json.dump(data, file, separators=(',', ':'))
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp, TC24_STATE_FILE)
            return True
        except Exception as exc:
            self._warn('save', 'Statusdatei konnte nicht gesichert werden: %s' % exc)
            return False

    def _show(self, pref):
        return self._run_tc(['-s', 'filter', 'show', 'dev', TC24_INTERFACE,
                             'parent', 'ffff:', 'protocol', 'ip',
                             'pref', str(pref)]).stdout

    @staticmethod
    def _identifies_rule(output, network, port):
        """Verhindert Loeschen fremder Regeln unter derselben pref."""
        subnet = ipaddress.ip_network(network)
        octets = subnet.network_address.packed
        # tc u32 zeigt den Quell-IP-Vergleich als hex/ffffff00 bei Offset 12.
        address = octets.hex()[:6]
        porthex = ('%04x' % port)
        return (bool(re.search(r'\bmatch\s+' + address +
                               r'00/ffffff00\s+at\s+12\b', output, re.I))
                and bool(re.search(r'\bmatch\s+0000' + porthex +
                                   r'/0000ffff\s+at\s+20\b', output, re.I))
                and 'gact action drop' in output.lower())

    def _ensure_ingress(self):
        result = self._run_tc(['qdisc', 'show', 'dev', TC24_INTERFACE])
        if 'ingress ffff:' in result.stdout or 'clsact ffff:' in result.stdout:
            return
        self._run_tc(['qdisc', 'add', 'dev', TC24_INTERFACE, 'ingress'])
        self.created_qdisc = True
        print('TC24: ingress qdisc an %s eingerichtet' % TC24_INTERFACE, flush=True)

    def _used_prefs(self):
        output = self._run_tc(['filter', 'show', 'dev', TC24_INTERFACE,
                               'parent', 'ffff:']).stdout
        return {int(pref) for pref in re.findall(r'\bpref\s+(\d+)\b', output)}

    def _alloc(self):
        used = self._used_prefs()
        # Eigene IDs sind ebenfalls in used: bestehende Eintraege werden
        # ausschliesslich anhand ihrer eigenen gespeicherten IDs verwaltet.
        slots = []
        for p in range(TC24_PREF_START, TC24_PREF_END + 1):
            if p not in used:
                slots.append(p)
                if len(slots) == len(SUBNET24_PORTS):
                    return dict(zip(sorted(SUBNET24_PORTS), slots))
        raise RuntimeError('TC24-Prioritaetsbereich ist voll')

    def _add_rule(self, net, port, pref):
        # IHL=5 verhindert Fehlmatches bei IPv4-Optionen. Nur TCP-SYN ohne
        # FIN/RST/ACK/PSH/URG; ECN-Bits bleiben moeglich. Keine bereits
        # bestehenden TCP-Verbindungen oder anderen Ports blockieren.
        self._run_tc(['filter', 'add', 'dev', TC24_INTERFACE,
                      'parent', 'ffff:', 'protocol', 'ip', 'pref', str(pref),
                      'u32',
                      'match', 'ip', 'src', net,
                      'match', 'ip', 'protocol', '6', '0xff',
                      'match', 'u8', '0x05', '0x0f', 'at', '0',
                      'match', 'ip', 'dport', str(port), '0xffff',
                      'match', 'u8', '0x02', '0x3f', 'at', '33',
                      'action', 'drop'])
        out = self._show(pref)
        if not self._identifies_rule(out, net, port):
            raise RuntimeError('TC24-Regel nach Anlage nicht sicher lesbar (%s / %s)' % (net, port))

    def _delete_rule(self, net, port, pref):
        try:
            output = self._show(pref)
            if not output.strip():
                return True
            if not self._identifies_rule(output, net, port):
                self._warn((net, pref), 'Fremde/veraenderte Regel bei pref %s: nicht geloescht' % pref)
                return False
            self._run_tc(['filter', 'del', 'dev', TC24_INTERFACE,
                          'parent', 'ffff:', 'protocol', 'ip', 'pref', str(pref)])
            return True
        except Exception as exc:
            self._warn(('del', net, pref), 'Regelentfernung fehlgeschlagen: %s' % exc)
            return False

    def _remove(self, net):
        entry = self.entries.get(net)
        if entry is None:
            return
        all_gone = True
        for port, pref in entry['prefs'].items():
            if not self._delete_rule(net, port, pref):
                all_gone = False
        if all_gone:
            del self.entries[net]
            self._save()
            print('TC24: entfernt %s' % net, flush=True)

    def _safe_to_drop(self, net):
        candidate = ipaddress.ip_network(net)
        # Statische Whitelist aus 12.7 hat Vorrang vor /24-Sperre. Eine
        # Kernel-Regel darf eine bereits whitelisted IP nicht treffen.
        for allowed in self.whitelist.ipv4:
            if candidate.overlaps(allowed):
                return False
        # Zusaetzlich dynamisch freigeschaltete Helper-IPs schuetzen.
        with self.trusted_ips.lock:
            now = time.time()
            for ip, expiry in self.trusted_ips.entries.items():
                if expiry > now and ipaddress.ip_address(ip) in candidate:
                    return False
        return True

    def _install(self, net):
        if time.time() < self.retry_after.get(net, 0):
            return
        if len(self.entries) >= TC24_MAX_NETWORKS:
            self._warn('max', 'Maximale tc-/24-Regelzahl erreicht; NFQUEUE bleibt aktiv')
            return
        try:
            prefs = self._alloc()
            # Persistieren VOR Anlage, damit ein unerwarteter Prozessabbruch
            # keine unerkennbaren tc-Regeln zuruecklaesst.
            self.entries[net] = {'prefs': prefs, 'counters': {}}
            if not self._save():
                raise RuntimeError('TC24-Status nicht persistent speicherbar')
            for port, pref in prefs.items():
                self._add_rule(net, port, pref)
            self.entries[net]['counters'] = {p: 0 for p in prefs}
            self._save()
            print('TC24: aktiv %s (SYN auf %s, %s)' %
                  (net, TC24_INTERFACE, sorted(prefs)), flush=True)
        except Exception as exc:
            self._warn(('add', net), 'Installation %s fehlgeschlagen: %s; NFQUEUE-Fallback' % (net, exc))
            self._remove(net)
            self.retry_after[net] = time.time() + 60

    def _snapshot_blocked(self):
        with self.tracker.lock:
            return dict(self.tracker.blocked)

    def _reconcile(self):
        now = time.time()
        blocked = self._snapshot_blocked()
        for net in list(self.entries):
            if net not in blocked or not self._safe_to_drop(net):
                self._remove(net)
        for net, expires in blocked.items():
            if expires > now and net not in self.entries:
                if self._safe_to_drop(net):
                    self._install(net)
                else:
                    self._warn(('white', net), '%s ueberlappt eine Freigabe: nur NFQUEUE' % net)

    def _poll_counters(self, only=None):
        now = time.time()
        modified = False
        for net, rec in list(self.entries.items()):
            if only is not None and net not in only:
                continue
            delta = 0
            invalid = False
            for port, pref in rec['prefs'].items():
                try:
                    output = self._show(pref)
                    if not self._identifies_rule(output, net, port):
                        invalid = True
                        break
                    found = _PKT_RE.findall(output)
                    if len(found) != 1:
                        invalid = True
                        break
                    current = int(found[0])
                    previous = rec['counters'].get(port, 0)
                    if current >= previous:
                        delta += current - previous
                    # Zaehlerreset: unbekannte fruehere Pakete nicht erfinden.
                    rec['counters'][port] = current
                    modified = True
                except Exception as exc:
                    self._warn(('counter', net, port), 'Zaehler %s:%d unlesbar: %s' % (net, port, exc))
                    invalid = True
                    break
            if invalid:
                self._warn(('invalid', net), 'Sicherheitsrueckfall auf NFQUEUE fuer %s' % net)
                self._remove(net)
                continue
            if delta:
                # Waerend der Laufzeit koennen die NFQUEUE-Callbacks dieselbe
                # Sperre verlaengern; niemals den spaeteren Ablauf verkürzen.
                with self.tracker.lock:
                    expiry = self.tracker.blocked.get(net)
                    if expiry is not None:
                        self.tracker.blocked[net] = max(expiry, now + self.tracker.block_ttl)
                        print('TC24: %s +%d SYN, Block +%ds' %
                              (net, delta, self.tracker.block_ttl), flush=True)
        if modified:
            self._save()

    def _expire_due(self):
        """Letzte tc-Zaehlerpruefung VOR der /24-Entsperrung.

        Auch bei einem Ablauf zwischen zwei regulaeren 10-Minuten-Polls
        bleiben die bis dahin gedroppten SYNs beruecksichtigt.
        """
        now = time.time()
        with self.tracker.lock:
            due = {net for net, expires in self.tracker.blocked.items()
                   if expires <= now}
        if not due:
            return
        # Bei einem tc-Fehler darf die Sperre regulär ablaufen; niemals
        # willkuerlich eine Verlängerung ohne nachgewiesene Treffer erfinden.
        self._poll_counters(only=due)
        now = time.time()
        with self.tracker.lock:
            for net in due:
                if self.tracker.blocked.get(net, float('inf')) <= now:
                    del self.tracker.blocked[net]
                    print('TC24: abgelaufen %s' % net, flush=True)

    def _worker(self):
        try:
            self._ensure_ingress()
            self.available = True
            self._load()
            # Gespeicherte, bereits abgelaufene Sperren sind beim Laden
            # verworfen worden. Vorhandene alte tc-Regeln abgleichen.
            self._reconcile()
            # Neustart: absolute Ablaufzeiten aus dem gespeicherten
            # Zustand gelten weiter. Uebrige aktive Regeln uebernehmen.
            self._poll_counters()
            self.last_poll = time.time()
            while not self.stop_event.is_set():
                self.wake_event.wait(TC24_SYNC_INTERVAL)
                self.wake_event.clear()
                if self.stop_event.is_set():
                    break
                # Zuerst regulaere Statistik, dann letzte Pruefung
                # bei faelligen Sperren, erst danach Regeln entfernen.
                if time.time() - self.last_poll >= TC24_POLL_INTERVAL:
                    self._poll_counters()
                    self.last_poll = time.time()
                self._expire_due()
                self._reconcile()
        except Exception as exc:
            self._warn('fatal', 'Worker ausgefallen: %s' % exc)
        finally:
            with self.tracker.lock:
                self.tracker.tc_manages_expiry = False
            # Keine verwaisten Sperren nach regulaerem Beenden: selbst wenn
            # Python/NFQUEUE stoppt, soll tc nicht dauerhaft weiter blocken.
            for net in list(self.entries):
                self._remove(net)
            self.available = False
            if self.created_qdisc:
                try:
                    if not self._run_tc(['filter', 'show', 'dev', TC24_INTERFACE,
                                         'parent', 'ffff:']).stdout.strip():
                        self._run_tc(['qdisc', 'del', 'dev', TC24_INTERFACE, 'ingress'])
                except Exception:
                    pass

    def start(self):
        if not TC24_ENABLE:
            # Falls nach einem Crash tc-Regeln uebrig sind und der Anwender
            # TC24 inzwischen deaktiviert hat, nur unsere Regeln aufraeumen.
            if os.path.exists(TC24_STATE_FILE) and self.tc:
                self._load()
                for net in list(self.entries):
                    self._remove(net)
            print('TC24: deaktiviert (TC24_ENABLE=False)', flush=True)
            return
        with self.tracker.lock:
            self.tracker.tc_manages_expiry = True
        self.thread = threading.Thread(target=self._worker, daemon=True,
                                       name='NFQ-TC24')
        self.thread.start()

    def notify(self):
        self.wake_event.set()

    def stop(self):
        self.stop_event.set()
        self.wake_event.set()
        if self.thread is not None:
            self.thread.join(timeout=30)
            if self.thread.is_alive():
                self._warn('stop', 'Worker konnte nicht rechtzeitig beendet werden; TC24-Statusdatei pruefen')

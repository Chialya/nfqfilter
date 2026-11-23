#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NFQfilter 13.1: optional early kernel DROP for currently BLOCKed IPs.

Dedicated ipsets with counters + exactly one WAN-ingress mangle rule per family.
No shell commands in the NFQUEUE callback. On every expiry, read counters
BEFORE deleting any entry. User-space DROP works even without kernel support.
"""
import ipaddress
import re
import shutil
import subprocess
import threading
import time

from config import (IP32_KERNEL_ENABLE, IP32_KERNEL_INTERFACE,
                    IP32_KERNEL_SYNC_INTERVAL, IP32_KERNEL_POLL_INTERVAL,
                    IP32_KERNEL_SET4, IP32_KERNEL_SET6,
                    IP32_KERNEL_MAX_MEMBERS, IP32_RULE_CHECK_INTERVAL,
                    SINGLE_IP_PORTS)

_MEMBER_RE = re.compile(r'^([^\s]+)\s+packets\s+(\d+)\s+bytes\s+(\d+)\s*$')


class KernelIP32Worker:
    def __init__(self, tracker, whitelist):
        self.tracker = tracker
        self.whitelist = whitelist
        self.enabled = IP32_KERNEL_ENABLE
        self.available = False
        self.ipset = shutil.which('ipset')
        self.iptables = shutil.which('iptables')
        self.ip6tables = shutil.which('ip6tables')
        self.stop_event = threading.Event()
        self.thread = None
        self.members = set()
        self.last_count = {}
        self.last_poll = 0
        self.last_rule_check = 0
        self.warned = set()
        self.owned_rules = set()
        self.ready = False
        self.on_change = None

    def _warn(self, name, message):
        if name not in self.warned:
            print('IP32:', message, flush=True)
            self.warned.add(name)

    def _run_cmd(self, args, input_text=None, check=True):
        proc = subprocess.run(args, input=input_text, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=15, check=False)
        if check and proc.returncode != 0:
            raise RuntimeError('%s: %s' % (' '.join(args),
                               (proc.stderr or proc.stdout).strip()))
        return proc

    def _rule(self, ipv6):
        setname = IP32_KERNEL_SET6 if ipv6 else IP32_KERNEL_SET4
        tool = self.ip6tables if ipv6 else self.iptables
        return (tool, ['-i', IP32_KERNEL_INTERFACE, '-p', 'tcp',
                       '-m', 'multiport', '--dports', ','.join(map(str, sorted(SINGLE_IP_PORTS))),
                       '--tcp-flags', 'SYN,ACK,RST', 'SYN',
                       '-m', 'set', '--match-set', setname, 'src', '-j', 'DROP'])

    def _remove_rules(self):
        """Remove only our specific rule, including duplicates after crashes."""
        for ipv6 in (False, True):
            tool, rule = self._rule(ipv6)
            if not tool:
                continue
            for _ in range(8):
                if self._run_cmd([tool, '-w', '-t', 'mangle', '-C', 'PREROUTING'] + rule,
                                 check=False).returncode != 0:
                    break
                self._run_cmd([tool, '-w', '-t', 'mangle', '-D', 'PREROUTING'] + rule)

    def _ensure_rules(self):
        """Repair our match rules when UniFi provisioning has replaced them."""
        for ipv6 in (False, True):
            tool, rule = self._rule(ipv6)
            if self._run_cmd([tool, '-w', '-t', 'mangle', '-C', 'PREROUTING'] + rule,
                             check=False).returncode != 0:
                self._run_cmd([tool, '-w', '-t', 'mangle', '-I', 'PREROUTING', '1'] + rule)
                print('IP32: Regel wiederhergestellt (%s)' %
                      ('IPv6' if ipv6 else 'IPv4'), flush=True)
        self.last_rule_check = time.time()

    def _install(self):
        if not all((self.ipset, self.iptables, self.ip6tables)):
            self._warn('missing', 'ipset/iptables/ip6tables fehlt; NFQUEUE bleibt aktiv')
            return False
        # On reboot or unclean restart the old matching rule may still exist.
        # Remove it BEFORE synchronizing sets, so stale IPs are never dropped.
        self._remove_rules()
        self._run_cmd([self.ipset, 'create', IP32_KERNEL_SET4, 'hash:ip',
                       'family', 'inet', 'counters', '-exist'])
        self._run_cmd([self.ipset, 'create', IP32_KERNEL_SET6, 'hash:ip',
                       'family', 'inet6', 'counters', '-exist'])
        for name in (IP32_KERNEL_SET4, IP32_KERNEL_SET6):
            output = self._run_cmd([self.ipset, 'list', name]).stdout
            if 'counters' not in output.split('Members:')[0]:
                raise RuntimeError('%s ohne counters, nicht uebernehmbar' % name)
            # Dedicated sets: source of truth is persisted cache_state.json.
            self._run_cmd([self.ipset, 'flush', name])
        self.members.clear()
        self.last_count.clear()
        self._update(time.time())
        # Enable kernel drop ONLY after restoring currently valid members.
        self._ensure_rules()
        return True

    def _stats(self):
        counters = {}
        for name in (IP32_KERNEL_SET4, IP32_KERNEL_SET6):
            output = self._run_cmd([self.ipset, 'list', name]).stdout
            members = output.split('Members:', 1)[-1]
            for line in members.splitlines():
                match = _MEMBER_RE.match(line.strip())
                if match:
                    counters[match.group(1)] = int(match.group(2))
        return counters

    def _update(self, now):
        # First: full count check BEFORE expiry cleanup. A hit since the
        # previous check extends the expiry, including at the last instant.
        counters = self._stats()
        changed = False
        for ip, cnt in counters.items():
            prev = self.last_count.get(ip, 0)
            if cnt > prev:
                changed = self.tracker.kernel_hit(ip, now) or changed
        self.last_count = counters
        self.last_poll = now
        expired = self.tracker.expire_blocks(now)
        changed = bool(expired) or changed
        if changed and self.on_change:
            self.on_change()
        desired_all = self.tracker.blocked_ips()
        desired = {ip for ip in desired_all
                   if not self.whitelist.is_whitelisted(ip)}
        if len(desired) > IP32_KERNEL_MAX_MEMBERS:
            # Excess entries stay in userspace, never relax the active limit.
            self._warn('limit', 'Maximale ipset-Belegung erreicht')
            desired = set(sorted(desired, key=lambda ip: desired_all[ip], reverse=True)
                          [:IP32_KERNEL_MAX_MEMBERS])
        existing = set(counters)
        additions = desired - existing
        removals = existing - desired
        if additions or removals:
            # ipset restore -exist batches thousands of entries efficiently.
            lines = []
            for ip in sorted(removals):
                name = IP32_KERNEL_SET6 if ipaddress.ip_address(ip).version == 6 else IP32_KERNEL_SET4
                lines.append('del %s %s' % (name, ip))
            for ip in sorted(additions):
                name = IP32_KERNEL_SET6 if ipaddress.ip_address(ip).version == 6 else IP32_KERNEL_SET4
                lines.append('add %s %s' % (name, ip))
            self._run_cmd([self.ipset, 'restore', '-exist'], '\n'.join(lines) + '\n')
            for ip in removals:
                self.last_count.pop(ip, None)
            for ip in additions:
                self.last_count[ip] = 0
        self.members = desired

    def _run(self):
        try:
            self.ready = self._install()
        except Exception as exc:
            self._warn('start', 'Kernel-Sperren deaktiviert: %s' % exc)
            self.ready = False
        if not self.ready:
            self._teardown()  # bei teilweiser Installation rueckgaengig machen
            return
        self.tracker.kernel_manages_expiry = True
        try:
            while not self.stop_event.wait(IP32_KERNEL_SYNC_INTERVAL):
                now = time.time()
                if now - self.last_rule_check >= IP32_RULE_CHECK_INTERVAL:
                    self._ensure_rules()
                blocks = self.tracker.blocked_ips()
                nearing_expiry = any(until <= now + IP32_KERNEL_POLL_INTERVAL
                                     for until in blocks.values())
                if now - self.last_poll >= IP32_KERNEL_POLL_INTERVAL or nearing_expiry:
                    self._update(now)
                else:
                    # New BLOCKs must enter the set quickly; checking per-IP
                    # stats is not required to add only the new members.
                    desired = {ip for ip in blocks if not self.whitelist.is_whitelisted(ip)}
                    if desired != self.members:
                        self._update(now)
        except Exception as exc:
            self._warn('runtime', 'Fehler, Kernel-Sperren werden entfernt: %s' % exc)
        finally:
            # A final count check before shutting down prevents losing the
            # last 60 seconds of kernel hits / expiry extensions.
            if self.ready:
                try:
                    self._update(time.time())
                except Exception as exc:
                    self._warn('final', 'Letzte Trefferpruefung fehlgeschlagen: %s' % exc)
            self._teardown()

    def _teardown(self):
        try:
            self._remove_rules()
        except Exception:
            pass
        if self.ipset:
            for name in (IP32_KERNEL_SET4, IP32_KERNEL_SET6):
                try:
                    self._run_cmd([self.ipset, 'flush', name], check=False)
                    self._run_cmd([self.ipset, 'destroy', name], check=False)
                except Exception:
                    pass
        self.tracker.kernel_manages_expiry = False
        self.ready = False

    def start(self):
        if not self.enabled:
            print('IP32: Kernel-Sperren deaktiviert; DROP nur in NFQUEUE', flush=True)
            return
        self.thread = threading.Thread(target=self._run, name='NFQ-IP32', daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=20)

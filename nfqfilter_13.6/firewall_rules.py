#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NFQfilter 13.6: direkte NFQUEUE-Regeln in mangle/POSTROUTING.

Ein Regel-Eintrag je konfiguriertem Port und IP-Familie, ohne eigene
iptables-Ketten. Ausschliesslich eindeutig als NFQfilter markierte Regeln
werden beim Neustart ersetzt oder beim Stop entfernt.
"""

import ipaddress
import re
import shlex
import subprocess

import config


class FirewallRuleError(RuntimeError):
    pass


def _as_port_list(ports):
    if isinstance(ports, (str, bytes)):
        raise ValueError('NFQ_PORTS muss eine Liste oder Menge von Ports sein')
    result = []
    try:
        for value in ports:
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
                raise ValueError('Ungueltiger NFQ_PORTS-Eintrag: %r' % (value,))
            result.append(value)
    except TypeError as exc:
        raise ValueError('NFQ_PORTS muss iterierbar sein') from exc
    if not result:
        raise ValueError('NFQ_PORTS darf nicht leer sein')
    return sorted(set(result))


def _as_networks(networks, version):
    if isinstance(networks, (str, bytes)):
        raise ValueError('NFQ_EXCLUDE_IPV%d muss eine Liste/Menge sein' % version)
    try:
        parsed = []
        for value in networks:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != version:
                raise ValueError('Falsche Adressfamilie in NFQ_EXCLUDE_IPV%d: %s' % (version, value))
            parsed.append(network)
    except TypeError as exc:
        raise ValueError('NFQ_EXCLUDE_IPV%d muss iterierbar sein' % version) from exc
    # Ueberlappende Netze zusammenfassen. Eine uebrig bleibende Quelle
    # wird ohne ipset direkt mit ! -s ausgeschlossen.
    return [str(net) for net in ipaddress.collapse_addresses(parsed)]


def _ipv6_match(value):
    # Erlaubt auch nicht-kontinuierliche IPv6-Zielmasken, z.B.
    # ::3/::ffff:ffff:ffff:ffff fuer wechselnde Prefixe bei fester Host-ID.
    if not isinstance(value, str):
        raise ValueError('NFQ_IPV6_TARGET muss eine IPv6-Zielangabe sein')
    parts = value.split('/')
    if len(parts) > 2 or not parts[0]:
        raise ValueError('Ungueltiges NFQ_IPV6_TARGET')
    ipaddress.IPv6Address(parts[0])
    if len(parts) == 2:
        if re.fullmatch(r'\d+', parts[1]):
            if not 0 <= int(parts[1]) <= 128:
                raise ValueError('Ungueltige IPv6-Praefixlaenge')
        else:
            ipaddress.IPv6Address(parts[1])
    return value


class FirewallRuleManager:
    COMMENT = 'NFQfilter'                 # keine Versionsnummer im Regelwerk
    OLD_CHAINS = {'iptables': 'NFQ133_POST4',
                  'ip6tables': 'NFQ133_POST6'}
    EXCLUDE_SETS = {'iptables': ('NFQFILTER_EX4', 'inet'),
                    'ip6tables': ('NFQFILTER_EX6', 'inet6')}

    def __init__(self, runner=None):
        self._runner = runner or subprocess.run
        self.ports = _as_port_list(config.NFQ_PORTS)
        self.interface = config.NFQ_INTERFACE
        if not isinstance(self.interface, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', self.interface):
            raise ValueError('NFQ_INTERFACE ist ungueltig')
        self.ipv4_target = str(ipaddress.IPv4Address(config.NFQ_IPV4_TARGET)) + '/32'
        self.ipv6_target = _ipv6_match(config.NFQ_IPV6_TARGET)
        self.exclude4 = _as_networks(config.NFQ_EXCLUDE_IPV4, 4)
        self.exclude6 = _as_networks(config.NFQ_EXCLUDE_IPV6, 6)

    def _run(self, binary, *args, check=True):
        command = [binary] + (['-w', '5'] if binary in ('iptables', 'ip6tables') else []) + list(args)
        try:
            response = self._runner(command, capture_output=True, text=True, check=False)
        except OSError as exc:
            raise FirewallRuleError('%s nicht ausfuehrbar: %s' % (binary, exc)) from exc
        if check and response.returncode != 0:
            message = (response.stderr or response.stdout or 'Fehler').strip()
            raise FirewallRuleError('%s: %s' % (' '.join(command), message))
        return response

    @staticmethod
    def _value(rule, key):
        try:
            return rule[rule.index(key) + 1]
        except (ValueError, IndexError):
            return None

    def _rules(self, binary, chain='POSTROUTING', allow_missing=False):
        response = self._run(binary, '-t', 'mangle', '-S', chain, check=not allow_missing)
        if response.returncode != 0:
            return None
        return [shlex.split(line) for line in response.stdout.splitlines()
                if line.startswith('-A ')]

    def _remove_owned_direct(self, binary):
        # Kein pauschales Loeschen von POSTROUTING oder fremden NFQUEUE-Regeln.
        for rule in self._rules(binary) or []:
            if (self._value(rule, '-j') == 'NFQUEUE'
                    and self._value(rule, '--comment') == self.COMMENT):
                self._run(binary, '-t', 'mangle', '-D', 'POSTROUTING', *rule[2:])

    def _remove_old_13_3(self, binary):
        # Einmaliger Umstieg von der eigenen v13.3-Kette. Ausschliesslich
        # die damals verwendete NFQ133-Kette in mangle; nie FORWARD/UniFi.
        chain = self.OLD_CHAINS[binary]
        for rule in self._rules(binary) or []:
            if self._value(rule, '-j') == chain:
                self._run(binary, '-t', 'mangle', '-D', 'POSTROUTING', *rule[2:])
        if self._rules(binary, chain, allow_missing=True) is not None:
            self._run(binary, '-t', 'mangle', '-F', chain)
            self._run(binary, '-t', 'mangle', '-X', chain)

    def _remove_unused_ipset(self, binary):
        name, _family = self.EXCLUDE_SETS[binary]
        # Fehlendes ipset/Set ist bei 0-1 Ausnahmen kein Fehler.
        try:
            self._run('ipset', 'destroy', name, check=False)
        except FirewallRuleError:
            pass

    def _source_match(self, binary, exclusions):
        if not exclusions:
            self._remove_unused_ipset(binary)
            return []
        if len(exclusions) == 1:
            self._remove_unused_ipset(binary)
            return ['!', '-s', exclusions[0]]
        # Nur bei mehreren Ausnahmen: ipset statt eigener iptables-Chain.
        name, family = self.EXCLUDE_SETS[binary]
        self._run('ipset', 'create', name, 'hash:net', 'family', family, '-exist')
        self._run('ipset', 'flush', name)
        for net in exclusions:
            self._run('ipset', 'add', name, net, '-exist')
        return ['-m', 'set', '!', '--match-set', name, 'src']

    def _install_family(self, binary, target, exclusions, ipv6=False):
        self._remove_owned_direct(binary)
        self._remove_old_13_3(binary)
        source_match = self._source_match(binary, exclusions)

        # -I 1 in umgekehrter Reihenfolge ergibt aufsteigende Portliste.
        for port in reversed(self.ports):
            # Originalzielport fuer IPv4 (vor DNAT), Zielport fuer IPv6.
            tcp_port = ['--dport', str(port)] if ipv6 else []
            orig_port = [] if ipv6 else ['--ctorigdstport', str(port)]
            self._run(binary, '-t', 'mangle', '-I', 'POSTROUTING', '1',
                      *source_match, '-d', target, '-o', self.interface,
                      '-p', 'tcp', '-m', 'tcp', '--tcp-flags', 'SYN,RST,ACK', 'SYN',
                      *tcp_port, '-m', 'conntrack', '--ctstate', 'NEW', *orig_port,
                      '-m', 'comment', '--comment', self.COMMENT,
                      '-j', 'NFQUEUE', '--queue-num', '0', '--queue-bypass')

    def start(self):
        try:
            self._install_family('iptables', self.ipv4_target, self.exclude4)
            self._install_family('ip6tables', self.ipv6_target, self.exclude6, True)
        except Exception:
            # Teilweise installierte eigene Regeln entfernen; keine UniFi-Regeln.
            try:
                self.stop()
            except Exception as cleanup_exc:
                print('NFQfilter: Rollback fehlgeschlagen: %s' % cleanup_exc)
            raise
        print('NFQfilter: direkte IPv4/IPv6-POSTROUTING-Regeln fuer Queue 0 aktiv')

    def stop(self):
        errors = []
        for binary in ('iptables', 'ip6tables'):
            try:
                self._remove_owned_direct(binary)
                self._remove_unused_ipset(binary)
            except Exception as exc:
                errors.append('%s: %s' % (binary, exc))
        if errors:
            raise FirewallRuleError('Fehler beim Entfernen der NFQfilter-Regeln: ' + '; '.join(errors))

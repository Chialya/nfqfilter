#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# NFQfilter 13.6 - zentrale Konfiguration (Änderungen erst nach Neustart)

import os

# DATA_DIR ist das Verzeichnis dieser Konfigurationsdatei. Alle persistenten
# Daten liegen hier, sofern kein eigener absoluter Pfad konfiguriert wird.
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(DATA_DIR)  # Programmverzeichnis (Kompatibilitaet)

# NFQUEUE / Firewall: direkte Regeln je Port in mangle/POSTROUTING.
# Bei >1 auszuschliessendem Quellnetz pro Adressfamilie wird ipset benoetigt.
# Alle Ports benutzen EINZIG Queue 0. Nur weitergeleitete TCP-SYNs.
NFQ_PORTS = {25, 5001}             # mehrere Ports moeglich
NFQ_INTERFACE = "br0"                   # Ausgangsschnittstelle zum NAS
NFQ_IPV4_TARGET = "192.168.0.10"       # NAS-IPv4 NACH DNAT
# IPv6: nur die feste Host-ID vergleichen, auch bei wechselndem /64-Praefix
NFQ_IPV6_TARGET = "::10/::ffff:ffff:ffff:ffff"
NFQ_EXCLUDE_IPV4 = {"192.168.0.0/16"}  # Quellen, die NFQUEUE umgehen
NFQ_EXCLUDE_IPV6 = {"fd00::/8"}        # z.B. {"fd00::/8"} sonst set()


# DNS / PTR
DNS_SERVERS = ["1.1.1.1", "9.9.9.9", "8.8.8.8"]
DNS_NAMES = {"1.1.1.1": "A", "9.9.9.9": "B", "8.8.8.8": "C"}
DNS_PORT = 53
DNS_TIMEOUT = 1.0
DNS_DOWN_TIME = 60
DNS_WORKERS = 4

# Gemeinsamer DNS-Gesundheitstest
HEALTH_TEST_IP = "8.8.8.8"
HEALTH_TEST_PTR = "dns.google"
HEALTH_POSITIVE_TTL = 600
HEALTH_NEGATIVE_TTL = 30
HEALTH_TIMEOUT = 3.0

# DNS-Entscheidungscache
CACHE_TTL = 86400           # PTR vorhanden: 24 Stunden (ACPT oder DROP B)
TEMP_BLOCK_TTL = 3600      # IPv4 ohne PTR / IPv6 ohne PTR: 1 Stunde
DNS_TIMEOUT_DROP_TTL = 86400 # DROP T mit positivem Gesundheitstest

# AbuseIPDB APIv2: nur am Ende der regulaeren Pruefkette bei ACPT -
# Nach Eintragen des Keys ABUSEIPDB_ENABLE=True setzen.
ABUSEIPDB_ENABLE = True
ABUSEIPDB_API_KEY = "xxx"
# Port -> Mindestscore (1..100); Score >= Grenzwert => DROP.
# Beispiel fuer mehrere Ports: {443: 40, 5001: 60}
# Standard behaelt das bisherige Verhalten von v13.4 bei.
ABUSEIPDB_PORTS = {5001: 10, 25: 90}
ABUSEIPDB_TIMEOUT = 3.0        # Socket-Timeout in Sekunden
ABUSEIPDB_WORKERS = 4
ABUSEIPDB_QUEUE_SIZE = 256
ABUSEIPDB_CACHE_TTL = 86400     # erfolgreiche Bewertung: min. 24h
ABUSEIPDB_ERROR_TTL = 300      # API-Fehler: ACPT fuer 5min
ABUSEIPDB_MAX_AGE_DAYS = 30    # Berichte der letzten 30 Tage

# /24 Angriffserkennung - unverändert aus 12.3
SUBNET24_PORTS = {443, 5001}
SUBNET24_THRESHOLD = 10
SUBNET24_WINDOW = 60
SUBNET24_BLOCK_TTL = 3600

# Nginx Helper
HELPER_HOST = "192.168.0.10"
HELPER_PORT = 8765
CONNECT_TIMEOUT = 1.0
READ_TIMEOUT = 2.0
TRUSTED_TTL = 3600
BAD_TTL = 3600

# Logging
DEBUG = True
# Leer/nicht gesetzt: DATA_DIR/logs. Relative Angaben beziehen sich auf DATA_DIR.
# Absolute Linux-Pfade werden unveraendert verwendet.
LOG_DIR = ""
_configured_log_dir = globals().get("LOG_DIR", "")
if not _configured_log_dir:
    LOG_DIR = os.path.join(DATA_DIR, "logs")
elif not os.path.isabs(_configured_log_dir):
    LOG_DIR = os.path.abspath(os.path.join(DATA_DIR, _configured_log_dir))
else:
    LOG_DIR = os.path.abspath(_configured_log_dir)
LOG_FILE = os.path.join(LOG_DIR, "nfqfilter.log")
LOG_WHITELIST_FILE = os.path.join(LOG_DIR, "nfqfilter_whitelist.log")

# Listen und persistente Statusdateien liegen im DATA_DIR.
IPV4_FILE = os.path.join(DATA_DIR, "blocked_ipv4.txt")
IPV6_FILE = os.path.join(DATA_DIR, "blocked_ipv6.txt")
BLOCKED_PTR_FILE = os.path.join(DATA_DIR, "blocked_ptr.txt")
WHITELIST_IPV4_FILE = os.path.join(DATA_DIR, "whitelist_ipv4.txt")
WHITELIST_IPV6_FILE = os.path.join(DATA_DIR, "whitelist_ipv6.txt")
DNS_ERROR_LOG = os.path.join(DATA_DIR, "dns_errors.log")
LOCK_FILE = os.path.join(DATA_DIR, ".nfqfilter.lock")

# RAM-Zustand sichern / wiederherstellen
STATE_FILE = os.path.join(DATA_DIR, "cache_state.json")
STATE_SAVE_INTERVAL = 60   # periodisch, auch bei Stromausfall
STATE_SAVE_DEBOUNCE = 5   # Zustandswechsel asynchron, Schreiblast begrenzen

# Einzel-IP-SYN-Flutschutz (konservative Startwerte)
IP_FLOOD_PORTS = {25: 300, 5001: 600}  # unterschiedliche SYN-Quellports in 60 s
IP_FLOOD_WINDOW = 60
IP_FLOOD_MIN_DURATION = 20           # Aktivitaet ueber mindestens 20 s
IP_FLOOD_BLOCK_TTL = 900             # 15 Minuten; erneute SYNs verlaengern

# /24 SYN-Kernel-Fastdrop (NFQfilter 12.8), nur IPv4, Ports wie SUBNET24_PORTS
TC24_ENABLE = False  # erst nach dem tc24-Selbsttest aktivieren
TC24_INTERFACE = "eth1"
TC24_POLL_INTERVAL = 600       # Paketzaehler exakt alle 10 min
TC24_SYNC_INTERVAL = 10       # Nur Abgleich von Sperrliste/Whitelist
TC24_MAX_NETWORKS = 256      # Schutz vor uebermaessig vielen tc-Regeln
TC24_PREF_START = 30000      # Fremde tc-Prioritaeten (z.B. NO) nicht verwenden
TC24_PREF_END = 30999
TC24_STATE_FILE = os.path.join(DATA_DIR, "tc_subnet24_state.json")

# V13.1 Einzel-IP-Erkennung / Scrambler. IPv4 und IPv6, nur TCP SYN.
SINGLE_IP_PORTS = {25, 5001}
SINGLE_FAST_60 = 10                   # SYN einer IP zum selben Zielport
SINGLE_FAST_300 = 20
SINGLE_REPEAT_COUNT = 5              # identischer Quell- UND Zielport
SINGLE_REPEAT_WINDOW = 1200          # 20 min, fuer langsame Angriffswellen
SINGLE_REPEAT_MIN_SPAN = 60
SINGLE_STATE_TTL = 3600              # WHITE / BLACK je eine Stunde
SINGLE_BLOCK_TTL = 3600              # /32 oder /128 nach letztem Treffer
SINGLE_HIGH_600 = 60                 # nur Meldegrenze, kein Auto-DROP
SINGLE_HIGH_3600 = 120
SINGLE_HIGH_WINDOW = 3600
SINGLE_HIGH_LOG_COOLDOWN = 3600
SINGLE_MAX_TRACKED = 10000          # Speicherbegrenzung

# V13 Kernel-fastdrop fuer Einzel-IP-Sperren (nicht fuer Erkennung).
# Beim Fehlschlag erfolgt weiterhin DROP im NFQUEUE-Callback.
IP32_KERNEL_ENABLE = False  # erst nach UCG-Livepruefung aktivieren
IP32_KERNEL_INTERFACE = "eth1"
IP32_KERNEL_SYNC_INTERVAL = 2
IP32_RULE_CHECK_INTERVAL = 30    # Provisioning / iptables-Regelverlust
IP32_KERNEL_POLL_INTERVAL = 60
IP32_KERNEL_SET4 = "NFQ13_DROP4"
IP32_KERNEL_SET6 = "NFQ13_DROP6"
IP32_KERNEL_MAX_MEMBERS = 2500

# tc-Eskalation ausschliesslich fuer extrem hohe Last vorgesehen.
# Noch keine automatische Umschaltung (Schwellen / WAN-Test fehlen).

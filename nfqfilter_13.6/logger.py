#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from datetime import datetime

import config

DEBUG = config.DEBUG
# Bestehende individuelle config.py aus 13.3 bleibt auch ohne die zwei
# neuen Schluessel startfaehig; die Musterwerte gelten dann automatisch.
CONFIG_LOG_FILE = getattr(config, 'LOG_FILE', 'nfqfilter.log')
CONFIG_LOG_WHITELIST_FILE = getattr(config, 'LOG_WHITELIST_FILE', 'nfqfilter_whitelist.log')


def _resolve_log_path(value):
    if not value or not isinstance(value, (str, os.PathLike)):
        raise ValueError('Logpfad muss angegeben werden')
    path = os.fspath(value)
    if not os.path.isabs(path):
        path = os.path.join(config.DATA_DIR, path)
    return os.path.abspath(path)


LOG_FILE = _resolve_log_path(CONFIG_LOG_FILE)
WHITELIST_LOG_FILE = _resolve_log_path(CONFIG_LOG_WHITELIST_FILE)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
os.makedirs(os.path.dirname(WHITELIST_LOG_FILE), exist_ok=True)


def log(decision, reason, port, ip, ptr="-", match="-",
        src_port="-", tcp_flags="-", resolver="-", detail=None, score=None):

    if not DEBUG:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if score is not None:
        # Neue API-Entscheidung: PTR und kompakter Score in separaten Feldern.
        log_detail = (str(ptr) if ptr else "-") + "\t-%d-" % int(score)

    elif detail is not None:
        log_detail = str(detail)

    elif reason == "B":
        log_detail = str(ptr) + " (" + str(match) + ")"

    elif reason == "W":
        log_detail = "- (" + str(match) + ")"

    elif ptr != "-" and ptr:
        log_detail = str(ptr)

    else:
        log_detail = "-"

    line = (
        timestamp + "\t"
        + str(decision) + " " + str(reason) + "\t"
        + str(port) + "\t"
        + str(ip) + "\t"
        + str(src_port) + "\t"
        + str(tcp_flags) + "\t"
        + str(resolver) + "\t"
        + log_detail + "\n"
    )

    # Ausschliesslich ACPT W wird in das separate Whitelist-Log geleitet.
    # Identische Pfade erzeugen keine Duplikate: genau ein Schreibvorgang.
    log_path = (WHITELIST_LOG_FILE
                if decision == 'ACPT' and reason == 'W'
                else LOG_FILE)
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError as e:
        print("Fehler beim Schreiben von %s: %s" % (log_path, e))

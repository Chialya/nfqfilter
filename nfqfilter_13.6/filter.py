# NFQFILTER - Filterentscheidung

import ipaddress
import os


from config import IPV4_FILE, IPV6_FILE

BLOCKED_IPV4_NETS = []
BLOCKED_IPV6_NETS = []

IPV4_MTIME = None
IPV6_MTIME = None


def load_networks(filename):
    networks = []

    with open(filename, "r") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            networks.append(ipaddress.ip_network(line, strict=False))

    return networks


def reload_lists():
    global BLOCKED_IPV4_NETS
    global BLOCKED_IPV6_NETS
    global IPV4_MTIME
    global IPV6_MTIME

    ipv4_mtime = os.path.getmtime(IPV4_FILE)
    ipv6_mtime = os.path.getmtime(IPV6_FILE)

    if ipv4_mtime != IPV4_MTIME:
        BLOCKED_IPV4_NETS = load_networks(IPV4_FILE)
        IPV4_MTIME = ipv4_mtime

    if ipv6_mtime != IPV6_MTIME:
        BLOCKED_IPV6_NETS = load_networks(IPV6_FILE)
        IPV6_MTIME = ipv6_mtime


def should_drop(packet):
    if packet is None:
        return False

    reload_lists()

    src_ip = ipaddress.ip_address(packet["src_ip"])

    if packet["version"] == 4:
        if any(src_ip in net for net in BLOCKED_IPV4_NETS):
            return True

    if packet["version"] == 6:
        if any(src_ip in net for net in BLOCKED_IPV6_NETS):
            return True

    return False


#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct


def parse_packet(packet, length):

    data = bytes(packet[:length])

    if len(data) < 20:
        return None

    version = data[0] >> 4

    # --------------------------------------------------
    # IPv4
    # --------------------------------------------------

    if version == 4:

        ihl = (data[0] & 0x0F) * 4

        if len(data) < ihl + 20:
            return None

        protocol = data[9]

        if protocol != socket.IPPROTO_TCP:
            return None

        src_ip = socket.inet_ntoa(
            data[12:16]
        )

        tcp_offset = ihl

    # --------------------------------------------------
    # IPv6
    # --------------------------------------------------

    elif version == 6:

        if len(data) < 40:
            return None

        next_header = data[6]

        if next_header != socket.IPPROTO_TCP:
            return None

        src_ip = socket.inet_ntop(
            socket.AF_INET6,
            data[8:24]
        )

        tcp_offset = 40

    else:

        return None


    # --------------------------------------------------
    # TCP
    # --------------------------------------------------

    if len(data) < tcp_offset + 20:
        return None


    src_port = struct.unpack(
        "!H",
        data[tcp_offset:tcp_offset + 2]
    )[0]


    dst_port = struct.unpack(
        "!H",
        data[tcp_offset + 2:tcp_offset + 4]
    )[0]


    flags_byte = data[tcp_offset + 13]


    flags = []

    if flags_byte & 0x01:
        flags.append("FIN")

    if flags_byte & 0x02:
        flags.append("SYN")

    if flags_byte & 0x04:
        flags.append("RST")

    if flags_byte & 0x08:
        flags.append("PSH")

    if flags_byte & 0x10:
        flags.append("ACK")

    if flags_byte & 0x20:
        flags.append("URG")


    tcp_flags = ",".join(flags) if flags else "-"


    return {
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": tcp_flags,
    }
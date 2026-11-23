#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
import config


class IPWhitelist:

    def __init__(self):

        self.ipv4 = []
        self.ipv6 = []

        self._load_file(config.WHITELIST_IPV4_FILE, self.ipv4)
        self._load_file(config.WHITELIST_IPV6_FILE, self.ipv6)


    def _load_file(self, filename, target):

        try:

            with open(
                filename,
                "r",
                encoding="utf-8"
            ) as f:

                for line in f:

                    line = line.strip()

                    if not line:
                        continue

                    if line.startswith("#"):
                        continue

                    try:

                        target.append(
                            ipaddress.ip_network(
                                line,
                                strict=False
                            )
                        )

                    except ValueError as e:

                        print(
                            "Ungültiger Whitelist-Eintrag:",
                            line,
                            "->",
                            e
                        )


        except FileNotFoundError:

            print(
                "Whitelist-Datei nicht vorhanden:",
                filename
            )


    def get_match(self, ip):

        try:

            address = ipaddress.ip_address(
                ip
            )

        except ValueError:

            return None


        networks = (
            self.ipv4
            if address.version == 4
            else self.ipv6
        )


        for network in networks:

            if address in network:

                return str(network)


        return None


    def is_whitelisted(self, ip):

        return self.get_match(ip) is not None
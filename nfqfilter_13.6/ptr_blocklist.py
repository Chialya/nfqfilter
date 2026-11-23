#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import config
import re


class PTRBlocklist:

    def __init__(self):

        self.patterns = []

        self._load()


    def _load(self):

        filename = config.BLOCKED_PTR_FILE

        try:

            with open(
                filename,
                "r",
                encoding="utf-8"
            ) as f:

                for line in f:

                    line = line.strip().lower()

                    if not line:
                        continue

                    if line.startswith("#"):
                        continue


                    regex = re.escape(
                        line
                    )

                    regex = regex.replace(
                        r"\*",
                        ".+"
                    )


                    self.patterns.append(
                        (
                            line,
                            re.compile(
                                r"(^|\.)"
                                + regex
                                + r"$"
                            )
                        )
                    )


        except FileNotFoundError:

            print(
                "PTR-Blockliste nicht vorhanden:",
                filename
            )


    def get_match(self, hostname):

        hostname = hostname.rstrip(
            "."
        ).lower()


        for pattern, regex in self.patterns:

            if regex.search(hostname):

                return pattern


        return None


    def is_blocked(self, hostname):

        return self.get_match(hostname) is not None
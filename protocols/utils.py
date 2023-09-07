#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements an advanced reverse shell console.
#    Copyright (C) 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""
This package implements an advanced reverse shell
console (supports: TCP, UDP, IRC, HTTP and DNS).
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This package implements an advanced reverse shell
console (supports: TCP, UDP, IRC, HTTP and DNS).
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/ReverseShell"

copyright = """
ReverseShell  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["get_random_message", "get_random_domain"]

from string import ascii_letters, digits
from random import randint, choices

letters: bytes = ascii_letters.encode()
alphanum: bytes = ascii_letters.encode() + b"_" + digits.encode()


def get_random_message() -> bytes:
    """
    This function generates a random message.
    """

    msg = b""
    for a in range(randint(2, 8)):
        msg += bytes(choices(letters, k=randint(1, 10))) + b" "
    return msg[:-1]


def get_random_domain(wildcard: bool = False) -> bytes:
    """
    This function generates a random domain.
    """

    return (
        b"*"
        if wildcard
        else bytes(
            choices(alphanum, k=randint(1, 10))
        )  # wildcard syntax for subdomain
        + b"."
        + bytes(choices(alphanum, k=randint(1, 10)))
        + b"."
        + bytes(choices(letters, k=randint(2, 4)))
    )

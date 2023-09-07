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

__all__ = ["ApplicationBaseClass"]

from abc import ABC, abstractmethod
from typing import Union, Tuple


class ApplicationBaseClass(ABC):
    """
    The abstract method class to write a new protocol.
    """

    @abstractmethod
    def initialization_request(
        self, data: bytes
    ) -> Union[Tuple[bytes], bytes, None]:
        """
        This method returns initialization packets request
        without any data (command or output), when
        initialization is done this method should
        returns None.
        """

        pass

    @abstractmethod
    def initialization_response(
        self, data: bytes
    ) -> Union[Tuple[bytes], bytes, None]:
        """
        This method returns initialization packets response
        without any data (command or output), when
        initialization is done this method should
        returns None.
        """

        pass

    @abstractmethod
    def parse_request(self, data: bytes) -> bytes:
        """
        This method parses application protocols request.
        """

        pass

    @abstractmethod
    def parse_response(self, data: bytes) -> bytes:
        """
        This method parses application protocols response.
        """

        pass

    @abstractmethod
    def wrap_response(self, data: bytes, is_encrypted: bool = False) -> bytes:
        """
        This method writes data in application protocols response to
        hide ReverseShell payload in application protocols traffic.
        """

        pass

    @abstractmethod
    def wrap_request(self, data: bytes, is_encrypted: bool = False) -> bytes:
        """
        This method writes data in application protocols request to
        hide ReverseShell payload in application protocols traffic.
        """

        pass

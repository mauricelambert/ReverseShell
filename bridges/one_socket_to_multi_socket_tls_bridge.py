#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    TCP bridge for ReverseShell.
#    Copyright (C) 2023  ReverseShell

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
TCP bridge for ReverseShell.
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
TCP bridge for ReverseShell.
"""
__url__ = "https://github.com/mauricelambert/ReverseShell"

# __all__ = []

__license__ = "GPL-3.0 License"
__copyright__ = """
ReverseShell  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
copyright = __copyright__
license = __license__

print(copyright)

from ssl import SSLContext, PROTOCOL_TLS_CLIENT, PROTOCOL_TLS_SERVER
from socket import socket, create_server
from contextlib import suppress
from os.path import join

use_timeout = True

address_server = ("127.0.0.1", 1337)
address_destination = ("127.0.0.1", 1338)
context_client = SSLContext(PROTOCOL_TLS_CLIENT)
context_server = SSLContext(PROTOCOL_TLS_SERVER)

certificate = join("..", "server.crt")
context_client.load_verify_locations(certificate)
context_server.load_cert_chain(certificate, join("..", "server.key"))

while True:
    with suppress(Exception):
        socket_client = socket()
        socket_client.connect(address_destination)
        ssocket_client = context_client.wrap_socket(
            socket_client, server_hostname="localhost"
        )

        while True:
            socket_server = create_server(address_server)
            socket_server.listen(1)
            ssocket_server = context_server.wrap_socket(socket_server)
            connection, address = ssocket_server.accept()

            data = connection.recv(65535)
            connection.settimeout(
                0.5
            ) if use_timeout else connection.setblocking(False)
            while True:
                try:
                    data += connection.recv(65535)
                except (BlockingIOError, TimeoutError):
                    break
            connection.setblocking(True)

            ssocket_client.sendall(data)
            data = ssocket_client.recv(65535)

            connection.sendall(data)
            connection.close()
            ssocket_server.close()
            socket_server.close()

        socket_client.close()

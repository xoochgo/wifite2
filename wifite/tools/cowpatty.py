#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency_base import Dependency
from ..config import Configuration
from ..util.color import Color
from ..util.process import Process


class Cowpatty(Dependency):
    """ Wrapper for Cowpatty program. """
    _dependency_required = False
    _dependency_name = 'cowpatty'
    _dependency_url = 'https://tools.kali.org/wireless-attacks/cowpatty'

    def name(self) -> str:
        return self._dependency_name

    def exists(self) -> bool:
        return Process.exists(self._dependency_name)

    def install(self) -> None:
        # TODO: Implement actual installation logic or provide instructions
        print(f"To install {self._dependency_name}, please visit {self._dependency_url}")
        print("You may need to run: sudo apt install cowpatty")

    def print_install(self) -> None:
        # TODO: Provide more detailed installation instructions
        print(f"Please install {self._dependency_name} by visiting {self._dependency_url}")
        print("You may need to run a command like: sudo apt install cowpatty")

    @staticmethod
    def crack_handshake(handshake, show_command=False):
        # Crack john file
        command = [
            'cowpatty',
            '-f', Configuration.wordlist,
            '-r', handshake.capfile,
            '-s', handshake.essid
        ]
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        process = Process(command)
        stdout, stderr = process.get_output()

        key = None
        for line in stdout.split('\n'):
            if 'The PSK is "' in line:
                key = line.split('"', 1)[1][:-2]
                break

        return key

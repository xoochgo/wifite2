#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency_base import Dependency
from ..config import Configuration
from ..util.color import Color
from ..util.process import Process
from ..tools.hashcat import HcxPcapngTool

import os


class John(Dependency):
    """ Wrapper for John program. """
    _dependency_required = False
    _dependency_name = 'john'
    _dependency_url = 'https://www.openwall.com/john/'

    def name(self) -> str:
        return self._dependency_name

    def exists(self) -> bool:
        return Process.exists(self._dependency_name)

    def install(self) -> None:
        # TODO: Implement actual installation logic or provide instructions
        print(f"To install {self._dependency_name}, please visit {self._dependency_url}")
        print("You may need to run: sudo apt install john or build from source.")

    def print_install(self) -> None:
        # TODO: Provide more detailed installation instructions
        print(f"Please install {self._dependency_name} by visiting {self._dependency_url}")
        print("You can typically install John The Ripper using your package manager (e.g., sudo apt install john)")
        print("Alternatively, download and build from source from the official website.")

    @staticmethod
    def crack_handshake(handshake, show_command=False):
        john_file = HcxPcapngTool.generate_john_file(handshake, show_command=show_command)

        key = None
        # Use `john --list=formats` to find if OpenCL or CUDA is supported.
        formats_stdout = Process(['john', '--list=formats']).stdout()
        if 'wpapsk-opencl' in formats_stdout:
            john_format = 'wpapsk-opencl'
        elif 'wpapsk-cuda' in formats_stdout:
            john_format = 'wpapsk-cuda'
        else:
            john_format = 'wpapsk'

        # Crack john file
        command = ['john', f'--format={john_format}', f'--wordlist={Configuration.wordlist}', john_file]
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        process = Process(command)
        process.wait()

        # Run again with --show to consistently get the password
        command = ['john', '--show', john_file]
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        process = Process(command)
        stdout, stderr = process.get_output()

        # Parse password (regex doesn't work for some reason)
        if '0 password hashes cracked' in stdout:
            key = None
        else:
            for line in stdout.split('\n'):
                if handshake.capfile in line:
                    key = line.split(':')[1]
                    break

        if os.path.exists(john_file):
            os.remove(john_file)

        return key

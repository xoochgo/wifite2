#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency_base import Dependency
from ..util.process import Process


class Iw(Dependency):
    _dependency_required = True
    _dependency_name = 'iw'
    _dependency_url = 'apt install iw'

    def name(self) -> str:
        return self._dependency_name

    def exists(self) -> bool:
        return Process.exists(self._dependency_name)

    def install(self) -> None:
        # TODO: Implement actual installation logic or provide instructions
        print(f"To install {self._dependency_name}, please visit {self._dependency_url}")
        print("You may need to run: sudo apt install iw")

    def print_install(self) -> None:
        # TODO: Provide more detailed installation instructions
        print(f"Please install {self._dependency_name} by visiting {self._dependency_url}")
        print("You may need to run a command like: sudo apt install iw")

    @classmethod
    def mode(cls, iface, mode_name):
        from ..util.process import Process

        if mode_name == "monitor":
            return Process.call(f'iw {iface} set monitor control')
        else:
            return Process.call(f'iw {iface} type {mode_name}')

    @classmethod
    def get_interfaces(cls, mode=None):
        from ..util.process import Process
        import re

        ireg = re.compile(r"\s+Interface\s[a-zA-Z\d]+")
        mreg = re.compile(r"\s+type\s[a-zA-Z]+")

        interfaces = set()
        iface = ''

        (out, err) = Process.call('iw dev')
        if mode is None:
            for line in out.split('\n'):
                if ires := ireg.search(line):
                    interfaces.add(ires.group().split("Interface")[-1])
        else:
            for line in out.split('\n'):
                ires = ireg.search(line)
                if mres := mreg.search(line):
                    if mode == mres.group().split("type")[-1][1:]:
                        interfaces.add(iface)
                if ires:
                    iface = ires.group().split("Interface")[-1][1:]

        return list(interfaces)

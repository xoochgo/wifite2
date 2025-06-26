#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency_base import Dependency
from ..util.process import Process


class Hostapd(Dependency):
    _dependency_required = False
    _dependency_name = 'hostapd'
    _dependency_url = 'apt install hostapd'
    pid = None

    def name(self) -> str:
        return self._dependency_name

    def exists(self) -> bool:
        return Process.exists(self._dependency_name)

    def install(self) -> None:
        # TODO: Implement actual installation logic or provide instructions
        print(f"To install {self._dependency_name}, please visit {self._dependency_url}")
        print("You may need to run: sudo apt install hostapd")

    def print_install(self) -> None:
        # TODO: Provide more detailed installation instructions
        print(f"Please install {self._dependency_name} by visiting {self._dependency_url}")
        print("You may need to run a command like: sudo apt install hostapd")

    @classmethod
    def run(cls, iface, target):

        with open('/tmp/hostapd.conf', 'w') as fout:
            fout.write(f'interface={iface}' + '\n')
            fout.write(f'ssid={target.essid}' + '\n')
            fout.write(f'channel={target.channel}' + '\n')
            fout.write('driver=nl80211\n')
        # command = [
        #     'hostapd',
        #     '/tmp/hostapd.conf'
        # ]
        # process = Process(command)

        return None

    @classmethod
    def stop(cls):
        if hasattr(cls, 'pid') and cls.pid and cls.pid.poll() is None:
            cls.pid.interrupt()
        return None

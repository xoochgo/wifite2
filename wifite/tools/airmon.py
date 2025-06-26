#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import signal
import subprocess
import time

from .dependency_base import Dependency
from .ip import Ip
from .iw import Iw
from ..config import Configuration
from ..util.color import Color
from ..util.process import Process


class AirmonIface:
    def __init__(self, phy, interface, driver, chipset):
        self.phy = phy
        self.interface = interface
        self.driver = driver
        self.chipset = chipset

    # Max length of fields.
    # Used for printing a table of interfaces.
    INTERFACE_LEN = 12
    PHY_LEN = 6
    DRIVER_LEN = 20
    CHIPSET_LEN = 30

    def __str__(self):
        """ Colored string representation of interface """
        s = ''
        s += Color.s(f'{self.interface.ljust(self.INTERFACE_LEN)}')
        s += Color.s(f'{self.phy.ljust(self.PHY_LEN)}')
        s += Color.s(f'{self.driver.ljust(self.DRIVER_LEN)}')
        s += Color.s(f'{self.chipset.ljust(self.CHIPSET_LEN)}')
        return s

    @staticmethod
    def menu_header():
        """ Colored header row for interfaces """
        s = '    ' + 'Interface'.ljust(AirmonIface.INTERFACE_LEN)
        s += 'PHY'.ljust(AirmonIface.PHY_LEN)
        s += 'Driver'.ljust(AirmonIface.DRIVER_LEN)
        s += 'Chipset'.ljust(AirmonIface.CHIPSET_LEN)
        s += '\n'
        s += '-' * \
             (AirmonIface.INTERFACE_LEN + AirmonIface.PHY_LEN + AirmonIface.DRIVER_LEN + AirmonIface.CHIPSET_LEN + 3)
        return s


class Airmon(Dependency):
    """ Wrapper around the 'airmon-ng' program """
    _dependency_required = True
    _dependency_name = 'airmon-ng'
    _dependency_url = 'https://www.aircrack-ng.org/install.html'
    chipset_table = 'https://wikidevi.com/wiki/Wireless_adapters/Chipset_table'
    base_interface = None
    killed_network_manager = False
    use_ipiw = False
    isdeprecated = False

    def name(self) -> str:
        return self._dependency_name

    def exists(self) -> bool:
        return Process.exists(self._dependency_name)

    def install(self) -> None:
        # TODO: Implement actual installation logic or provide instructions
        print(f"To install {self._dependency_name}, please visit {self._dependency_url}")

    def print_install(self) -> None:
        # TODO: Provide more detailed installation instructions
        print(f"Please install {self._dependency_name} by visiting {self._dependency_url}")
        print("You may need to run a command like: sudo apt install aircrack-ng")

    # Drivers that need to be manually put into monitor mode
    BAD_DRIVERS = ['rtl8821au']
    DEPRECATED_DRIVERS = ['rtl8723cs']
    # see if_arp.h
    ARPHRD_ETHER = 1  # managed
    ARPHRD_IEEE80211_RADIOTAP = 803  # monitor

    def __init__(self):
        self.interfaces = None
        self.refresh()

    def refresh(self):
        """ Get airmon-recognized interfaces """
        self.interfaces = Airmon.get_interfaces()

    def print_menu(self):
        """ Prints menu """
        print((AirmonIface.menu_header()))
        for idx, interface in enumerate(self.interfaces, start=1):
            Color.pl(' {G}%d{W}. %s' % (idx, interface))

    def get(self, index):
        """ Gets interface at index (starts at 1) """
        if type(index) is str:
            index = int(index)
        return self.interfaces[index - 1]

    @staticmethod
    def get_interfaces():
        """Returns List of AirmonIface objects known by airmon-ng"""
        interfaces = []
        p2 = Process('airmon-ng')
        for line in p2.stdout().split('\n'):
            # [PHY ]IFACE DRIVER CHIPSET
            airmon_re = re.compile(r'^(?:([^\t]*)\t+)?([^\t]*)\t+([^\t]*)\t+([^\t]*)$')
            matches = airmon_re.match(line)
            if not matches:
                continue

            phy, interface, driver, chipset = matches.groups()
            if phy in ['PHY', 'Interface']:
                continue

            if len(interface.strip()) == 0:
                continue

            interfaces.append(AirmonIface(phy, interface, driver, chipset))

        return interfaces

    @staticmethod
    def get_iface_info(interface_name):
        """
        Get interface info (driver, chipset), based on interface name.
        Returns an AirmonIface if interface name is found by airmon-ng or None
        """
        return next((intf_adapter for intf_adapter in Airmon.get_interfaces() if intf_adapter.interface == interface_name), None)

    @staticmethod
    def start_bad_driver(interface, isdeprecated=False):
        """
        Manually put interface into monitor mode (no airmon-ng or vif).
        Fix for bad drivers like the rtl8812AU.
        """
        Ip.down(interface)
        if isdeprecated:
            Process(['iwconfig', interface, 'mode', 'monitor']).stdout()
        else:
            Iw.mode(interface, 'monitor')
        Ip.up(interface)

        # /sys/class/net/wlan0/type
        iface_type_path = os.path.join('/sys/class/net', interface, 'type')
        if os.path.exists(iface_type_path):
            with open(iface_type_path, 'r'):
                pass

        return interface

    @staticmethod
    def stop_bad_driver(interface):
        """
        Manually put interface into managed mode (no airmon-ng or vif).
        Fix for bad drivers like the rtl8812AU.
        """
        # Get driver info for ICNSS2 check
        iface_info = Airmon.get_iface_info(interface)
        if iface_info and iface_info.driver == 'icnss2':
            Color.p('{+} ICNSS2 driver detected for %s. Running "svc wifi disable"... ' % interface)
            # Run 'svc wifi disable'
            proc = Process(['svc', 'wifi', 'disable'])
            # proc.wait() # Wait for command to complete.
            # Alternatively, use Process.call for simpler cases if output isn't critical and we just need to run it
            # For now, let's assume we want to wait and check for errors, similar to other Process calls.
            stdout, stderr = proc.communicate() # communicate calls wait() internally
            if proc.poll() == 0:
                Color.pl('{G}success!{W}')
            else:
                Color.pl('{R}failed.{W}')
                if stdout: Color.pl('{O}STDOUT: %s{W}' % stdout.strip())
                if stderr: Color.pl('{R}STDERR: %s{W}' % stderr.strip())
                # Decide if we should proceed or raise an error. For now, let's proceed.

        Ip.down(interface)
        Iw.mode(interface, 'managed')
        Ip.up(interface)

        # /sys/class/net/wlan0/type
        iface_type_path = os.path.join('/sys/class/net', interface, 'type')
        if os.path.exists(iface_type_path):
            with open(iface_type_path, 'r'):
                pass

        return interface

    @classmethod
    def start(cls, interface):
        """
            Starts an interface (iface) in monitor mode
            Args:
                interface: Interface to start
            Returns:
                enabled_interface: Enabled interface
            Throws:
                Exception: If no interface is found
        """
        # Get interface name from input
        if type(interface) == AirmonIface:
            iface_name = interface.interface
            driver = interface.driver
        else:
            iface_name = interface
            driver = None # We'll try to fetch this if needed

        # Remember this as the 'base' interface.
        Airmon.base_interface = iface_name

        # Try ICNSS2-specific activation first
        if iface_name == 'wlan0':
            # Try to get driver info if not already available
            if driver is None:
                iface_obj = Airmon.get_iface_info(iface_name)
                if iface_obj:
                    driver = iface_obj.driver

            if driver == 'icnss2':
                Color.p('{+} Attempting {G}ICNSS2 monitor mode{W} on {C}%s{W}... ' % iface_name)
                con_mode_path = '/sys/module/wlan/parameters/con_mode'
                if os.path.exists(con_mode_path):
                    try:
                        # Ensure interface is down before changing mode
                        Ip.down(iface_name)
                        subprocess.run(['echo', '4', '>', con_mode_path], shell=True, check=True, capture_output=True)
                        # Bring interface up
                        Ip.up(iface_name)
                        # Verify it's in monitor mode
                        if Iw.is_monitor(iface_name):
                            Color.pl('{G}enabled (ICNSS2 specific)!{W}')
                            # TODO: Consider if we need to set cls.use_ipiw or other flags here
                            return iface_name
                        else:
                            Color.pl('{O}failed (ICNSS2 specific, could not verify monitor mode). Trying other methods...{W}')
                            # Attempt to revert if possible, or let subsequent methods handle it
                            # Process(['echo', '0', '>', con_mode_path], shell=True) # Optional: revert
                    except subprocess.CalledProcessError as e:
                        Color.pl('{R}failed (ICNSS2 specific command error: %s). Trying other methods...{W}' % e.stderr.decode().strip())
                    except Exception as e:
                        Color.pl('{R}failed (ICNSS2 specific error: %s). Trying other methods...{W}' % str(e))
                else:
                    Color.pl('{O}con_mode path not found for ICNSS2. Trying other methods...{W}')


        # If driver is deprecated then skip airmon-ng
        if driver not in Airmon.DEPRECATED_DRIVERS:
            # Try to enable using Airmon-ng first (for better compatibility)
            Color.p('{+} Enabling {G}monitor mode{W} on {C}%s{W}... ' % iface_name)
            airmon_output = Process(['airmon-ng', 'start', iface_name]).stdout()
            enabled_interface = Airmon._parse_airmon_start(airmon_output)
        else:
            enabled_interface = None

        # if it fails, try to use ip/iw
        if enabled_interface is None:
            Airmon.isdeprecated = driver in Airmon.DEPRECATED_DRIVERS
            enabled_interface = Airmon.start_bad_driver(iface_name, Airmon.isdeprecated)
        else:
            # If not, just set for us know how it went in monitor mode
            cls.use_ipiw = True

        if not Airmon.isdeprecated:
            # if that also fails, just give up
            if enabled_interface is None:
                Color.pl('{R}failed to enable monitor mode using standard methods.{W}')
                raise Exception('Failed to enable monitor mode')

            # Assert that there is an interface in monitor mode
            # interfaces = Iw.get_interfaces(mode='monitor') # This might be too early if mon iface has a new name
            # We rely on Iw.is_monitor(enabled_interface) or similar check later.
            if not Iw.is_monitor(enabled_interface):
                 # Airmon-ng sometimes creates a new interface (e.g. wlan0mon)
                 # We need to check if *any* monitor interface was created if enabled_interface itself is not in mon mode.
                 # However, our _parse_airmon_start should return the *new* monitor interface name.
                Color.pl('{R}interface %s not in monitor mode after airmon-ng/iw.{W}' % enabled_interface)
                raise Exception(f'Interface {enabled_interface} not in monitor mode after airmon-ng/iw')


        # No errors found; the device 'enabled_iface' was put into Mode:Monitor.
        Color.pl('{G}enabled{W}!')

        return enabled_interface

    @staticmethod
    def _parse_airmon_start(airmon_output):
        """Find the interface put into monitor mode (if any)"""
        # airmon-ng output: (mac80211 monitor mode vif enabled for [phy10]wlan0 on [phy10]wlan0mon)
        enabled_re = re.compile(r'.*\(mac80211 monitor mode (?:vif )?enabled (?:for [^ ]+ )?on (?:\[\w+])?(\w+)\)?.*')
        lines = airmon_output.split('\n')

        for index, line in enumerate(lines):
            if matches := enabled_re.match(line):
                return matches.group(1)
            if "monitor mode enabled" in line:
                return line.split()[-1]

        return None

    @classmethod
    def stop(cls, interface):
        Color.p('{!}{W} Disabling {O}monitor{W} mode on {R}%s{W}...\n' % interface)

        if cls.use_ipiw:
            enabled_interface = disabled_interface = Airmon.stop_bad_driver(interface)
        else:
            airmon_output = Process(['airmon-ng', 'stop', interface]).stdout()
            disabled_interface, enabled_interface = Airmon._parse_airmon_stop(airmon_output)

        if disabled_interface:
            Color.pl('{+}{W} Disabled monitor mode on {G}%s{W}' % disabled_interface)
        else:
            Color.pl('{!} {O}Could not disable {R}%s{W}' % interface)

        return disabled_interface, enabled_interface

    @staticmethod
    def _parse_airmon_stop(airmon_output):
        """Find the interface taken out of into monitor mode (if any)"""
        # airmon-ng 1.2rc2 output: (mac80211 monitor mode vif enabled for [phy10]wlan0 on [phy10]wlan0mon)
        disabled_re = re.compile(r'\s*\(mac80211 monitor mode (?:vif )?disabled for (?:\[\w+])?(\w+)\)\s*')

        # airmon-ng 1.2rc1 output: wlan0mon (removed)
        removed_re = re.compile(r'([a-zA-Z\d]+).*\(removed\)')

        # Enabled interface: (mac80211 station mode vif enabled on [phy4]wlan0)
        enabled_re = re.compile(r'\s*\(mac80211 station mode (?:vif )?enabled on (?:\[\w+])?(\w+)\)\s*')

        disabled_interface = None
        enabled_interface = None
        for line in airmon_output.split('\n'):
            if matches := disabled_re.match(line):
                disabled_interface = matches.group(1)

            if matches := removed_re.match(line):
                disabled_interface = matches.group(1)

            if matches := enabled_re.match(line):
                enabled_interface = matches.group(1)

        return disabled_interface, enabled_interface

    @staticmethod
    def ask():
        """
        Asks user to define which wireless interface to use.
        Does not ask if:
            1. There is already an interface in monitor mode, or
            2. There is only one wireless interface (automatically selected).
        Puts selected device into Monitor Mode.
        """
        Airmon.terminate_conflicting_processes()

        Color.p('\n{+} Looking for {C}wireless interfaces{W}...')
        monitor_interfaces = Iw.get_interfaces(mode='monitor')
        if len(monitor_interfaces) == 1:
            # Assume we're using the device already in monitor mode
            interface = monitor_interfaces[0]
            Color.clear_entire_line()
            Color.pl('{+} Using {G}%s{W} already in monitor mode' % interface)
            Airmon.base_interface = None
            return interface

        Color.clear_entire_line()
        Color.p('{+} Checking {C}airmon-ng{W}...')

        a = Airmon()
        if len(a.interfaces) == 0:
            # No interfaces found
            Color.pl('\n{!} {O}airmon-ng did not find {R}any{O} wireless interfaces')
            Color.pl('{!} {O}Make sure your wireless device is connected')
            Color.pl('{!} {O}See {C}https://www.aircrack-ng.org/doku.php?id=airmon-ng{O} for more info{W}')
            raise Exception('airmon-ng did not find any wireless interfaces')

        Color.clear_entire_line()
        a.print_menu()

        Color.pl('')

        if len(a.interfaces) == 1:
            # Only one interface, assume this is the one to use
            choice = 1
        else:
            # Multiple interfaces found
            Color.p('{+} Select wireless interface ({G}1-%d{W}): ' % len(a.interfaces))
            choice = input()

        selected = a.get(choice)

        if a.get(choice).interface in monitor_interfaces:
            Color.pl('{+} {G}%s{W} is already in monitor mode' % selected.interface)
        else:
            selected.interface = Airmon.start(selected)

        return selected.interface

    @staticmethod
    def terminate_conflicting_processes():
        """ Deletes conflicting processes reported by airmon-ng """
        airmon_output = Process(['airmon-ng', 'check']).stdout()

        # Checking for systemd, otherwise assume openrc

        if os.path.exists('/usr/lib/systemd/systemd'):
            init_system = 'systemd'
        else:
            init_system = 'openrc'
        # TODO: add support for other unorthodox init systems (maybe?)

        # Conflicting process IDs and names
        pid_pnames = []

        # 2272    dhclient
        # 2293    NetworkManager
        pid_pname_re = re.compile(r'^\s*(\d+)\s*([a-zA-Z\d_\-]+)\s*$')
        for line in airmon_output.split('\n'):
            if match := pid_pname_re.match(line):
                pid_pnames.append((match.group(1), match.group(2)))

        if not pid_pnames:
            return

        if not Configuration.kill_conflicting_processes:
            # Don't kill processes, warn user
            names_and_pids = ', '.join([f'{pname} ({pid})' for pid, pname in pid_pnames])
            Color.pl('{!} {O}Conflicting processes: %s' % names_and_pids)
            Color.pl('{!} {O}If you have problems: {R}kill -9 PID{O} or re-run wifite with {R}--kill{O}{W}')
            return

        Color.pl('{!} {O}Killing {R}%d {O}conflicting processes' % len(pid_pnames))
        for pid, pname in pid_pnames:
            if pname == 'NetworkManager' and Process.exists('systemctl'):
                Process(['systemctl', 'stop', 'NetworkManager']).stdout()
            elif pname == 'network-manager' and Process.exists('service'):
                Process(['service', 'network-manager', 'stop']).stdout()
            elif pname == 'avahi-daemon' and Process.exists('service'):
                Process(['service', 'avahi-daemon', 'stop']).stdout()
            else:
                os.kill(int(pid), signal.SIGKILL)

    @staticmethod
    def put_interface_up(interface):
        Color.p('{!}{W} Putting interface {R}%s{W} {G}up{W}...\n' % interface)
        Ip.up(interface)
        Color.pl('{+}{W} Done !')

    @staticmethod
    def start_network_manager():
        Color.p('{!} {O}start {R}NetworkManager{O}...')

        if Process.exists('service'):
            cmd = 'service networkmanager start'
            proc = Process(cmd)
            (out, err) = proc.get_output()
            if proc.poll() != 0:
                Color.pl(' {R}Error executing {O}%s{W}' % cmd)
                if out is not None and out.strip() != '':
                    Color.pl('{!} {O}STDOUT> %s{W}' % out)
                if err is not None and err.strip() != '':
                    Color.pl('{!} {O}STDERR> %s{W}' % err)
            else:
                Color.pl(' {G}Done{W} ({C}%s{W})' % cmd)
                return

        if Process.exists('systemctl'):
            cmd = 'systemctl start NetworkManager'
            proc = Process(cmd)
            (out, err) = proc.get_output()
            if proc.poll() != 0:
                Color.pl(' {R}Error executing {O}%s{W}' % cmd)
                if out is not None and out.strip() != '':
                    Color.pl('{!} {O}STDOUT> %s{W}' % out)
                if err is not None and err.strip() != '':
                    Color.pl('{!} {O}STDERR> %s{W}' % err)
            else:
                Color.pl(' {G}done{W} ({C}%s{W})' % cmd)
                return
        else:
            Color.pl(' {R}Cannot start NetworkManager: {O}systemctl{R} or {O}service{R} not found{W}')


if __name__ == '__main__':
    stdout = '''
Found 2 processes that could cause trouble.
If airodump-ng, aireplay-ng or airtun-ng stops working after
a short period of time, you may want to run 'airmon-ng check kill'

  PID Name
 5563 avahi-daemon
 5564 avahi-daemon

PHY	Interface	Driver		Chipset

phy0	wlx00c0ca4ecae0	rtl8187		Realtek Semiconductor Corp. RTL8187
Interface 15mon is too long for linux so it will be renamed to the old style (wlan#) name.

                (mac80211 monitor mode vif enabled on [phy0]wlan0mon
                (mac80211 station mode vif disabled for [phy0]wlx00c0ca4ecae0)
    '''
    start_iface = Airmon._parse_airmon_start(stdout)
    print(('start_iface from stdout:', start_iface))

    Configuration.initialize(False)
    iface = Airmon.ask()
    (disabled_iface, enabled_iface) = Airmon.stop(iface)
    print(('Disabled:', disabled_iface))
    print(('Enabled:', enabled_iface))

    print(f""""reaver" exists: {Process.exists('reaver')}""")

    # Test on never-ending process
    p = Process('yes')
    print('Running yes...')
    time.sleep(1)
    print('yes should stop now')
    p.interrupt()

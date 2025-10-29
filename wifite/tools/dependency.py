#!/usr/bin/env python
# -*- coding: utf-8 -*-

#from wifite.tools.aircrack import Aircrack
#from wifite.tools.bully import Bully
#from wifite.tools.hashcat import Hashcat, HcxDumpTool, HcxPcapngTool
#from wifite.tools.ip import Ip
#from wifite.tools.iw import Iw
#from wifite.tools.macchanger import Macchanger
#from wifite.tools.reaver import Reaver
#from wifite.tools.tshark import Tshark


class Dependency(object):
    dependency_name = None
    dependency_required = None
    dependency_url = None
    required_attr_names = ['dependency_name', 'dependency_url', 'dependency_required']

    # https://stackoverflow.com/a/49024227
    def __init_subclass__(cls):
        for attr_name in cls.required_attr_names:
            if attr_name not in cls.__dict__:
                raise NotImplementedError(f'Attribute "{attr_name}" has not been overridden in class "{cls.__name__}"')

    @classmethod
    def exists(cls):
        from ..util.process import Process
        return Process.exists(cls.dependency_name)

    @classmethod
    def run_dependency_check(cls):
        from ..util.color import Color

        from .aircrack import Aircrack
        from .ip import Ip
        from .iw import Iw
        from .bully import Bully
        from .reaver import Reaver
        from .tshark import Tshark
        from .macchanger import Macchanger
        from .hashcat import Hashcat, HcxDumpTool, HcxPcapngTool

        apps = [
            # Aircrack
            Aircrack,  # Airodump, Airmon, Aireplay,
            # wireless/net tools
            Iw, Ip,
            # WPS
            Reaver, Bully,
            # Cracking/handshakes
            Tshark,
            # Hashcat
            Hashcat, HcxDumpTool, HcxPcapngTool,
            # Misc
            Macchanger
        ]

        missing_required = any(app.fails_dependency_check() for app in apps)

        if missing_required:
            Color.pl('{!} {O}At least 1 Required app is missing. Wifite needs Required apps to run{W}')
            import sys
            sys.exit(-1)

        # Check WPA3 tools (optional, but warn if missing)
        cls._check_wpa3_tools()

        # Check Evil Twin tools (optional, but warn if missing)
        cls._check_eviltwin_tools()

        # Check wpa-sec upload tools (optional, but warn if missing)
        cls._check_wpasec_tools()

    @classmethod
    def _check_wpa3_tools(cls):
        """Check for WPA3-specific tools and warn if missing."""
        from ..util.color import Color
        from ..util.wpa3_tools import WPA3ToolChecker

        if not WPA3ToolChecker.can_attack_wpa3():
            missing = WPA3ToolChecker.get_missing_tools()
            if missing:
                Color.pl('\n{!} {O}Warning: WPA3 attacks will not be available{W}')
                Color.pl('{!} {O}Missing WPA3 tools: {R}%s{W}' % ', '.join(missing))
                Color.pl('{!} {O}Install with: {C}apt install hcxdumptool hcxtools{W}')
                Color.pl('')

    @classmethod
    def _check_eviltwin_tools(cls):
        """Check for Evil Twin-specific tools and warn if missing."""
        from ..util.color import Color
        from ..config import Configuration

        # Only check if Evil Twin is enabled
        if not Configuration.use_eviltwin:
            return

        missing_tools = []
        install_commands = []

        # Check for hostapd
        from ..util.process import Process
        if not Process.exists('hostapd'):
            missing_tools.append('hostapd')
            install_commands.append('apt install hostapd')

        # Check for dnsmasq
        if not Process.exists('dnsmasq'):
            missing_tools.append('dnsmasq')
            install_commands.append('apt install dnsmasq')

        # Check for wpa_supplicant (for credential validation)
        if not Process.exists('wpa_supplicant'):
            missing_tools.append('wpa_supplicant')
            install_commands.append('apt install wpasupplicant')

        if missing_tools:
            Color.pl('\n{!} {R}Error: Evil Twin attack requires additional tools{W}')
            Color.pl('{!} {O}Missing tools: {R}%s{W}' % ', '.join(missing_tools))
            Color.pl('{!} {O}Install with:{W}')
            for cmd in install_commands:
                Color.pl('{!}   {C}%s{W}' % cmd)
            Color.pl('')

            import sys
            sys.exit(-1)

    @classmethod
    def _check_wpasec_tools(cls):
        """Check for wpa-sec upload tools and warn if missing."""
        from ..util.color import Color
        from .wlancap2wpasec import Wlancap2wpasec

        if not Wlancap2wpasec.exists():
            Color.pl('\n{!} {O}Warning: wpa-sec upload functionality will not be available{W}')
            Color.pl('{!} {O}Missing tool: {R}wlancap2wpasec{W}')
            Color.pl('{!} {O}Install with: {C}apt install hcxtools{W}')
            Color.pl('{!} {O}wpa-sec allows uploading captures to wpa-sec.stanev.org for online cracking{W}')
            Color.pl('')

    @classmethod
    def fails_dependency_check(cls):
        from ..util.color import Color
        from ..util.process import Process

        if Process.exists(cls.dependency_name):
            return False

        if cls.dependency_required:
            Color.p('{!} {O}Error: Required app {R}%s{O} was not found' % cls.dependency_name)
            Color.pl('. {W}install @ {C}%s{W}' % cls.dependency_url)
            return True

        else:
            Color.p('{!} {O}Warning: Recommended app {R}%s{O} was not found' % cls.dependency_name)
            Color.pl('. {W}install @ {C}%s{W}' % cls.dependency_url)
            return False

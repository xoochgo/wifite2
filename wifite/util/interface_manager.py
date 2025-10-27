#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Network interface management for Evil Twin attacks.

Provides high-level interface management including AP mode detection,
configuration, IP assignment, and cleanup.
"""

import os
import re
from typing import Optional, List, Tuple

from ..tools.iw import Iw
from ..tools.ip import Ip
from ..tools.airmon import Airmon
from ..util.process import Process
from ..util.color import Color
from ..util.logger import log_info, log_error, log_warning, log_debug


class InterfaceCapabilities:
    """Represents wireless interface capabilities."""
    
    def __init__(self, interface):
        self.interface = interface
        self.supports_ap_mode = False
        self.supports_monitor_mode = False
        self.supports_managed_mode = False
        self.phy = None
        self.driver = None
        self.chipset = None
        self.mac_address = None
        
        self._detect_capabilities()
    
    def _detect_capabilities(self):
        """Detect interface capabilities using iw."""
        try:
            # Get PHY info
            output = Process(['iw', self.interface, 'info']).stdout()
            
            # Extract PHY
            if match := re.search(r'wiphy\s+(\d+)', output):
                self.phy = f'phy{match.group(1)}'
            
            # Get MAC address
            try:
                self.mac_address = Ip.get_mac(self.interface)
            except Exception as e:
                log_debug('InterfaceManager', f'Failed to get MAC for {self.interface}: {e}')
            
            # Get driver and chipset info from airmon
            iface_info = Airmon.get_iface_info(self.interface)
            if iface_info:
                self.driver = iface_info.driver
                self.chipset = iface_info.chipset
            
            # Check supported modes using iw phy
            if self.phy:
                phy_output = Process(['iw', 'phy', self.phy, 'info']).stdout()
                
                # Look for supported interface modes
                in_modes_section = False
                for line in phy_output.split('\n'):
                    if 'Supported interface modes:' in line:
                        in_modes_section = True
                        continue
                    
                    if in_modes_section:
                        if line.strip() and not line.startswith('\t'):
                            # End of modes section
                            break
                        
                        if '* AP' in line or '* master' in line:
                            self.supports_ap_mode = True
                        if '* monitor' in line:
                            self.supports_monitor_mode = True
                        if '* managed' in line:
                            self.supports_managed_mode = True
            
            log_debug('InterfaceManager', 
                     f'{self.interface}: AP={self.supports_ap_mode}, '
                     f'Monitor={self.supports_monitor_mode}, '
                     f'Managed={self.supports_managed_mode}')
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to detect capabilities for {self.interface}: {e}', e)
    
    def __str__(self):
        modes = []
        if self.supports_ap_mode:
            modes.append('AP')
        if self.supports_monitor_mode:
            modes.append('Monitor')
        if self.supports_managed_mode:
            modes.append('Managed')
        
        return f'{self.interface} ({", ".join(modes)})'


class InterfaceManager:
    """
    Manages network interfaces for Evil Twin attacks.
    
    Handles interface mode changes, IP configuration, and cleanup.
    """
    
    def __init__(self):
        self.managed_interfaces = {}  # interface -> original_state
        self.assigned_ips = {}  # interface -> ip_address
    
    @staticmethod
    def get_wireless_interfaces() -> List[str]:
        """
        Get list of all wireless interfaces.
        
        Returns:
            List of interface names
        """
        try:
            interfaces = []
            
            # Use iw to get all wireless interfaces
            output = Process(['iw', 'dev']).stdout()
            
            for line in output.split('\n'):
                if 'Interface' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        interface = parts[1]
                        interfaces.append(interface)
            
            log_info('InterfaceManager', f'Found {len(interfaces)} wireless interfaces')
            return interfaces
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to get wireless interfaces: {e}', e)
            return []
    
    @staticmethod
    def get_ap_capable_interfaces() -> List[InterfaceCapabilities]:
        """
        Get list of interfaces that support AP mode.
        
        Returns:
            List of InterfaceCapabilities objects for AP-capable interfaces
        """
        ap_interfaces = []
        
        for interface in InterfaceManager.get_wireless_interfaces():
            caps = InterfaceCapabilities(interface)
            if caps.supports_ap_mode:
                ap_interfaces.append(caps)
        
        log_info('InterfaceManager', f'Found {len(ap_interfaces)} AP-capable interfaces')
        return ap_interfaces
    
    @staticmethod
    def check_ap_mode_support(interface) -> bool:
        """
        Check if an interface supports AP mode.
        
        Args:
            interface: Interface name to check
            
        Returns:
            True if AP mode is supported, False otherwise
        """
        caps = InterfaceCapabilities(interface)
        return caps.supports_ap_mode
    
    def get_interface_state(self, interface) -> dict:
        """
        Get current state of an interface.
        
        Args:
            interface: Interface name
            
        Returns:
            Dictionary with interface state information
        """
        try:
            state = {
                'interface': interface,
                'up': False,
                'mode': 'unknown',
                'ip_addresses': [],
                'mac': None
            }
            
            # Check if interface is up
            output = Process(['ip', 'link', 'show', interface]).stdout()
            state['up'] = 'UP' in output and 'state UP' in output
            
            # Get MAC address
            try:
                state['mac'] = Ip.get_mac(interface)
            except:
                pass
            
            # Get mode using iw
            try:
                iw_output = Process(['iw', interface, 'info']).stdout()
                if 'type AP' in iw_output or 'type master' in iw_output:
                    state['mode'] = 'AP'
                elif 'type monitor' in iw_output:
                    state['mode'] = 'monitor'
                elif 'type managed' in iw_output:
                    state['mode'] = 'managed'
            except:
                pass
            
            # Get IP addresses
            try:
                ip_output = Process(['ip', 'addr', 'show', interface]).stdout()
                for line in ip_output.split('\n'):
                    if 'inet ' in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            state['ip_addresses'].append(parts[1])
            except:
                pass
            
            return state
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to get state for {interface}: {e}', e)
            return {'interface': interface, 'error': str(e)}
    
    def configure_for_ap(self, interface, ip_address='192.168.100.1/24') -> bool:
        """
        Configure interface for AP mode.
        
        Args:
            interface: Interface to configure
            ip_address: IP address to assign (CIDR notation)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Save original state
            if interface not in self.managed_interfaces:
                self.managed_interfaces[interface] = self.get_interface_state(interface)
                log_debug('InterfaceManager', f'Saved state for {interface}')
            
            # Bring interface down
            log_debug('InterfaceManager', f'Bringing {interface} down')
            Ip.down(interface)
            
            # Set to AP mode
            log_debug('InterfaceManager', f'Setting {interface} to AP mode')
            Process(['iw', interface, 'set', 'type', '__ap']).wait()
            
            # Bring interface up
            log_debug('InterfaceManager', f'Bringing {interface} up')
            Ip.up(interface)
            
            # Flush existing IP addresses
            log_debug('InterfaceManager', f'Flushing IP addresses on {interface}')
            Process(['ip', 'addr', 'flush', 'dev', interface]).wait()
            
            # Assign IP address
            log_debug('InterfaceManager', f'Assigning {ip_address} to {interface}')
            Process(['ip', 'addr', 'add', ip_address, 'dev', interface]).wait()
            
            self.assigned_ips[interface] = ip_address
            
            log_info('InterfaceManager', f'Configured {interface} for AP mode with IP {ip_address}')
            return True
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to configure {interface} for AP: {e}', e)
            return False
    
    def restore_interface(self, interface) -> bool:
        """
        Restore interface to its original state.
        
        Args:
            interface: Interface to restore
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if interface not in self.managed_interfaces:
                log_warning('InterfaceManager', f'No saved state for {interface}')
                return False
            
            original_state = self.managed_interfaces[interface]
            
            log_debug('InterfaceManager', f'Restoring {interface} to original state')
            
            # Bring interface down
            Ip.down(interface)
            
            # Flush IP addresses
            Process(['ip', 'addr', 'flush', 'dev', interface]).wait()
            
            # Restore mode (default to managed)
            mode = original_state.get('mode', 'managed')
            if mode == 'AP':
                mode = 'managed'  # Don't restore to AP mode
            
            log_debug('InterfaceManager', f'Setting {interface} to {mode} mode')
            if mode == 'monitor':
                Process(['iw', interface, 'set', 'monitor', 'control']).wait()
            else:
                Process(['iw', interface, 'set', 'type', mode]).wait()
            
            # Bring interface up if it was originally up
            if original_state.get('up', False):
                Ip.up(interface)
            
            # Clean up tracking
            del self.managed_interfaces[interface]
            if interface in self.assigned_ips:
                del self.assigned_ips[interface]
            
            log_info('InterfaceManager', f'Restored {interface} to original state')
            return True
            
        except Exception as e:
            log_error('InterfaceManager', f'Failed to restore {interface}: {e}', e)
            return False
    
    def cleanup_all(self):
        """Restore all managed interfaces."""
        interfaces = list(self.managed_interfaces.keys())
        
        for interface in interfaces:
            try:
                self.restore_interface(interface)
            except Exception as e:
                log_error('InterfaceManager', f'Error restoring {interface}: {e}', e)
        
        log_info('InterfaceManager', 'Cleanup complete')
    
    @staticmethod
    def select_ap_interface(preferred=None) -> Optional[str]:
        """
        Select an interface for AP mode.
        
        Args:
            preferred: Preferred interface name (optional)
            
        Returns:
            Selected interface name or None
        """
        ap_interfaces = InterfaceManager.get_ap_capable_interfaces()
        
        if not ap_interfaces:
            Color.pl('{!} {R}No AP-capable interfaces found{W}')
            Color.pl('{!} {O}Your wireless adapter may not support AP mode{W}')
            return None
        
        # If preferred interface is specified and available, use it
        if preferred:
            for caps in ap_interfaces:
                if caps.interface == preferred:
                    log_info('InterfaceManager', f'Using preferred interface: {preferred}')
                    return preferred
            
            Color.pl('{!} {O}Preferred interface {R}%s{O} not found or not AP-capable{W}' % preferred)
        
        # If only one interface, use it
        if len(ap_interfaces) == 1:
            interface = ap_interfaces[0].interface
            Color.pl('{+} Using {G}%s{W} for AP mode' % interface)
            return interface
        
        # Multiple interfaces, ask user
        Color.pl('\n{+} {C}AP-capable interfaces:{W}')
        for idx, caps in enumerate(ap_interfaces, start=1):
            Color.pl('  {G}%d{W}. %s' % (idx, caps))
        
        Color.p('\n{+} Select interface for AP mode ({G}1-%d{W}): ' % len(ap_interfaces))
        try:
            choice = int(input())
            if 1 <= choice <= len(ap_interfaces):
                interface = ap_interfaces[choice - 1].interface
                log_info('InterfaceManager', f'User selected interface: {interface}')
                return interface
            else:
                Color.pl('{!} {R}Invalid selection{W}')
                return None
        except (ValueError, KeyboardInterrupt, EOFError):
            Color.pl('{!} {R}Selection cancelled{W}')
            return None
    
    def __del__(self):
        """Cleanup on deletion."""
        try:
            self.cleanup_all()
        except:
            pass

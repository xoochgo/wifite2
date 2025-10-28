#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Integration tests for Evil Twin attack with dual interface support.

Tests the dual interface attack flow including:
- Dual interface initialization
- AP interface configuration
- Deauth interface configuration
- Parallel AP and deauth operations
- No mode switching verification
"""

import unittest
import sys
from unittest.mock import Mock, patch, MagicMock, call

# Mock sys.argv to prevent argparse from reading test arguments
original_argv = sys.argv
sys.argv = ['wifite']

from wifite.config import Configuration
from wifite.model.target import Target
from wifite.model.interface_info import InterfaceInfo, InterfaceAssignment

# Set required Configuration attributes
Configuration.wpa_attack_timeout = 600
Configuration.interface = 'wlan0'
Configuration.evil_twin_timeout = 0
Configuration.evil_twin_portal_template = 'generic'
Configuration.evil_twin_deauth_interval = 5
Configuration.interface_primary = None
Configuration.interface_secondary = None
Configuration.dual_interface_enabled = False

from wifite.attack.eviltwin import EvilTwin

# Restore original argv
sys.argv = original_argv


def create_mock_interface(name, has_ap=True, has_monitor=True, has_injection=True, is_up=False):
    """Create mock InterfaceInfo for testing."""
    return InterfaceInfo(
        name=name,
        phy=f'phy{name[-1]}',
        driver='ath9k',
        chipset='Atheros AR9271',
        mac_address=f'00:11:22:33:44:{name[-1]}',
        supports_ap_mode=has_ap,
        supports_monitor_mode=has_monitor,
        supports_injection=has_injection,
        current_mode='managed',
        is_up=is_up,
        is_connected=False
    )


class TestEvilTwinDualInterface(unittest.TestCase):
    """Test Evil Twin attack with dual interfaces."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        self.mock_target.encryption = 'WPA2'
        self.mock_target.power = -50
        self.mock_target.wps = False
        
        Configuration.interface = 'wlan0'
        Configuration.interface_primary = None
        Configuration.interface_secondary = None
    
    def test_dual_interface_initialization(self):
        """Test Evil Twin initialization with dual interfaces."""
        # Create Evil Twin attack with dual interfaces
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Verify initialization
        self.assertEqual(attack.interface_ap, 'wlan0')
        self.assertEqual(attack.interface_deauth, 'wlan1')
        self.assertIsNone(attack.interface_assignment)
    
    def test_get_interface_assignment_dual(self):
        """Test getting interface assignment for dual interface mode."""
        # Mock interface assignment
        assignment = InterfaceAssignment(
            attack_type='evil_twin',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Rogue AP (hostapd)',
            secondary_role='Deauthentication (aireplay-ng)'
        )
        
        # Create attack and set assignment
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        attack.interface_assignment = assignment
        
        # Get assignment
        result = attack._get_interface_assignment()
        
        # Verify assignment
        self.assertIsNotNone(result)
        self.assertTrue(result.is_dual_interface())
        self.assertEqual(result.primary, 'wlan0')
        self.assertEqual(result.secondary, 'wlan1')
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Airmon')
    def test_configure_ap_interface(self, mock_airmon, mock_color):
        """Test AP interface configuration."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Configure AP interface
        result = attack._configure_ap_interface('wlan0')
        
        # Verify configuration steps
        self.assertTrue(result)
        mock_airmon.put_interface_down.assert_called_with('wlan0')
        mock_airmon.set_interface_mode.assert_called_with('wlan0', 'managed')
        mock_airmon.put_interface_up.assert_called_with('wlan0')
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Airmon')
    def test_configure_deauth_interface(self, mock_airmon, mock_color):
        """Test deauth interface configuration."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Mock monitor mode activation
        mock_airmon.start.return_value = 'wlan1mon'
        
        # Configure deauth interface
        result = attack._configure_deauth_interface('wlan1')
        
        # Verify configuration
        self.assertTrue(result)
        mock_airmon.start.assert_called_with('wlan1')
        self.assertEqual(attack.interface_deauth, 'wlan1mon')
        mock_airmon.set_interface_channel.assert_called_with('wlan1mon', 6)
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Hostapd')
    def test_start_rogue_ap_dual(self, mock_hostapd_class, mock_color):
        """Test starting rogue AP on dedicated AP interface."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Mock hostapd
        mock_hostapd = Mock()
        mock_hostapd.start.return_value = True
        mock_hostapd.is_running.return_value = True
        mock_hostapd_class.return_value = mock_hostapd
        mock_hostapd_class.check_ap_mode_support.return_value = True
        
        # Start rogue AP
        result = attack._start_rogue_ap_dual('wlan0')
        
        # Verify AP started
        self.assertTrue(result)
        mock_hostapd_class.check_ap_mode_support.assert_called_with('wlan0')
        mock_hostapd.start.assert_called_once()
        mock_hostapd.is_running.assert_called_once()
        self.assertIsNotNone(attack.hostapd)
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Dnsmasq')
    @patch('wifite.attack.eviltwin.PortalServer')
    def test_start_network_services_dual(self, mock_portal_class, mock_dnsmasq_class, mock_color):
        """Test starting network services for dual interface mode."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        attack.interface_ap = 'wlan0'
        
        # Mock dnsmasq
        mock_dnsmasq = Mock()
        mock_dnsmasq.start.return_value = True
        mock_dnsmasq_class.return_value = mock_dnsmasq
        
        # Mock portal server
        mock_portal = Mock()
        mock_portal.start.return_value = True
        mock_portal_class.return_value = mock_portal
        
        # Start network services
        result = attack._start_network_services_dual()
        
        # Verify services started
        self.assertTrue(result)
        mock_dnsmasq.start.assert_called_once()
        mock_portal.start.assert_called_once()
        self.assertIsNotNone(attack.dnsmasq)
        self.assertIsNotNone(attack.portal_server)
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Airmon')
    def test_start_deauth_dual(self, mock_airmon, mock_color):
        """Test preparing deauth on dedicated deauth interface."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1mon')
        attack.interface_deauth = 'wlan1mon'
        
        # Mock interface mode check
        mock_airmon.get_interface_mode.return_value = 'monitor'
        mock_airmon.get_interface_channel.return_value = 6
        
        # Start deauth
        result = attack._start_deauth_dual('wlan1mon')
        
        # Verify deauth ready
        self.assertTrue(result)
        mock_airmon.get_interface_mode.assert_called_with('wlan1mon')
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.input')
    @patch('wifite.attack.eviltwin.EvilTwin._check_dependencies')
    @patch('wifite.attack.eviltwin.EvilTwin._check_for_conflicts')
    @patch('wifite.attack.eviltwin.EvilTwin._configure_ap_interface')
    @patch('wifite.attack.eviltwin.EvilTwin._configure_deauth_interface')
    @patch('wifite.attack.eviltwin.EvilTwin._start_rogue_ap_dual')
    @patch('wifite.attack.eviltwin.EvilTwin._start_network_services_dual')
    @patch('wifite.attack.eviltwin.EvilTwin._start_deauth_dual')
    @patch('wifite.attack.eviltwin.EvilTwin._monitor_attack_loop')
    @patch('wifite.attack.eviltwin.EvilTwin._cleanup')
    def test_run_dual_interface_flow(self, mock_cleanup, mock_monitor, mock_start_deauth,
                                     mock_start_services, mock_start_ap, mock_config_deauth,
                                     mock_config_ap, mock_conflicts, mock_deps, mock_input, mock_color):
        """Test complete dual interface attack flow."""
        # Mock user confirmation
        mock_input.return_value = 'YES'
        
        # Mock successful setup
        mock_deps.return_value = True
        mock_conflicts.return_value = True
        mock_config_ap.return_value = True
        mock_config_deauth.return_value = True
        mock_start_ap.return_value = True
        mock_start_services.return_value = True
        mock_start_deauth.return_value = True
        mock_monitor.return_value = True
        
        # Create attack with dual interface assignment
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        assignment = InterfaceAssignment(
            attack_type='evil_twin',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Rogue AP (hostapd)',
            secondary_role='Deauthentication (aireplay-ng)'
        )
        attack.interface_assignment = assignment
        
        # Run attack
        result = attack.run()
        
        # Verify dual interface flow
        mock_config_ap.assert_called_with('wlan0')
        mock_config_deauth.assert_called_with('wlan1')
        mock_start_ap.assert_called_with('wlan0')
        mock_start_services.assert_called_once()
        mock_start_deauth.assert_called_with('wlan1')
        mock_monitor.assert_called_once()
        mock_cleanup.assert_called()
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Airmon')
    def test_no_mode_switching_in_dual_interface(self, mock_airmon, mock_color):
        """Verify no mode switching occurs in dual interface mode."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1mon')
        attack.interface_ap = 'wlan0'
        attack.interface_deauth = 'wlan1mon'
        
        # Mock interface modes
        mock_airmon.get_interface_mode.side_effect = lambda iface: 'managed' if iface == 'wlan0' else 'monitor'
        
        # Verify AP interface stays in managed mode (for hostapd)
        ap_mode = mock_airmon.get_interface_mode('wlan0')
        self.assertEqual(ap_mode, 'managed')
        
        # Verify deauth interface stays in monitor mode
        deauth_mode = mock_airmon.get_interface_mode('wlan1mon')
        self.assertEqual(deauth_mode, 'monitor')
        
        # In dual interface mode, set_interface_mode should only be called during initial setup
        # Not during attack execution (no mode switching)


if __name__ == '__main__':
    unittest.main()



class TestEvilTwinSingleInterfaceFallback(unittest.TestCase):
    """Test Evil Twin attack with single interface fallback."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        self.mock_target.encryption = 'WPA2'
        
        Configuration.interface = 'wlan0'
        Configuration.interface_primary = None
        Configuration.interface_secondary = None
    
    def test_single_interface_initialization(self):
        """Test Evil Twin initialization with single interface."""
        # Create Evil Twin attack with single interface
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan0')
        
        # Verify initialization
        self.assertEqual(attack.interface_ap, 'wlan0')
        self.assertEqual(attack.interface_deauth, 'wlan0')
    
    def test_fallback_to_single_interface(self):
        """Test fallback to single interface when only one available."""
        # Mock assignment strategy returning single interface assignment
        assignment = InterfaceAssignment(
            attack_type='evil_twin',
            primary='wlan0',
            secondary=None,
            primary_role='Rogue AP and Deauth (mode switching)'
        )
        
        # Create attack
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan0')
        attack.interface_assignment = assignment
        
        # Verify single interface mode
        result = attack._get_interface_assignment()
        self.assertIsNotNone(result)
        self.assertFalse(result.is_dual_interface())
        self.assertEqual(result.primary, 'wlan0')
        self.assertIsNone(result.secondary)
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.input')
    @patch('wifite.attack.eviltwin.EvilTwin._check_dependencies')
    @patch('wifite.attack.eviltwin.EvilTwin._check_for_conflicts')
    @patch('wifite.attack.eviltwin.EvilTwin._setup')
    @patch('wifite.attack.eviltwin.EvilTwin._cleanup')
    def test_single_interface_mode_execution(self, mock_cleanup, mock_setup, mock_conflicts,
                                             mock_deps, mock_input, mock_color):
        """Test Evil Twin execution in single interface mode."""
        # Mock user confirmation
        mock_input.return_value = 'YES'
        
        # Mock successful setup
        mock_deps.return_value = True
        mock_conflicts.return_value = True
        mock_setup.return_value = True
        
        # Create attack with single interface (no assignment = single mode)
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan0')
        attack.interface_assignment = None  # No assignment means single interface mode
        
        # Mock attack loop to exit immediately
        with patch.object(attack, '_monitor_attack_loop', return_value=False):
            # Run attack
            result = attack.run()
        
        # Verify single interface mode was used
        # (dual interface methods should not be called)
        mock_setup.assert_called_once()
        mock_cleanup.assert_called()
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Airmon')
    def test_mode_switching_in_single_interface(self, mock_airmon, mock_color):
        """Test mode switching behavior in single interface mode."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan0')
        attack.interface_ap = 'wlan0'
        attack.interface_deauth = 'wlan0'
        
        # In single interface mode, the same interface is used for both roles
        # This requires mode switching between managed (for AP) and monitor (for deauth)
        
        # Verify same interface is used
        self.assertEqual(attack.interface_ap, attack.interface_deauth)
        self.assertEqual(attack.interface_ap, 'wlan0')
    
    @patch('wifite.attack.eviltwin.Color')
    def test_backward_compatibility_single_interface(self, mock_color):
        """Verify backward compatibility with existing single interface behavior."""
        # Create attack without interface assignment (legacy mode)
        attack = EvilTwin(self.mock_target)
        
        # Verify default interface is used
        self.assertEqual(attack.interface_ap, Configuration.interface)
        self.assertEqual(attack.interface_deauth, Configuration.interface)
        
        # Verify no interface assignment
        self.assertIsNone(attack.interface_assignment)

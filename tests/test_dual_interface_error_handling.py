#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Integration tests for dual interface error handling and recovery.

Tests error scenarios including:
- Interface failure during attack
- Fallback to remaining interface
- Cleanup after errors
- Error message display
"""

import unittest
import sys
from unittest.mock import Mock, patch, MagicMock

# Mock sys.argv to prevent argparse from reading test arguments
original_argv = sys.argv
sys.argv = ['wifite']

from wifite.config import Configuration
from wifite.model.target import Target
from wifite.model.interface_info import InterfaceInfo, InterfaceAssignment
from wifite.util.interface_exceptions import (
    InterfaceError,
    InterfaceNotFoundError,
    InterfaceCapabilityError,
    InterfaceAssignmentError,
    InterfaceConfigurationError
)

# Set required Configuration attributes
Configuration.interface = 'wlan0'
Configuration.evil_twin_timeout = 0
Configuration.wpa_attack_timeout = 600
Configuration.interface_primary = None
Configuration.interface_secondary = None

from wifite.attack.eviltwin import EvilTwin
from wifite.attack.wpa import AttackWPA

# Restore original argv
sys.argv = original_argv


def create_mock_interface(name, has_ap=True, has_monitor=True, has_injection=True):
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
        is_up=False,
        is_connected=False
    )


class TestInterfaceFailureDuringAttack(unittest.TestCase):
    """Test interface failure scenarios during attack."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        
        Configuration.interface = 'wlan0'
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Airmon')
    def test_ap_interface_failure(self, mock_airmon, mock_color):
        """Test AP interface failure during Evil Twin attack."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Mock AP interface configuration failure
        mock_airmon.put_interface_down.side_effect = Exception('Interface disappeared')
        
        # Configure AP interface (should fail)
        result = attack._configure_ap_interface('wlan0')
        
        # Verify failure is handled
        self.assertFalse(result)
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Airmon')
    def test_deauth_interface_failure(self, mock_airmon, mock_color):
        """Test deauth interface failure during Evil Twin attack."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Mock deauth interface configuration failure
        mock_airmon.start.return_value = None
        
        # Configure deauth interface (should fail)
        result = attack._configure_deauth_interface('wlan1')
        
        # Verify failure is handled
        self.assertFalse(result)
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.Airmon')
    def test_capture_interface_failure(self, mock_airmon, mock_color):
        """Test capture interface failure during WPA attack."""
        attack = AttackWPA(self.mock_target)
        
        # Mock capture interface failure
        mock_airmon.start.side_effect = [None, 'wlan1mon']  # First fails, second succeeds
        
        # Try to start dual interface attack
        assignment = InterfaceAssignment(
            attack_type='wpa',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Capture',
            secondary_role='Deauth'
        )
        attack.interface_assignment = assignment
        
        # Run dual interface (should fail on capture interface)
        result = attack._run_dual_interface()
        
        # Verify failure is handled
        self.assertIsNone(result)
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Hostapd')
    def test_hostapd_failure(self, mock_hostapd_class, mock_color):
        """Test hostapd failure during Evil Twin attack."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Mock hostapd failure
        mock_hostapd = Mock()
        mock_hostapd.start.return_value = False
        mock_hostapd_class.return_value = mock_hostapd
        mock_hostapd_class.check_ap_mode_support.return_value = True
        
        # Start rogue AP (should fail)
        result = attack._start_rogue_ap_dual('wlan0')
        
        # Verify failure is handled
        self.assertFalse(result)


class TestFallbackToRemainingInterface(unittest.TestCase):
    """Test fallback to remaining interface when one fails."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        
        Configuration.interface = 'wlan0'
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.input')
    @patch('wifite.attack.eviltwin.EvilTwin._check_dependencies')
    @patch('wifite.attack.eviltwin.EvilTwin._check_for_conflicts')
    @patch('wifite.attack.eviltwin.EvilTwin._configure_ap_interface')
    @patch('wifite.attack.eviltwin.EvilTwin._configure_deauth_interface')
    @patch('wifite.attack.eviltwin.EvilTwin._cleanup')
    def test_fallback_when_secondary_fails(self, mock_cleanup, mock_config_deauth,
                                           mock_config_ap, mock_conflicts, mock_deps,
                                           mock_input, mock_color):
        """Test fallback to single interface when secondary interface fails."""
        # Mock user confirmation
        mock_input.return_value = 'YES'
        
        # Mock successful checks
        mock_deps.return_value = True
        mock_conflicts.return_value = True
        mock_config_ap.return_value = True
        mock_config_deauth.return_value = False  # Deauth interface fails
        
        # Create attack with dual interface assignment
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        assignment = InterfaceAssignment(
            attack_type='evil_twin',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Rogue AP',
            secondary_role='Deauth'
        )
        attack.interface_assignment = assignment
        
        # Run attack (should fail due to deauth interface failure)
        with patch.object(attack, '_run_dual_interface', return_value=False):
            result = attack.run()
        
        # Verify cleanup was called
        mock_cleanup.assert_called()
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.Airmon')
    def test_wpa_fallback_on_interface_failure(self, mock_airmon, mock_color):
        """Test WPA fallback when one interface fails."""
        attack = AttackWPA(self.mock_target)
        
        # Mock interface failure
        mock_airmon.start.side_effect = ['wlan0mon', None]  # Second interface fails
        mock_airmon.stop.return_value = None
        
        # Try dual interface attack
        assignment = InterfaceAssignment(
            attack_type='wpa',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Capture',
            secondary_role='Deauth'
        )
        attack.interface_assignment = assignment
        
        # Run dual interface (should fail and cleanup)
        result = attack._run_dual_interface()
        
        # Verify failure and cleanup
        self.assertIsNone(result)
        mock_airmon.stop.assert_called()



class TestCleanupAfterErrors(unittest.TestCase):
    """Test cleanup procedures after errors."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        
        Configuration.interface = 'wlan0'
    
    @patch('wifite.attack.eviltwin.Color')
    def test_cleanup_on_configuration_error(self, mock_color):
        """Test cleanup is called when configuration fails."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Create mock processes
        attack.hostapd = Mock()
        attack.hostapd.stop = Mock()
        attack.dnsmasq = Mock()
        attack.dnsmasq.stop = Mock()
        
        # Run cleanup
        attack._cleanup()
        
        # Verify cleanup was performed
        attack.hostapd.stop.assert_called_once()
        attack.dnsmasq.stop.assert_called_once()
    
    @patch('wifite.attack.eviltwin.Color')
    def test_cleanup_handles_none_processes(self, mock_color):
        """Test cleanup handles None processes gracefully."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Set all processes to None
        attack.hostapd = None
        attack.dnsmasq = None
        attack.portal_server = None
        
        # Run cleanup (should not raise exceptions)
        attack._cleanup()
        
        # Verify no exceptions occurred
        self.assertIsNotNone(attack)
    
    @patch('wifite.attack.eviltwin.Color')
    def test_cleanup_handles_stop_errors(self, mock_color):
        """Test cleanup handles process stop errors gracefully."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Create mock process that raises exception on stop
        attack.hostapd = Mock()
        attack.hostapd.stop = Mock(side_effect=Exception('Stop failed'))
        
        # Run cleanup (should not raise exceptions)
        attack._cleanup()
        
        # Verify cleanup attempted to stop process
        attack.hostapd.stop.assert_called_once()



class TestErrorMessageDisplay(unittest.TestCase):
    """Test error message display."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        
        Configuration.interface = 'wlan0'
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Airmon')
    def test_interface_not_found_error_message(self, mock_airmon, mock_color):
        """Test error message when interface not found."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Mock interface not found
        mock_airmon.put_interface_down.side_effect = InterfaceNotFoundError('Interface wlan0 not found')
        
        # Try to configure interface
        result = attack._configure_ap_interface('wlan0')
        
        # Verify error is handled
        self.assertFalse(result)
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.Hostapd')
    def test_capability_error_message(self, mock_hostapd_class, mock_color):
        """Test error message when interface lacks capability."""
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        
        # Mock AP mode not supported
        mock_hostapd_class.check_ap_mode_support.return_value = False
        
        # Try to start rogue AP
        result = attack._start_rogue_ap_dual('wlan0')
        
        # Verify error is handled
        self.assertFalse(result)
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.input')
    @patch('wifite.attack.eviltwin.EvilTwin._check_dependencies')
    @patch('wifite.attack.eviltwin.EvilTwin._check_for_conflicts')
    @patch('wifite.attack.eviltwin.EvilTwin._configure_ap_interface')
    @patch('wifite.attack.eviltwin.EvilTwin._cleanup')
    def test_configuration_error_message(self, mock_cleanup, mock_config_ap,
                                         mock_conflicts, mock_deps, mock_input, mock_color):
        """Test error message when configuration fails."""
        # Mock user confirmation
        mock_input.return_value = 'YES'
        
        # Mock successful checks but failed configuration
        mock_deps.return_value = True
        mock_conflicts.return_value = True
        mock_config_ap.return_value = False
        
        # Create attack
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1')
        assignment = InterfaceAssignment(
            attack_type='evil_twin',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Rogue AP',
            secondary_role='Deauth'
        )
        attack.interface_assignment = assignment
        attack.error_message = 'Failed to configure AP interface wlan0'
        
        # Run attack (should fail)
        with patch.object(attack, '_run_dual_interface', return_value=False):
            result = attack.run()
        
        # Verify error message is set
        self.assertIsNotNone(attack.error_message)
        self.assertIn('wlan0', attack.error_message)


if __name__ == '__main__':
    unittest.main()

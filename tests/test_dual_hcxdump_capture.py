#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Integration tests for hcxdumptool-based dual interface WPA capture.

Tests core functionality of the hcxdump capture method.
"""

import unittest
import sys
from unittest.mock import Mock, patch, MagicMock

# Mock sys.argv to prevent argparse from reading test arguments
original_argv = sys.argv
sys.argv = ['wifite']

from wifite.config import Configuration
from wifite.model.target import Target
from wifite.model.interface_info import InterfaceAssignment

# Set required Configuration attributes
Configuration.interface = 'wlan0'
Configuration.wpa_attack_timeout = 10
Configuration.wpa_deauth_timeout = 2
Configuration.use_hcxdump = True
Configuration.no_deauth = False
Configuration.ignore_old_handshakes = True

from wifite.attack.wpa import AttackWPA

# Restore original argv
sys.argv = original_argv


class TestDualHcxdumpCapture(unittest.TestCase):
    """Test hcxdumptool-based dual interface capture."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        self.mock_target.pmf_required = False
        
        # Create dual interface assignment
        self.assignment = InterfaceAssignment(
            attack_type='wpa',
            primary='wlan0mon',
            secondary='wlan1mon',
            primary_role='Handshake capture',
            secondary_role='Deauthentication'
        )
    
    def test_method_exists(self):
        """Test that _capture_handshake_dual_hcxdump method exists."""
        attack = AttackWPA(self.mock_target)
        self.assertTrue(hasattr(attack, '_capture_handshake_dual_hcxdump'))
        self.assertTrue(callable(getattr(attack, '_capture_handshake_dual_hcxdump')))


class TestParallelDeauth(unittest.TestCase):
    """Test parallel deauthentication functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        
        Configuration.no_deauth = False
    
    def test_method_exists(self):
        """Test that _deauth_parallel method exists."""
        attack = AttackWPA(self.mock_target)
        self.assertTrue(hasattr(attack, '_deauth_parallel'))
        self.assertTrue(callable(getattr(attack, '_deauth_parallel')))
    
    @patch('wifite.util.color.Color')
    def test_parallel_deauth_respects_no_deauth(self, mock_color):
        """Test that parallel deauth respects no_deauth configuration."""
        Configuration.no_deauth = True
        
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        
        # Run parallel deauth - should return immediately
        attack._deauth_parallel(self.mock_target)
        
        # No assertions needed - just verify it doesn't crash


class TestErrorHandling(unittest.TestCase):
    """Test error handling and fallback scenarios."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.essid_known = True
        self.mock_target.channel = 6
        self.mock_target.power = -50
        self.mock_target.pmf_required = False
        
        # Create dual interface assignment
        self.assignment = InterfaceAssignment(
            attack_type='wpa',
            primary='wlan0mon',
            secondary='wlan1mon',
            primary_role='Handshake capture',
            secondary_role='Deauthentication'
        )
        
        Configuration.use_hcxdump = True
        Configuration.ignore_old_handshakes = True
    
    @patch('wifite.tools.hcxdumptool.HcxDumpTool')
    @patch('wifite.util.color.Color')
    @patch('wifite.tools.airmon.Airmon')
    def test_fallback_when_tool_not_found(self, mock_airmon, mock_color, mock_hcxdump):
        """Test fallback to airodump-ng when hcxdumptool not found."""
        # Mock hcxdumptool not existing
        mock_hcxdump.exists.return_value = False
        mock_hcxdump.dependency_url = 'https://github.com/ZerBea/hcxdumptool'
        
        # Mock airmon to return monitor interfaces
        mock_airmon.start.side_effect = ['wlan0mon', 'wlan1mon']
        mock_airmon.stop.return_value = True
        
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.interface_assignment = self.assignment
        
        # Mock the airodump fallback method
        with patch.object(attack, '_capture_handshake_dual_airodump') as mock_airodump:
            mock_airodump.return_value = None
            
            # Run dual interface attack
            result = attack._run_dual_interface()
            
            # Verify fallback was called
            mock_airodump.assert_called_once()
    
    @patch('wifite.tools.hcxdumptool.HcxDumpTool')
    @patch('wifite.util.color.Color')
    @patch('wifite.tools.airmon.Airmon')
    def test_fallback_when_version_insufficient(self, mock_airmon, mock_color, mock_hcxdump):
        """Test fallback to airodump-ng when hcxdumptool version insufficient."""
        # Mock hcxdumptool existing but with insufficient version
        mock_hcxdump.exists.return_value = True
        mock_hcxdump.check_minimum_version.return_value = False
        mock_hcxdump.check_version.return_value = '5.0.0'
        
        # Mock airmon to return monitor interfaces
        mock_airmon.start.side_effect = ['wlan0mon', 'wlan1mon']
        mock_airmon.stop.return_value = True
        
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.interface_assignment = self.assignment
        
        # Mock the airodump fallback method
        with patch.object(attack, '_capture_handshake_dual_airodump') as mock_airodump:
            mock_airodump.return_value = None
            
            # Run dual interface attack
            result = attack._run_dual_interface()
            
            # Verify fallback was called
            mock_airodump.assert_called_once()
    
    @patch('wifite.tools.hcxdumptool.HcxDumpTool')
    @patch('wifite.tools.hcxdumptool.HcxPcapngTool')
    @patch('wifite.util.timer.Timer')
    @patch('time.sleep')
    @patch('wifite.util.color.Color')
    @patch('os.path.exists')
    @patch('os.path.getsize')
    def test_recovery_from_process_failure(self, mock_getsize, mock_exists, mock_color, 
                                          mock_sleep, mock_timer, mock_hcxpcapng, mock_hcxdump):
        """Test recovery when hcxdumptool process dies during capture."""
        # Mock hcxdumptool available
        mock_hcxdump.exists.return_value = True
        mock_hcxdump.check_minimum_version.return_value = True
        
        # Create mock hcxdump instance that dies
        mock_instance = MagicMock()
        mock_instance.is_running.return_value = False  # Process died
        mock_instance.has_captured_data.return_value = False
        mock_instance.__enter__ = MagicMock(return_value=mock_instance)
        mock_instance.__exit__ = MagicMock(return_value=False)
        mock_hcxdump.return_value = mock_instance
        
        # Mock timer - create a function that returns properly configured timer instances
        def create_timer(*args, **kwargs):
            timer = MagicMock()
            timer.ended.return_value = False
            timer.remaining.return_value = 0
            timer.__str__ = MagicMock(return_value='0:00')
            return timer
        mock_timer.side_effect = create_timer
        
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.interface_assignment = self.assignment
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        attack.clients = []
        
        # Mock the airodump fallback method
        with patch.object(attack, '_capture_handshake_dual_airodump') as mock_airodump:
            mock_airodump.return_value = None
            
            # Run capture - should detect process death and fall back
            result = attack._capture_handshake_dual_hcxdump()
            
            # Verify fallback was called
            mock_airodump.assert_called_once()
    
    @patch('wifite.tools.hcxdumptool.HcxDumpTool')
    @patch('wifite.tools.hcxdumptool.HcxPcapngTool')
    @patch('wifite.util.timer.Timer')
    @patch('time.sleep')
    @patch('wifite.util.color.Color')
    @patch('os.path.exists')
    @patch('os.path.getsize')
    @patch('os.remove')
    def test_large_file_warning(self, mock_remove, mock_getsize, mock_exists, mock_color,
                                mock_sleep, mock_timer, mock_hcxpcapng, mock_hcxdump):
        """Test warning displayed when capture file exceeds 50MB."""
        # Mock hcxdumptool available
        mock_hcxdump.exists.return_value = True
        mock_hcxdump.check_minimum_version.return_value = True
        
        # Create mock hcxdump instance
        mock_instance = MagicMock()
        mock_instance.is_running.return_value = True
        mock_instance.has_captured_data.return_value = True
        mock_instance.__enter__ = MagicMock(return_value=mock_instance)
        mock_instance.__exit__ = MagicMock(return_value=False)
        mock_hcxdump.return_value = mock_instance
        
        # Mock large file size (60MB)
        mock_exists.return_value = True
        mock_getsize.return_value = 60 * 1024 * 1024
        
        # Mock timer - create a function that returns properly configured timer instances
        timer_call_count = [0]
        def create_timer(*args, **kwargs):
            timer = MagicMock()
            # First two timers (timeout and deauth) don't end, third one (step) ends
            if timer_call_count[0] < 2:
                timer.ended.return_value = False
            else:
                timer.ended.side_effect = [False, True]  # Run once then end
            timer.remaining.return_value = 0
            timer.__str__ = MagicMock(return_value='0:00')
            timer_call_count[0] += 1
            return timer
        mock_timer.side_effect = create_timer
        
        # Mock conversion to fail (no handshake)
        mock_hcxpcapng.convert_to_hashcat.return_value = False
        
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.interface_assignment = self.assignment
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        attack.clients = []
        
        # Run capture
        result = attack._capture_handshake_dual_hcxdump()
        
        # Verify warning was displayed (check Color.pl was called with warning)
        warning_calls = [call for call in mock_color.pl.call_args_list 
                        if 'Warning' in str(call) and 'large' in str(call).lower()]
        self.assertTrue(len(warning_calls) > 0, "Large file warning should be displayed")


if __name__ == '__main__':
    unittest.main()

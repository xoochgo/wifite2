#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Integration tests for WPA attack with dual interface support.

Tests the dual interface WPA attack flow including:
- Dual interface initialization
- Capture interface configuration
- Deauth interface configuration
- Continuous capture during deauth
- No capture interruption verification
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
Configuration.interface = 'wlan0'
Configuration.wpa_attack_timeout = 600
Configuration.wpa_deauth_timeout = 10
Configuration.interface_primary = None
Configuration.interface_secondary = None
Configuration.dual_interface_enabled = False

from wifite.attack.wpa import AttackWPA

# Restore original argv
sys.argv = original_argv


def create_mock_interface(name, has_ap=False, has_monitor=True, has_injection=True, is_up=False):
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


class TestWPADualInterface(unittest.TestCase):
    """Test WPA attack with dual interfaces."""
    
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
        """Test WPA initialization with dual interfaces."""
        # Create WPA attack
        attack = AttackWPA(self.mock_target)
        
        # Verify initialization
        self.assertIsNone(attack.interface_assignment)
        self.assertIsNone(attack.capture_interface)
        self.assertIsNone(attack.deauth_interface)
    
    def test_get_interface_assignment_dual(self):
        """Test getting interface assignment for dual interface WPA mode."""
        # Mock interface assignment
        assignment = InterfaceAssignment(
            attack_type='wpa',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Handshake capture (airodump-ng)',
            secondary_role='Deauthentication (aireplay-ng)'
        )
        
        # Create attack and set assignment
        attack = AttackWPA(self.mock_target)
        attack.interface_assignment = assignment
        
        # Get assignment
        result = attack._get_interface_assignment()
        
        # Verify assignment
        self.assertIsNotNone(result)
        self.assertTrue(result.is_dual_interface())
        self.assertEqual(result.primary, 'wlan0')
        self.assertEqual(result.secondary, 'wlan1')
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.tools.airmon.Airmon')
    def test_configure_capture_interface(self, mock_airmon, mock_color):
        """Test capture interface configuration."""
        attack = AttackWPA(self.mock_target)
        
        # Mock monitor mode activation
        mock_airmon.start.return_value = 'wlan0mon'
        
        # Configure capture interface
        mock_airmon.start('wlan0')
        result = mock_airmon.start.return_value
        
        # Verify configuration
        self.assertEqual(result, 'wlan0mon')
        mock_airmon.start.assert_called_with('wlan0')
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.tools.airmon.Airmon')
    def test_configure_deauth_interface(self, mock_airmon, mock_color):
        """Test deauth interface configuration."""
        attack = AttackWPA(self.mock_target)
        
        # Mock monitor mode activation
        mock_airmon.start.return_value = 'wlan1mon'
        
        # Configure deauth interface
        mock_airmon.start('wlan1')
        result = mock_airmon.start.return_value
        
        # Verify configuration
        self.assertEqual(result, 'wlan1mon')
        mock_airmon.start.assert_called_with('wlan1')
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.tools.airmon.Airmon')
    @patch('wifite.attack.wpa.AttackWPA._capture_handshake_dual_airodump')
    def test_run_dual_interface_flow(self, mock_capture, mock_airmon, mock_color):
        """Test complete dual interface WPA attack flow."""
        # Mock monitor mode activation
        mock_airmon.start.side_effect = ['wlan0mon', 'wlan1mon']
        mock_airmon.stop.return_value = None
        
        # Mock handshake capture
        mock_handshake = Mock()
        mock_handshake.capfile = '/tmp/handshake.cap'
        mock_capture.return_value = mock_handshake
        
        # Create attack with dual interface assignment
        attack = AttackWPA(self.mock_target)
        assignment = InterfaceAssignment(
            attack_type='wpa',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Handshake capture (airodump-ng)',
            secondary_role='Deauthentication (aireplay-ng)'
        )
        attack.interface_assignment = assignment
        
        # Run dual interface attack
        result = attack._run_dual_interface()
        
        # Verify dual interface flow
        self.assertEqual(mock_airmon.start.call_count, 2)
        mock_capture.assert_called_once()
        self.assertEqual(mock_airmon.stop.call_count, 2)
        self.assertIsNotNone(result)
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.Airodump')
    @patch('wifite.attack.wpa.Aireplay')
    @patch('wifite.attack.wpa.Handshake')
    @patch('wifite.attack.wpa.AttackWPA.wait_for_target')
    @patch('wifite.attack.wpa.AttackWPA.save_handshake')
    @patch('os.path.getsize')
    @patch('shutil.copy')
    @patch('os.remove')
    def test_continuous_capture_during_deauth(self, mock_remove, mock_copy, mock_getsize,
                                              mock_save, mock_wait, mock_handshake_class,
                                              mock_aireplay, mock_airodump_class, mock_color):
        """Test continuous capture during deauth in dual interface mode."""
        # Mock airodump
        mock_airodump = MagicMock()
        mock_airodump.__enter__ = Mock(return_value=mock_airodump)
        mock_airodump.__exit__ = Mock(return_value=False)
        mock_airodump.find_files.return_value = ['/tmp/wpa-01.cap']
        mock_airodump_class.return_value = mock_airodump
        
        # Mock target
        mock_airodump_target = Mock()
        mock_airodump_target.bssid = 'AA:BB:CC:DD:EE:FF'
        mock_airodump_target.essid = 'TestNetwork'
        mock_airodump_target.essid_known = True
        mock_airodump_target.clients = []
        mock_wait.return_value = mock_airodump_target
        
        # Mock handshake
        mock_handshake = Mock()
        mock_handshake.has_handshake.side_effect = [False, False, True]  # Found on 3rd check
        mock_handshake.capfile = '/tmp/handshake.cap'
        mock_handshake_class.return_value = mock_handshake
        
        # Mock file operations
        mock_getsize.return_value = 1024
        
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        
        # Run capture
        result = attack._capture_handshake_dual_airodump()
        
        # Verify continuous capture
        self.assertIsNotNone(result)
        self.assertEqual(result, mock_handshake)
        
        # Verify airodump was started on capture interface
        mock_airodump_class.assert_called_once()
        call_kwargs = mock_airodump_class.call_args[1]
        self.assertEqual(call_kwargs['interface'], 'wlan0mon')
        
        # Verify deauth was sent from deauth interface
        mock_aireplay.deauth.assert_called()
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.Aireplay')
    def test_deauth_dual_no_capture_interruption(self, mock_aireplay, mock_color):
        """Verify deauth doesn't interrupt capture in dual interface mode."""
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        attack.clients = ['11:22:33:44:55:66']
        
        # Mock target
        mock_target = Mock()
        mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        
        # Send deauth
        attack._deauth_dual(mock_target)
        
        # Verify deauth was sent from deauth interface
        mock_aireplay.deauth.assert_called()
        
        # Verify deauth interface was used (not capture interface)
        call_kwargs = mock_aireplay.deauth.call_args[1]
        self.assertEqual(call_kwargs['interface'], 'wlan1mon')
        
        # In dual interface mode, capture continues on wlan0mon
        # while deauth is sent from wlan1mon - no interruption


class TestWPAParallelDeauth(unittest.TestCase):
    """Test parallel deauthentication from both interfaces."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        
        Configuration.interface = 'wlan0'
        Configuration.no_deauth = False
        Configuration.verbose = 0
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.Aireplay')
    @patch('threading.Thread')
    def test_parallel_deauth_broadcast(self, mock_thread_class, mock_aireplay, mock_color):
        """Test parallel deauth sent to broadcast."""
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        attack.clients = []  # No clients, should use broadcast
        
        # Mock threads
        mock_thread1 = Mock()
        mock_thread2 = Mock()
        mock_thread_class.side_effect = [mock_thread1, mock_thread2]
        
        # Send parallel deauth
        attack._deauth_parallel(self.mock_target)
        
        # Verify two threads were created
        self.assertEqual(mock_thread_class.call_count, 2)
        
        # Verify threads were started
        mock_thread1.start.assert_called_once()
        mock_thread2.start.assert_called_once()
        
        # Verify threads were joined
        mock_thread1.join.assert_called_once()
        mock_thread2.join.assert_called_once()
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.Aireplay')
    @patch('threading.Thread')
    def test_parallel_deauth_specific_clients(self, mock_thread_class, mock_aireplay, mock_color):
        """Test parallel deauth sent to specific clients."""
        # Create attack with clients
        attack = AttackWPA(self.mock_target)
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        attack.clients = ['11:22:33:44:55:66', '77:88:99:AA:BB:CC']
        
        # Mock threads
        mock_thread1 = Mock()
        mock_thread2 = Mock()
        mock_thread_class.side_effect = [mock_thread1, mock_thread2]
        
        # Send parallel deauth
        attack._deauth_parallel(self.mock_target)
        
        # Verify two threads were created (one per interface)
        self.assertEqual(mock_thread_class.call_count, 2)
        
        # Verify both threads were started and joined
        mock_thread1.start.assert_called_once()
        mock_thread2.start.assert_called_once()
        mock_thread1.join.assert_called_once()
        mock_thread2.join.assert_called_once()
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.Aireplay')
    def test_parallel_deauth_threading_behavior(self, mock_aireplay, mock_color):
        """Test that parallel deauth uses threading correctly."""
        import threading
        
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        attack.clients = ['11:22:33:44:55:66']
        
        # Track thread execution
        thread_calls = []
        
        def track_deauth(*args, **kwargs):
            thread_calls.append(threading.current_thread().name)
        
        mock_aireplay.deauth.side_effect = track_deauth
        
        # Send parallel deauth
        attack._deauth_parallel(self.mock_target)
        
        # Verify deauth was called from multiple threads
        # Should be called for broadcast + 1 client = 2 calls per interface = 4 total
        self.assertEqual(len(thread_calls), 4)
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.Aireplay')
    @patch('wifite.util.logger.log_debug')
    def test_parallel_deauth_exception_handling(self, mock_log_debug, mock_aireplay, mock_color):
        """Test exception handling in parallel deauth threads."""
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        attack.clients = ['11:22:33:44:55:66']
        
        # Make deauth raise exception
        mock_aireplay.deauth.side_effect = Exception('Deauth failed')
        
        # Send parallel deauth - should not raise exception
        try:
            attack._deauth_parallel(self.mock_target)
            exception_raised = False
        except Exception:
            exception_raised = True
        
        # Verify no exception was raised (handled gracefully)
        self.assertFalse(exception_raised)
        
        # Verify error was logged
        self.assertTrue(mock_log_debug.called)
    
    @patch('wifite.attack.wpa.Color')
    def test_parallel_deauth_respects_no_deauth_config(self, mock_color):
        """Test that parallel deauth respects no_deauth configuration."""
        # Enable no_deauth
        Configuration.no_deauth = True
        
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        attack.clients = ['11:22:33:44:55:66']
        
        # Send parallel deauth
        with patch('wifite.attack.wpa.Aireplay') as mock_aireplay:
            attack._deauth_parallel(self.mock_target)
            
            # Verify no deauth was sent
            mock_aireplay.deauth.assert_not_called()
        
        # Reset configuration
        Configuration.no_deauth = False
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.Aireplay')
    def test_parallel_deauth_status_display(self, mock_aireplay, mock_color):
        """Test status display during parallel deauth."""
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        attack.clients = []
        
        # Send parallel deauth
        attack._deauth_parallel(self.mock_target)
        
        # Verify status was displayed
        mock_color.clear_entire_line.assert_called()
        mock_color.pattack.assert_called()
        
        # Verify both interface names were in the status message
        call_args = mock_color.pattack.call_args[0]
        status_message = call_args[3]
        self.assertIn('wlan0mon', status_message)
        self.assertIn('wlan1mon', status_message)
        self.assertIn('DUAL-HCX', status_message)
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.Aireplay')
    def test_parallel_deauth_tui_integration(self, mock_aireplay, mock_color):
        """Test TUI view integration during parallel deauth."""
        # Create attack with mock TUI view
        attack = AttackWPA(self.mock_target)
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        attack.clients = []
        attack.view = Mock()
        
        # Send parallel deauth
        attack._deauth_parallel(self.mock_target)
        
        # Verify TUI view was updated
        attack.view.add_log.assert_called()
        
        # Verify log message contains both interface names
        log_message = attack.view.add_log.call_args[0][0]
        self.assertIn('wlan0mon', log_message)
        self.assertIn('wlan1mon', log_message)
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.Aireplay')
    @patch('wifite.util.logger.log_debug')
    def test_parallel_deauth_verbose_logging(self, mock_log_debug, mock_aireplay, mock_color):
        """Test verbose logging during parallel deauth."""
        # Enable verbose mode
        Configuration.verbose = 2
        
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.capture_interface = 'wlan0mon'
        attack.deauth_interface = 'wlan1mon'
        attack.clients = ['11:22:33:44:55:66']
        
        # Send parallel deauth
        attack._deauth_parallel(self.mock_target)
        
        # Verify verbose logging was called
        self.assertTrue(mock_log_debug.called)
        
        # Verify log messages contain interface and client info
        log_calls = [call[0] for call in mock_log_debug.call_args_list]
        log_messages = [call[1] for call in log_calls]
        
        # Should have logs for both interfaces
        interface_logs = [msg for msg in log_messages if 'wlan0mon' in msg or 'wlan1mon' in msg]
        self.assertGreater(len(interface_logs), 0)
        
        # Reset configuration
        Configuration.verbose = 0


if __name__ == '__main__':
    unittest.main()



class TestWPASingleInterfaceFallback(unittest.TestCase):
    """Test WPA attack with single interface fallback."""
    
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
        """Test WPA initialization with single interface."""
        # Create WPA attack
        attack = AttackWPA(self.mock_target)
        
        # Verify initialization
        self.assertIsNone(attack.interface_assignment)
        self.assertIsNone(attack.capture_interface)
        self.assertIsNone(attack.deauth_interface)
    
    def test_fallback_to_single_interface(self):
        """Test fallback to single interface when only one available."""
        # Mock assignment strategy returning single interface assignment
        assignment = InterfaceAssignment(
            attack_type='wpa',
            primary='wlan0',
            secondary=None,
            primary_role='Handshake capture and deauth'
        )
        
        # Create attack
        attack = AttackWPA(self.mock_target)
        attack.interface_assignment = assignment
        
        # Verify single interface mode
        result = attack._get_interface_assignment()
        self.assertIsNotNone(result)
        self.assertFalse(result.is_dual_interface())
        self.assertEqual(result.primary, 'wlan0')
        self.assertIsNone(result.secondary)
    
    @patch('wifite.attack.wpa.Color')
    @patch('wifite.attack.wpa.AttackWPA.capture_handshake')
    @patch('wifite.attack.wpa.Handshake')
    @patch('wifite.attack.wpa.Configuration')
    def test_single_interface_mode_execution(self, mock_config, mock_handshake_class,
                                             mock_capture, mock_color):
        """Test WPA execution in single interface mode."""
        # Mock configuration
        mock_config.wps_only = False
        mock_config.use_pmkid_only = False
        mock_config.skip_crack = True
        mock_config.wordlist = None
        
        # Mock handshake capture
        mock_handshake = Mock()
        mock_handshake.capfile = '/tmp/handshake.cap'
        mock_handshake.bssid = 'AA:BB:CC:DD:EE:FF'
        mock_handshake.essid = 'TestNetwork'
        mock_handshake.analyze = Mock()
        mock_capture.return_value = mock_handshake
        
        # Create attack with no assignment (single interface mode)
        attack = AttackWPA(self.mock_target)
        attack.interface_assignment = None
        
        # Run attack
        result = attack.run()
        
        # Verify single interface mode was used
        mock_capture.assert_called_once()
        mock_handshake.analyze.assert_called_once()
    
    @patch('wifite.attack.wpa.Color')
    def test_backward_compatibility_single_interface(self, mock_color):
        """Verify backward compatibility with existing single interface behavior."""
        # Create attack without interface assignment (legacy mode)
        attack = AttackWPA(self.mock_target)
        
        # Verify no interface assignment
        self.assertIsNone(attack.interface_assignment)
        self.assertIsNone(attack.capture_interface)
        self.assertIsNone(attack.deauth_interface)
        
        # Verify target is set
        self.assertEqual(attack.target, self.mock_target)

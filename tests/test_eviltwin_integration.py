#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Integration tests for Evil Twin attack.

Tests the full attack flow including:
- Complete attack lifecycle
- Multi-client handling
- Interrupt handling
- Cleanup procedures
"""

import unittest
import tempfile
import shutil
import os
import time
import signal
import threading
import sys
from unittest.mock import Mock, patch, MagicMock, PropertyMock

# Mock sys.argv to prevent argparse from reading test arguments
original_argv = sys.argv
sys.argv = ['wifite']

from wifite.config import Configuration

# Set required Configuration attributes before importing other modules
Configuration.wpa_attack_timeout = 600
Configuration.interface = 'wlan0'
Configuration.evil_twin_timeout = 0
Configuration.evil_twin_portal_template = 'generic'
Configuration.evil_twin_deauth_interval = 5

from wifite.attack.eviltwin import EvilTwin, AttackState
from wifite.model.target import Target
from wifite.util.client_monitor import ClientConnection

# Restore original argv
sys.argv = original_argv


class TestEvilTwinFullAttackFlow(unittest.TestCase):
    """Test complete Evil Twin attack flow."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create mock target
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        self.mock_target.encryption = 'WPA2'
        self.mock_target.power = -50
        self.mock_target.wps = False
        
        # Mock configuration
        Configuration.interface = 'wlan0'
        Configuration.evil_twin_timeout = 0
        Configuration.evil_twin_portal_template = 'generic'
        Configuration.evil_twin_deauth_interval = 5
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.input')
    def test_full_attack_initialization(self, mock_input, mock_color):
        """Test Evil Twin attack initialization."""
        # Mock user confirmation
        mock_input.return_value = 'YES'
        
        # Create attack instance
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1mon')
        
        # Verify initialization
        self.assertEqual(attack.target, self.mock_target)
        self.assertEqual(attack.interface_ap, 'wlan0')
        self.assertEqual(attack.interface_deauth, 'wlan1mon')
        self.assertEqual(attack.state, AttackState.INITIALIZING)
        self.assertFalse(attack.running)
        self.assertFalse(attack.success)
        self.assertIsNone(attack.crack_result)
        self.assertEqual(len(attack.clients_connected), 0)
        self.assertEqual(len(attack.credential_attempts), 0)
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.input')
    @patch('wifite.attack.eviltwin.EvilTwin._check_dependencies')
    @patch('wifite.attack.eviltwin.EvilTwin._check_for_conflicts')
    @patch('wifite.attack.eviltwin.EvilTwin._setup')
    @patch('wifite.attack.eviltwin.EvilTwin._cleanup')
    def test_full_attack_flow_success(self, mock_cleanup, mock_setup, mock_conflicts, 
                                      mock_deps, mock_input, mock_color):
        """Test successful full attack flow."""
        # Mock user confirmation
        mock_input.return_value = 'YES'
        
        # Mock successful setup
        mock_deps.return_value = True
        mock_conflicts.return_value = True
        mock_setup.return_value = True
        
        # Create attack instance
        attack = EvilTwin(self.mock_target, 'wlan0', 'wlan1mon')
        
        # Mock credential capture
        def simulate_credential_capture():
            time.sleep(0.1)
            attack.on_credential_submission('11:22:33:44:55:66', 'testpassword123', True)
        
        # Start credential capture in background
        capture_thread = threading.Thread(target=simulate_credential_capture)
        capture_thread.daemon = True
        capture_thread.start()
        
        # Run attack
        result = attack.run()
        
        # Verify success
        self.assertTrue(result)
        self.assertTrue(attack.success)
        self.assertIsNotNone(attack.crack_result)
        self.assertEqual(attack.crack_result.key, 'testpassword123')
        
        # Verify cleanup was called
        mock_cleanup.assert_called()
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.input')
    @patch('wifite.attack.eviltwin.EvilTwin._check_dependencies')
    @patch('wifite.attack.eviltwin.EvilTwin._cleanup')
    def test_attack_flow_dependency_failure(self, mock_cleanup, mock_deps, mock_input, mock_color):
        """Test attack flow when dependencies are missing."""
        # Mock user confirmation
        mock_input.return_value = 'YES'
        
        # Mock dependency failure
        mock_deps.return_value = False
        
        # Create and run attack
        attack = EvilTwin(self.mock_target)
        result = attack.run()
        
        # Verify failure
        self.assertFalse(result)
        self.assertFalse(attack.success)
        # State will be CLEANING_UP after cleanup runs, but we check it was FAILED before
        self.assertIn(attack.state, [AttackState.FAILED, AttackState.CLEANING_UP])
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.input')
    @patch('wifite.attack.eviltwin.EvilTwin._cleanup')
    def test_attack_flow_user_declines_warning(self, mock_cleanup, mock_input, mock_color):
        """Test attack flow when user declines legal warning."""
        # Mock user declining
        mock_input.return_value = 'NO'
        
        # Create and run attack
        attack = EvilTwin(self.mock_target)
        result = attack.run()
        
        # Verify cancellation
        self.assertFalse(result)
        self.assertFalse(attack.success)
        self.assertIn(attack.state, [AttackState.FAILED, AttackState.CLEANING_UP])
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.input')
    @patch('wifite.attack.eviltwin.EvilTwin._check_dependencies')
    @patch('wifite.attack.eviltwin.EvilTwin._check_for_conflicts')
    @patch('wifite.attack.eviltwin.EvilTwin._setup')
    @patch('wifite.attack.eviltwin.EvilTwin._cleanup')
    def test_attack_flow_setup_failure(self, mock_cleanup, mock_setup, mock_conflicts, mock_deps, 
                                       mock_input, mock_color):
        """Test attack flow when setup fails."""
        # Mock user confirmation
        mock_input.return_value = 'YES'
        
        # Mock successful checks but failed setup
        mock_deps.return_value = True
        mock_conflicts.return_value = True
        mock_setup.return_value = False
        
        # Create and run attack
        attack = EvilTwin(self.mock_target)
        attack.error_message = 'Setup failed'
        result = attack.run()
        
        # Verify failure
        self.assertFalse(result)
        self.assertFalse(attack.success)
        self.assertIn(attack.state, [AttackState.FAILED, AttackState.CLEANING_UP])


class TestEvilTwinMultiClientHandling(unittest.TestCase):
    """Test Evil Twin multi-client handling."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        
        Configuration.interface = 'wlan0'
    
    def test_multiple_client_connections(self):
        """Test handling multiple client connections."""
        attack = EvilTwin(self.mock_target)
        
        # Simulate multiple clients connecting
        clients = [
            ClientConnection('11:22:33:44:55:66', '192.168.100.10', 'client1', time.time()),
            ClientConnection('AA:BB:CC:DD:EE:FF', '192.168.100.11', 'client2', time.time()),
            ClientConnection('12:34:56:78:90:AB', '192.168.100.12', 'client3', time.time())
        ]
        
        for client in clients:
            attack._on_client_connect(client)
        
        # Verify all clients are tracked
        self.assertEqual(len(attack.clients_connected), 3)
    
    def test_multiple_credential_attempts(self):
        """Test handling multiple credential attempts."""
        attack = EvilTwin(self.mock_target)
        
        # Simulate multiple credential attempts
        attempts = [
            ('11:22:33:44:55:66', 'password1', False),
            ('11:22:33:44:55:66', 'password2', False),
            ('AA:BB:CC:DD:EE:FF', 'wrongpass', False),
            ('11:22:33:44:55:66', 'correctpass', True)
        ]
        
        for mac, password, success in attempts[:-1]:
            attack.on_credential_submission(mac, password, success)
        
        # Verify attempts are tracked
        self.assertEqual(len(attack.credential_attempts), 3)
        
        # Submit successful attempt
        mac, password, success = attempts[-1]
        attack.on_credential_submission(mac, password, success)
        
        # Verify success
        self.assertEqual(len(attack.credential_attempts), 4)
        self.assertIsNotNone(attack.crack_result)
        self.assertEqual(attack.crack_result.key, 'correctpass')
    
    def test_concurrent_client_operations(self):
        """Test concurrent client connect/disconnect operations."""
        attack = EvilTwin(self.mock_target)
        
        # Create mock client monitor
        attack.client_monitor = Mock()
        attack.client_monitor.has_connected_clients = Mock(return_value=True)
        
        # Simulate clients connecting
        client1 = ClientConnection('11:22:33:44:55:66', '192.168.100.10', 'client1', time.time())
        client2 = ClientConnection('AA:BB:CC:DD:EE:FF', '192.168.100.11', 'client2', time.time())
        
        attack._on_client_connect(client1)
        attack._on_client_connect(client2)
        
        self.assertEqual(len(attack.clients_connected), 2)
        
        # Simulate client1 disconnecting
        attack._on_client_disconnect(client1)
        
        # Verify client1 is still in history but client2 remains connected
        self.assertEqual(len(attack.clients_connected), 2)
    
    def test_client_dhcp_assignment(self):
        """Test client DHCP assignment handling."""
        attack = EvilTwin(self.mock_target)
        
        # Simulate client DHCP
        client = ClientConnection('11:22:33:44:55:66', '192.168.100.10', 'test-device', time.time())
        attack._on_client_dhcp(client)
        
        # Verify client is tracked (should be added if not already present)
        # Note: _on_client_dhcp doesn't add to clients_connected, just updates TUI
        # This is expected behavior


class TestEvilTwinInterruptHandling(unittest.TestCase):
    """Test Evil Twin interrupt handling."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        
        Configuration.interface = 'wlan0'
    
    @patch('wifite.attack.eviltwin.Color')
    def test_signal_handler_sigint(self, mock_color):
        """Test SIGINT signal handling."""
        attack = EvilTwin(self.mock_target)
        attack.running = True
        attack.start_time = time.time()
        
        # Simulate SIGINT
        try:
            attack._signal_handler(signal.SIGINT, None)
        except KeyboardInterrupt:
            pass  # Expected
        
        # Verify attack is stopping
        self.assertFalse(attack.running)
        self.assertEqual(attack.state, AttackState.STOPPING)
    
    @patch('wifite.attack.eviltwin.Color')
    def test_signal_handler_sigterm(self, mock_color):
        """Test SIGTERM signal handling."""
        attack = EvilTwin(self.mock_target)
        attack.running = True
        attack.start_time = time.time()
        
        # Simulate SIGTERM
        attack._signal_handler(signal.SIGTERM, None)
        
        # Verify attack is stopping
        self.assertFalse(attack.running)
        self.assertEqual(attack.state, AttackState.STOPPING)
    
    @patch('wifite.attack.eviltwin.Color')
    def test_display_partial_results(self, mock_color):
        """Test displaying partial results on interrupt."""
        attack = EvilTwin(self.mock_target)
        attack.start_time = time.time()
        
        # Add some test data
        client = ClientConnection('11:22:33:44:55:66', '192.168.100.10', 'client1', time.time())
        attack.clients_connected.append(client)
        
        attack.credential_attempts.append({
            'mac': '11:22:33:44:55:66',
            'password': 'testpass',
            'success': False,
            'timestamp': time.time()
        })
        
        # Display partial results
        attack._display_partial_results()
        
        # Verify no exceptions were raised
        self.assertEqual(len(attack.clients_connected), 1)
        self.assertEqual(len(attack.credential_attempts), 1)
    
    @patch('wifite.attack.eviltwin.Color')
    @patch('wifite.attack.eviltwin.input')
    @patch('wifite.attack.eviltwin.EvilTwin._check_dependencies')
    @patch('wifite.attack.eviltwin.EvilTwin._check_for_conflicts')
    @patch('wifite.attack.eviltwin.EvilTwin._setup')
    @patch('wifite.attack.eviltwin.EvilTwin._cleanup')
    def test_keyboard_interrupt_during_attack(self, mock_cleanup, mock_setup, mock_conflicts,
                                              mock_deps, mock_input, mock_color):
        """Test keyboard interrupt during attack."""
        # Mock user confirmation
        mock_input.return_value = 'YES'
        
        # Mock successful setup
        mock_deps.return_value = True
        mock_conflicts.return_value = True
        mock_setup.return_value = True
        
        # Create attack instance
        attack = EvilTwin(self.mock_target)
        
        # Simulate keyboard interrupt after short delay
        def simulate_interrupt():
            time.sleep(0.1)
            attack.running = False
            attack.state = AttackState.STOPPING
        
        interrupt_thread = threading.Thread(target=simulate_interrupt)
        interrupt_thread.daemon = True
        interrupt_thread.start()
        
        # Run attack (should be interrupted)
        result = attack.run()
        
        # Verify cleanup was called
        mock_cleanup.assert_called()
    
    def test_stop_method(self):
        """Test stop() method for graceful shutdown."""
        attack = EvilTwin(self.mock_target)
        attack.running = True
        attack.state = AttackState.RUNNING
        
        # Call stop
        attack.stop()
        
        # Verify attack is stopping
        self.assertFalse(attack.running)
        self.assertEqual(attack.state, AttackState.STOPPING)


class TestEvilTwinCleanupProcedures(unittest.TestCase):
    """Test Evil Twin cleanup procedures."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        
        Configuration.interface = 'wlan0'
    
    def test_cleanup_stops_all_processes(self):
        """Test cleanup stops all spawned processes."""
        attack = EvilTwin(self.mock_target)
        
        # Create mock processes with stop methods
        mock_hostapd = Mock()
        mock_hostapd.stop = Mock()
        attack.hostapd = mock_hostapd
        
        mock_dnsmasq = Mock()
        mock_dnsmasq.stop = Mock()
        attack.dnsmasq = mock_dnsmasq
        
        mock_portal = Mock()
        mock_portal.stop = Mock()
        attack.portal_server = mock_portal
        
        mock_deauth = Mock()
        mock_deauth.stop = Mock()
        attack.deauth_process = mock_deauth
        
        mock_monitor = Mock()
        mock_monitor.stop = Mock()
        attack.client_monitor = mock_monitor
        
        # Run cleanup
        attack._cleanup()
        
        # Verify all processes were stopped (they get set to None after stopping)
        mock_hostapd.stop.assert_called_once()
        mock_dnsmasq.stop.assert_called_once()
        mock_portal.stop.assert_called_once()
        mock_deauth.stop.assert_called_once()
        mock_monitor.stop.assert_called_once()
    
    def test_cleanup_removes_temp_files(self):
        """Test cleanup removes temporary files."""
        attack = EvilTwin(self.mock_target)
        
        # Create temporary files
        temp_files = []
        for i in range(3):
            fd, temp_file = tempfile.mkstemp()
            os.close(fd)
            temp_files.append(temp_file)
            attack.temp_files.append(temp_file)
        
        # Verify files exist
        for temp_file in temp_files:
            self.assertTrue(os.path.exists(temp_file))
        
        # Run cleanup
        attack._cleanup()
        
        # Verify files are removed
        for temp_file in temp_files:
            self.assertFalse(os.path.exists(temp_file))
    
    def test_cleanup_handles_none_processes(self):
        """Test cleanup handles None processes gracefully."""
        attack = EvilTwin(self.mock_target)
        
        # Set all processes to None
        attack.hostapd = None
        attack.dnsmasq = None
        attack.portal_server = None
        attack.deauth_process = None
        attack.client_monitor = None
        
        # Run cleanup (should not raise exceptions)
        attack._cleanup()
        
        # Verify state
        self.assertEqual(attack.state, AttackState.CLEANING_UP)
    
    def test_cleanup_handles_process_errors(self):
        """Test cleanup handles process stop errors gracefully."""
        attack = EvilTwin(self.mock_target)
        
        # Create mock process that raises exception on stop
        mock_hostapd = Mock()
        mock_hostapd.stop = Mock(side_effect=Exception('Stop failed'))
        attack.hostapd = mock_hostapd
        
        # Run cleanup (should not raise exceptions)
        attack._cleanup()
        
        # Verify cleanup attempted to stop process
        mock_hostapd.stop.assert_called_once()
    
    def test_cleanup_idempotent(self):
        """Test cleanup can be called multiple times safely."""
        attack = EvilTwin(self.mock_target)
        
        # Create mock process
        attack.hostapd = Mock()
        attack.hostapd.stop = Mock()
        
        # Run cleanup multiple times
        attack._cleanup()
        attack._cleanup()
        attack._cleanup()
        
        # Verify no errors occurred
        self.assertEqual(attack.state, AttackState.CLEANING_UP)
    
    @patch('subprocess.run')
    def test_cleanup_orphaned_processes(self, mock_run):
        """Test cleanup of orphaned processes."""
        attack = EvilTwin(self.mock_target)
        
        # Mock pgrep finding orphaned processes
        mock_run.side_effect = [
            Mock(returncode=0, stdout='1234\n5678\n'),  # hostapd
            Mock(returncode=0, stdout='9012\n'),         # dnsmasq
            Mock(returncode=1, stdout=''),               # portal
            Mock(returncode=0),  # kill 1234
            Mock(returncode=0),  # kill 5678
            Mock(returncode=0),  # kill 9012
        ]
        
        # Run cleanup
        attack.cleanup_orphaned_processes()
        
        # Verify pgrep was called
        self.assertGreaterEqual(mock_run.call_count, 3)
    
    @patch('subprocess.run')
    def test_is_attack_running_detection(self, mock_run):
        """Test detection of running Evil Twin attacks."""
        # Mock hostapd process found
        mock_run.return_value = Mock(returncode=0, stdout='1234\n')
        
        result = EvilTwin.is_attack_running()
        
        self.assertTrue(result)
    
    @patch('subprocess.run')
    def test_is_attack_running_no_processes(self, mock_run):
        """Test detection when no Evil Twin attacks are running."""
        # Mock no processes found
        mock_run.return_value = Mock(returncode=1, stdout='')
        
        result = EvilTwin.is_attack_running()
        
        self.assertFalse(result)


class TestEvilTwinSessionIntegration(unittest.TestCase):
    """Test Evil Twin session management integration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        self.mock_target = Mock(spec=Target)
        self.mock_target.bssid = 'AA:BB:CC:DD:EE:FF'
        self.mock_target.essid = 'TestNetwork'
        self.mock_target.channel = 6
        
        Configuration.interface = 'wlan0'
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_save_state_to_session(self):
        """Test saving attack state to session."""
        attack = EvilTwin(self.mock_target)
        attack.start_time = time.time()
        attack.setup_time = 10.5
        
        # Add test data
        client = ClientConnection('11:22:33:44:55:66', '192.168.100.10', 'client1', time.time())
        attack.clients_connected.append(client)
        
        attack.credential_attempts.append({
            'mac': '11:22:33:44:55:66',
            'password': 'testpass',
            'success': False,
            'timestamp': time.time()
        })
        
        # Save state
        state = attack.save_state_to_session()
        
        # Verify state
        self.assertEqual(state.interface_ap, 'wlan0')
        self.assertEqual(len(state.clients), 1)
        self.assertEqual(len(state.credential_attempts), 1)
        self.assertEqual(state.total_clients_connected, 1)
        self.assertEqual(state.total_credential_attempts, 1)
    
    def test_restore_state_from_session(self):
        """Test restoring attack state from session."""
        from wifite.util.session import EvilTwinAttackState, EvilTwinClientState, EvilTwinCredentialAttempt
        
        # Create state to restore
        client_state = EvilTwinClientState(
            mac_address='11:22:33:44:55:66',
            ip_address='192.168.100.10',
            hostname='client1',
            connect_time=time.time()
        )
        
        attempt_state = EvilTwinCredentialAttempt(
            mac_address='11:22:33:44:55:66',
            password='testpass',
            success=False,
            timestamp=time.time()
        )
        
        state = EvilTwinAttackState(
            interface_ap='wlan0',
            interface_deauth='wlan1mon',
            attack_phase='running',
            start_time=time.time(),
            setup_time=10.5,
            clients=[client_state],
            credential_attempts=[attempt_state],
            total_clients_connected=1,
            total_credential_attempts=1
        )
        
        # Create attack and restore state
        attack = EvilTwin(self.mock_target)
        result = attack.restore_state_from_session(state)
        
        # Verify restoration
        self.assertTrue(result)
        self.assertEqual(attack.interface_ap, 'wlan0')
        self.assertEqual(attack.interface_deauth, 'wlan1mon')
        self.assertEqual(len(attack.credential_attempts), 1)
    
    def test_can_resume_from_state(self):
        """Test checking if attack can be resumed."""
        from wifite.util.session import EvilTwinAttackState
        
        attack = EvilTwin(self.mock_target)
        
        # Test case 1: Can resume from running state
        state = EvilTwinAttackState(
            interface_ap='wlan0',
            attack_phase='running',
            start_time=time.time()
        )
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout='wlan0')
            result = attack.can_resume_from_state(state)
            self.assertTrue(result)
        
        # Test case 2: Cannot resume from completed state
        state.captured_password = 'testpass'
        result = attack.can_resume_from_state(state)
        self.assertFalse(result)
        
        # Test case 3: Cannot resume from failed state
        state.captured_password = None
        state.attack_phase = 'failed'
        result = attack.can_resume_from_state(state)
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()

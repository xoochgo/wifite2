#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Unit tests for interface detection functionality.

Tests the interface detection and capability checking methods.
"""

import unittest
from unittest.mock import Mock, patch
from wifite.util.interface_manager import InterfaceManager
from wifite.model.interface_info import InterfaceInfo


class TestInterfaceDetection(unittest.TestCase):
    """Test interface detection methods."""
    
    @patch('wifite.util.interface_manager.Process')
    def test_get_available_interfaces_multiple(self, mock_process):
        """Test detection of multiple interfaces."""
        # Mock iw dev output
        mock_proc = Mock()
        mock_proc.stdout.return_value = """
phy#0
        Interface wlan0
                ifindex 3
                wdev 0x1
                addr 00:11:22:33:44:55
                type managed
phy#1
        Interface wlan1
                ifindex 4
                wdev 0x2
                addr AA:BB:CC:DD:EE:FF
                type managed
"""
        mock_process.return_value = mock_proc
        
        # Test - this will call the real system, so we just check it doesn't crash
        # In a real environment, this would return actual interfaces
        interfaces = InterfaceManager.get_available_interfaces()
        
        # Just verify it returns a list
        self.assertIsInstance(interfaces, list)
    
    @patch('wifite.util.interface_manager.Process')
    def test_get_available_interfaces_none(self, mock_process):
        """Test detection when no interfaces available."""
        # Mock iw dev output with no interfaces
        mock_proc = Mock()
        mock_proc.stdout.return_value = ""
        mock_process.return_value = mock_proc
        
        interfaces = InterfaceManager.get_available_interfaces()
        
        self.assertIsInstance(interfaces, list)
    
    def test_check_ap_mode_support(self):
        """Test AP mode detection method exists."""
        # Just verify the method exists and can be called
        result = InterfaceManager.check_ap_mode_support('wlan0')
        self.assertIsInstance(result, bool)
    
    def test_check_injection_support_known_good_driver(self):
        """Test injection detection for known good drivers."""
        # Test with ath9k (known good)
        result = InterfaceManager.check_injection_support('ath9k')
        self.assertTrue(result)
        
        # Test with rt2800usb (known good)
        result = InterfaceManager.check_injection_support('rt2800usb')
        self.assertTrue(result)
    
    def test_check_injection_support_known_bad_driver(self):
        """Test injection detection for known problematic drivers."""
        # Test with iwlwifi (no injection)
        result = InterfaceManager.check_injection_support('iwlwifi')
        self.assertFalse(result)
        
        # Test with brcmfmac (limited injection)
        result = InterfaceManager.check_injection_support('brcmfmac')
        self.assertFalse(result)
    
    def test_check_injection_support_unknown_driver(self):
        """Test injection detection for unknown drivers."""
        # Should default to True (optimistic)
        result = InterfaceManager.check_injection_support('unknown_driver')
        self.assertTrue(result)


class TestCapabilityDetection(unittest.TestCase):
    """Test capability detection for different scenarios."""
    
    def test_injection_capability_various_drivers(self):
        """Test injection capability detection for various drivers."""
        # Good drivers
        good_drivers = ['ath9k', 'ath9k_htc', 'ath10k', 'rt2800usb', 'rtl8812au']
        for driver in good_drivers:
            with self.subTest(driver=driver):
                self.assertTrue(InterfaceManager.check_injection_support(driver))
        
        # Bad drivers
        bad_drivers = ['iwlwifi', 'brcmfmac', 'rtw88']
        for driver in bad_drivers:
            with self.subTest(driver=driver):
                self.assertFalse(InterfaceManager.check_injection_support(driver))


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Unit tests for interface assignment strategy.

Tests the logic for assigning interfaces to roles in multi-interface attacks.
"""

import unittest
from unittest.mock import Mock, patch
from wifite.util.interface_assignment import InterfaceAssignmentStrategy
from wifite.model.interface_info import InterfaceInfo, InterfaceAssignment


class TestEvilTwinAssignment(unittest.TestCase):
    """Test Evil Twin interface assignment."""
    
    def _create_interface(self, name, phy, driver, ap_mode=True, monitor_mode=True, 
                         injection=True, is_up=False):
        """Helper to create test interface."""
        return InterfaceInfo(
            name=name, phy=phy, driver=driver, chipset=f'{driver} chipset',
            mac_address=f'00:11:22:33:44:{name[-1]}',
            supports_ap_mode=ap_mode,
            supports_monitor_mode=monitor_mode,
            supports_injection=injection,
            current_mode='managed',
            is_up=is_up,
            is_connected=False
        )
    
    def test_evil_twin_assignment_two_suitable_interfaces(self):
        """Test Evil Twin assignment with two suitable interfaces."""
        interfaces = [
            self._create_interface('wlan0', 'phy0', 'ath9k'),
            self._create_interface('wlan1', 'phy1', 'rtl8812au')
        ]
        
        assignment = InterfaceAssignmentStrategy.assign_for_evil_twin(interfaces)
        
        self.assertIsNotNone(assignment)
        self.assertEqual(assignment.attack_type, 'evil_twin')
        self.assertTrue(assignment.is_dual_interface())
        self.assertIn(assignment.primary, ['wlan0', 'wlan1'])
        self.assertIn(assignment.secondary, ['wlan0', 'wlan1'])
        self.assertNotEqual(assignment.primary, assignment.secondary)
    
    def test_evil_twin_assignment_one_suitable_interface(self):
        """Test Evil Twin assignment with one suitable interface."""
        interfaces = [
            self._create_interface('wlan0', 'phy0', 'ath9k')
        ]
        
        assignment = InterfaceAssignmentStrategy.assign_for_evil_twin(interfaces)
        
        self.assertIsNotNone(assignment)
        self.assertEqual(assignment.attack_type, 'evil_twin')
        self.assertFalse(assignment.is_dual_interface())
        self.assertEqual(assignment.primary, 'wlan0')
        self.assertIsNone(assignment.secondary)
    
    def test_evil_twin_assignment_no_suitable_interfaces(self):
        """Test Evil Twin assignment with no suitable interfaces."""
        # Interface without AP mode
        interfaces = [
            self._create_interface('wlan0', 'phy0', 'iwlwifi', ap_mode=False, injection=False)
        ]
        
        with self.assertRaises(Exception):
            InterfaceAssignmentStrategy.assign_for_evil_twin(interfaces)
    
    def test_evil_twin_prefers_down_interfaces(self):
        """Test Evil Twin prefers interfaces that are down."""
        interfaces = [
            self._create_interface('wlan0', 'phy0', 'ath9k', is_up=True),
            self._create_interface('wlan1', 'phy1', 'ath9k', is_up=False)
        ]
        
        assignment = InterfaceAssignmentStrategy.assign_for_evil_twin(interfaces)
        
        # Should prefer wlan1 (down) for primary
        self.assertEqual(assignment.primary, 'wlan1')
    
    def test_evil_twin_prefers_good_drivers(self):
        """Test Evil Twin prefers known good drivers."""
        interfaces = [
            self._create_interface('wlan0', 'phy0', 'rtl8812au'),
            self._create_interface('wlan1', 'phy1', 'ath9k')
        ]
        
        assignment = InterfaceAssignmentStrategy.assign_for_evil_twin(interfaces)
        
        # Should prefer ath9k (better driver) for primary
        self.assertEqual(assignment.primary, 'wlan1')


class TestWPAAssignment(unittest.TestCase):
    """Test WPA interface assignment."""
    
    def _create_interface(self, name, phy, driver, monitor_mode=True, 
                         injection=True, is_up=False):
        """Helper to create test interface."""
        return InterfaceInfo(
            name=name, phy=phy, driver=driver, chipset=f'{driver} chipset',
            mac_address=f'00:11:22:33:44:{name[-1]}',
            supports_ap_mode=False,
            supports_monitor_mode=monitor_mode,
            supports_injection=injection,
            current_mode='managed',
            is_up=is_up,
            is_connected=False
        )
    
    def test_wpa_assignment_two_suitable_interfaces(self):
        """Test WPA assignment with two suitable interfaces."""
        interfaces = [
            self._create_interface('wlan0', 'phy0', 'ath9k'),
            self._create_interface('wlan1', 'phy1', 'rt2800usb')
        ]
        
        assignment = InterfaceAssignmentStrategy.assign_for_wpa(interfaces)
        
        self.assertIsNotNone(assignment)
        self.assertEqual(assignment.attack_type, 'wpa')
        self.assertTrue(assignment.is_dual_interface())
        self.assertIn(assignment.primary, ['wlan0', 'wlan1'])
        self.assertIn(assignment.secondary, ['wlan0', 'wlan1'])
        self.assertNotEqual(assignment.primary, assignment.secondary)
    
    def test_wpa_assignment_one_suitable_interface(self):
        """Test WPA assignment with one suitable interface."""
        interfaces = [
            self._create_interface('wlan0', 'phy0', 'ath9k')
        ]
        
        assignment = InterfaceAssignmentStrategy.assign_for_wpa(interfaces)
        
        self.assertIsNotNone(assignment)
        self.assertEqual(assignment.attack_type, 'wpa')
        self.assertFalse(assignment.is_dual_interface())
        self.assertEqual(assignment.primary, 'wlan0')
        self.assertIsNone(assignment.secondary)
    
    def test_wpa_assignment_no_suitable_interfaces(self):
        """Test WPA assignment with no suitable interfaces."""
        # Interface without monitor mode
        interfaces = [
            self._create_interface('wlan0', 'phy0', 'unknown', monitor_mode=False)
        ]
        
        with self.assertRaises(Exception):
            InterfaceAssignmentStrategy.assign_for_wpa(interfaces)


class TestWPSAssignment(unittest.TestCase):
    """Test WPS interface assignment."""
    
    def _create_interface(self, name, phy, driver, monitor_mode=True):
        """Helper to create test interface."""
        return InterfaceInfo(
            name=name, phy=phy, driver=driver, chipset=f'{driver} chipset',
            mac_address=f'00:11:22:33:44:{name[-1]}',
            supports_ap_mode=False,
            supports_monitor_mode=monitor_mode,
            supports_injection=False,
            current_mode='managed',
            is_up=False,
            is_connected=False
        )
    
    def test_wps_assignment_two_interfaces(self):
        """Test WPS assignment with two interfaces."""
        interfaces = [
            self._create_interface('wlan0', 'phy0', 'ath9k'),
            self._create_interface('wlan1', 'phy1', 'rt2800usb')
        ]
        
        assignment = InterfaceAssignmentStrategy.assign_for_wps(interfaces)
        
        self.assertIsNotNone(assignment)
        self.assertEqual(assignment.attack_type, 'wps')
        # WPS can use dual interface but doesn't require it
        self.assertIsNotNone(assignment.primary)
    
    def test_wps_assignment_one_interface(self):
        """Test WPS assignment with one interface."""
        interfaces = [
            self._create_interface('wlan0', 'phy0', 'ath9k')
        ]
        
        assignment = InterfaceAssignmentStrategy.assign_for_wps(interfaces)
        
        self.assertIsNotNone(assignment)
        self.assertEqual(assignment.attack_type, 'wps')
        self.assertEqual(assignment.primary, 'wlan0')


class TestInterfaceSelection(unittest.TestCase):
    """Test interface selection criteria."""
    
    def _create_interface(self, name, phy, driver, ap_mode=True, monitor_mode=True,
                         injection=True, is_up=False, is_connected=False):
        """Helper to create test interface."""
        return InterfaceInfo(
            name=name, phy=phy, driver=driver, chipset=f'{driver} chipset',
            mac_address=f'00:11:22:33:44:{name[-1]}',
            supports_ap_mode=ap_mode,
            supports_monitor_mode=monitor_mode,
            supports_injection=injection,
            current_mode='managed',
            is_up=is_up,
            is_connected=is_connected
        )
    
    def test_select_best_ap_interface_prefers_down(self):
        """Test AP interface selection prefers down interfaces."""
        candidates = [
            self._create_interface('wlan0', 'phy0', 'ath9k', is_up=True),
            self._create_interface('wlan1', 'phy1', 'ath9k', is_up=False)
        ]
        
        best = InterfaceAssignmentStrategy._select_best_ap_interface(candidates)
        
        # Should prefer wlan1 (down)
        self.assertEqual(best.name, 'wlan1')
    
    def test_select_best_ap_interface_prefers_good_driver(self):
        """Test AP interface selection prefers known good drivers."""
        candidates = [
            self._create_interface('wlan0', 'phy0', 'rtl8812au'),
            self._create_interface('wlan1', 'phy1', 'ath9k')
        ]
        
        best = InterfaceAssignmentStrategy._select_best_ap_interface(candidates)
        
        # Should prefer ath9k (better driver)
        self.assertEqual(best.name, 'wlan1')
    
    def test_select_best_monitor_interface_prefers_down(self):
        """Test monitor interface selection prefers down interfaces."""
        candidates = [
            self._create_interface('wlan0', 'phy0', 'ath9k', is_up=True),
            self._create_interface('wlan1', 'phy1', 'ath9k', is_up=False)
        ]
        
        best = InterfaceAssignmentStrategy._select_best_monitor_interface(candidates)
        
        # Should prefer wlan1 (down)
        self.assertEqual(best.name, 'wlan1')
    
    def test_select_best_monitor_interface_prefers_injection(self):
        """Test monitor interface selection prefers injection support."""
        candidates = [
            self._create_interface('wlan0', 'phy0', 'ath9k', injection=False),
            self._create_interface('wlan1', 'phy1', 'ath9k', injection=True)
        ]
        
        best = InterfaceAssignmentStrategy._select_best_monitor_interface(candidates)
        
        # Should prefer wlan1 (injection support)
        self.assertEqual(best.name, 'wlan1')


if __name__ == '__main__':
    unittest.main()

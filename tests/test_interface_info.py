#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Unit tests for InterfaceInfo and InterfaceAssignment data models.

Tests the data models used for dual wireless device support.
"""

import unittest
from wifite.model.interface_info import InterfaceInfo, InterfaceAssignment


class TestInterfaceInfo(unittest.TestCase):
    """Test InterfaceInfo data model."""
    
    def test_interface_info_creation_all_fields(self):
        """Test InterfaceInfo creation with all fields."""
        iface = InterfaceInfo(
            name='wlan0',
            phy='phy0',
            driver='ath9k',
            chipset='Atheros AR9271',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed',
            is_up=True,
            is_connected=False,
            frequency=2437.0,
            channel=6,
            tx_power=20
        )
        
        # Basic identification
        self.assertEqual(iface.name, 'wlan0')
        self.assertEqual(iface.phy, 'phy0')
        self.assertEqual(iface.driver, 'ath9k')
        self.assertEqual(iface.chipset, 'Atheros AR9271')
        self.assertEqual(iface.mac_address, '00:11:22:33:44:55')
        
        # Capabilities
        self.assertTrue(iface.supports_ap_mode)
        self.assertTrue(iface.supports_monitor_mode)
        self.assertTrue(iface.supports_injection)
        
        # Current state
        self.assertEqual(iface.current_mode, 'managed')
        self.assertTrue(iface.is_up)
        self.assertFalse(iface.is_connected)
        
        # Optional details
        self.assertEqual(iface.frequency, 2437.0)
        self.assertEqual(iface.channel, 6)
        self.assertEqual(iface.tx_power, 20)
    
    def test_interface_info_creation_minimal_fields(self):
        """Test InterfaceInfo creation with minimal required fields."""
        iface = InterfaceInfo(
            name='wlan1',
            phy='phy1',
            driver='rtl8812au',
            chipset='Realtek RTL8812AU',
            mac_address='AA:BB:CC:DD:EE:FF',
            supports_ap_mode=False,
            supports_monitor_mode=True,
            supports_injection=False,
            current_mode='monitor',
            is_up=False,
            is_connected=False
        )
        
        self.assertEqual(iface.name, 'wlan1')
        self.assertFalse(iface.supports_ap_mode)
        self.assertTrue(iface.supports_monitor_mode)
        self.assertFalse(iface.supports_injection)
        self.assertIsNone(iface.frequency)
        self.assertIsNone(iface.channel)
        self.assertIsNone(iface.tx_power)
    
    def test_can_be_ap_with_full_capabilities(self):
        """Test can_be_ap() returns True when interface has AP mode and injection."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        self.assertTrue(iface.can_be_ap())
    
    def test_can_be_ap_without_injection(self):
        """Test can_be_ap() returns False when interface lacks injection support."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='iwlwifi', chipset='Intel',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=False,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        self.assertFalse(iface.can_be_ap())
    
    def test_can_be_ap_without_ap_mode(self):
        """Test can_be_ap() returns False when interface lacks AP mode support."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='rtl8812au', chipset='Realtek',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=False,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        self.assertFalse(iface.can_be_ap())
    
    def test_can_be_ap_without_both(self):
        """Test can_be_ap() returns False when interface lacks both AP mode and injection."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='brcmfmac', chipset='Broadcom',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=False,
            supports_monitor_mode=True,
            supports_injection=False,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        self.assertFalse(iface.can_be_ap())
    
    def test_can_be_monitor_with_full_capabilities(self):
        """Test can_be_monitor() returns True when interface has monitor mode and injection."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        self.assertTrue(iface.can_be_monitor())
    
    def test_can_be_monitor_without_injection(self):
        """Test can_be_monitor() returns False when interface lacks injection support."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='iwlwifi', chipset='Intel',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=False,
            supports_monitor_mode=True,
            supports_injection=False,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        self.assertFalse(iface.can_be_monitor())
    
    def test_can_be_monitor_without_monitor_mode(self):
        """Test can_be_monitor() returns False when interface lacks monitor mode support."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='unknown', chipset='Unknown',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=False,
            supports_monitor_mode=False,
            supports_injection=True,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        self.assertFalse(iface.can_be_monitor())
    
    def test_is_suitable_for_evil_twin_ap(self):
        """Test is_suitable_for_evil_twin_ap() method."""
        # Suitable interface
        iface_suitable = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed', is_up=False, is_connected=False
        )
        self.assertTrue(iface_suitable.is_suitable_for_evil_twin_ap())
        
        # Unsuitable interface (no AP mode)
        iface_unsuitable = InterfaceInfo(
            name='wlan1', phy='phy1', driver='iwlwifi', chipset='Intel',
            mac_address='AA:BB:CC:DD:EE:FF',
            supports_ap_mode=False,
            supports_monitor_mode=True,
            supports_injection=False,
            current_mode='managed', is_up=False, is_connected=False
        )
        self.assertFalse(iface_unsuitable.is_suitable_for_evil_twin_ap())
    
    def test_is_suitable_for_evil_twin_deauth(self):
        """Test is_suitable_for_evil_twin_deauth() method."""
        # Suitable interface
        iface_suitable = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed', is_up=False, is_connected=False
        )
        self.assertTrue(iface_suitable.is_suitable_for_evil_twin_deauth())
        
        # Unsuitable interface (no injection)
        iface_unsuitable = InterfaceInfo(
            name='wlan1', phy='phy1', driver='iwlwifi', chipset='Intel',
            mac_address='AA:BB:CC:DD:EE:FF',
            supports_ap_mode=False,
            supports_monitor_mode=True,
            supports_injection=False,
            current_mode='managed', is_up=False, is_connected=False
        )
        self.assertFalse(iface_unsuitable.is_suitable_for_evil_twin_deauth())
    
    def test_is_suitable_for_wpa_capture(self):
        """Test is_suitable_for_wpa_capture() method."""
        # Suitable interface (only needs monitor mode)
        iface_suitable = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=False,
            supports_monitor_mode=True,
            supports_injection=False,
            current_mode='managed', is_up=False, is_connected=False
        )
        self.assertTrue(iface_suitable.is_suitable_for_wpa_capture())
        
        # Unsuitable interface (no monitor mode)
        iface_unsuitable = InterfaceInfo(
            name='wlan1', phy='phy1', driver='unknown', chipset='Unknown',
            mac_address='AA:BB:CC:DD:EE:FF',
            supports_ap_mode=False,
            supports_monitor_mode=False,
            supports_injection=False,
            current_mode='managed', is_up=False, is_connected=False
        )
        self.assertFalse(iface_unsuitable.is_suitable_for_wpa_capture())
    
    def test_is_suitable_for_wpa_deauth(self):
        """Test is_suitable_for_wpa_deauth() method."""
        # Suitable interface (needs monitor mode and injection)
        iface_suitable = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=False,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed', is_up=False, is_connected=False
        )
        self.assertTrue(iface_suitable.is_suitable_for_wpa_deauth())
        
        # Unsuitable interface (no injection)
        iface_unsuitable = InterfaceInfo(
            name='wlan1', phy='phy1', driver='iwlwifi', chipset='Intel',
            mac_address='AA:BB:CC:DD:EE:FF',
            supports_ap_mode=False,
            supports_monitor_mode=True,
            supports_injection=False,
            current_mode='managed', is_up=False, is_connected=False
        )
        self.assertFalse(iface_unsuitable.is_suitable_for_wpa_deauth())
    
    def test_get_capability_summary_full_capabilities(self):
        """Test get_capability_summary() with all capabilities."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        summary = iface.get_capability_summary()
        self.assertIn('Monitor', summary)
        self.assertIn('AP', summary)
        self.assertIn('Injection', summary)
    
    def test_get_capability_summary_partial_capabilities(self):
        """Test get_capability_summary() with partial capabilities."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='iwlwifi', chipset='Intel',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=False,
            supports_monitor_mode=True,
            supports_injection=False,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        summary = iface.get_capability_summary()
        self.assertIn('Monitor', summary)
        self.assertNotIn('AP', summary)
        self.assertNotIn('Injection', summary)
    
    def test_get_capability_summary_no_capabilities(self):
        """Test get_capability_summary() with no capabilities."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='unknown', chipset='Unknown',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=False,
            supports_monitor_mode=False,
            supports_injection=False,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        summary = iface.get_capability_summary()
        self.assertEqual(summary, 'Limited capabilities')
    
    def test_get_status_summary_interface_up(self):
        """Test get_status_summary() for interface that is up."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='monitor',
            is_up=True,
            is_connected=False,
            channel=6
        )
        
        summary = iface.get_status_summary()
        self.assertIn('Mode: monitor', summary)
        self.assertIn('Up', summary)
        self.assertIn('Ch 6', summary)
    
    def test_get_status_summary_interface_down(self):
        """Test get_status_summary() for interface that is down."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed',
            is_up=False,
            is_connected=False
        )
        
        summary = iface.get_status_summary()
        self.assertIn('Mode: managed', summary)
        self.assertIn('Down', summary)
    
    def test_get_status_summary_connected(self):
        """Test get_status_summary() for connected interface."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed',
            is_up=True,
            is_connected=True
        )
        
        summary = iface.get_status_summary()
        self.assertIn('Connected', summary)
    
    def test_str_representation(self):
        """Test __str__() method."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros AR9271',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        str_repr = str(iface)
        self.assertIn('wlan0', str_repr)
        self.assertIn('Atheros AR9271', str_repr)
    
    def test_repr_representation(self):
        """Test __repr__() method."""
        iface = InterfaceInfo(
            name='wlan0', phy='phy0', driver='ath9k', chipset='Atheros',
            mac_address='00:11:22:33:44:55',
            supports_ap_mode=True,
            supports_monitor_mode=True,
            supports_injection=True,
            current_mode='managed', is_up=False, is_connected=False
        )
        
        repr_str = repr(iface)
        self.assertIn('InterfaceInfo', repr_str)
        self.assertIn('name=wlan0', repr_str)
        self.assertIn('phy=phy0', repr_str)
        self.assertIn('driver=ath9k', repr_str)


class TestInterfaceAssignment(unittest.TestCase):
    """Test InterfaceAssignment data model."""
    
    def test_interface_assignment_dual_interface(self):
        """Test InterfaceAssignment creation for dual interface."""
        assignment = InterfaceAssignment(
            attack_type='evil_twin',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Rogue AP',
            secondary_role='Deauth'
        )
        
        self.assertEqual(assignment.attack_type, 'evil_twin')
        self.assertEqual(assignment.primary, 'wlan0')
        self.assertEqual(assignment.secondary, 'wlan1')
        self.assertEqual(assignment.primary_role, 'Rogue AP')
        self.assertEqual(assignment.secondary_role, 'Deauth')
    
    def test_interface_assignment_single_interface(self):
        """Test InterfaceAssignment creation for single interface."""
        assignment = InterfaceAssignment(
            attack_type='wpa',
            primary='wlan0',
            secondary=None,
            primary_role='Capture + Deauth',
            secondary_role=None
        )
        
        self.assertEqual(assignment.attack_type, 'wpa')
        self.assertEqual(assignment.primary, 'wlan0')
        self.assertIsNone(assignment.secondary)
        self.assertEqual(assignment.primary_role, 'Capture + Deauth')
        self.assertIsNone(assignment.secondary_role)
    
    def test_is_dual_interface_true(self):
        """Test is_dual_interface() returns True for dual interface assignment."""
        assignment = InterfaceAssignment(
            attack_type='evil_twin',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Rogue AP',
            secondary_role='Deauth'
        )
        
        self.assertTrue(assignment.is_dual_interface())
    
    def test_is_dual_interface_false(self):
        """Test is_dual_interface() returns False for single interface assignment."""
        assignment = InterfaceAssignment(
            attack_type='wpa',
            primary='wlan0',
            secondary=None,
            primary_role='Capture + Deauth'
        )
        
        self.assertFalse(assignment.is_dual_interface())
    
    def test_get_interfaces_dual(self):
        """Test get_interfaces() returns both interfaces for dual interface."""
        assignment = InterfaceAssignment(
            attack_type='evil_twin',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Rogue AP',
            secondary_role='Deauth'
        )
        
        interfaces = assignment.get_interfaces()
        self.assertEqual(len(interfaces), 2)
        self.assertIn('wlan0', interfaces)
        self.assertIn('wlan1', interfaces)
    
    def test_get_interfaces_single(self):
        """Test get_interfaces() returns only primary for single interface."""
        assignment = InterfaceAssignment(
            attack_type='wpa',
            primary='wlan0',
            secondary=None,
            primary_role='Capture + Deauth'
        )
        
        interfaces = assignment.get_interfaces()
        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0], 'wlan0')
    
    def test_get_assignment_summary_dual(self):
        """Test get_assignment_summary() for dual interface."""
        assignment = InterfaceAssignment(
            attack_type='evil_twin',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Rogue AP',
            secondary_role='Deauth'
        )
        
        summary = assignment.get_assignment_summary()
        self.assertIn('wlan0', summary)
        self.assertIn('wlan1', summary)
        self.assertIn('Rogue AP', summary)
        self.assertIn('Deauth', summary)
    
    def test_get_assignment_summary_single(self):
        """Test get_assignment_summary() for single interface."""
        assignment = InterfaceAssignment(
            attack_type='wpa',
            primary='wlan0',
            secondary=None,
            primary_role='Capture + Deauth'
        )
        
        summary = assignment.get_assignment_summary()
        self.assertIn('wlan0', summary)
        self.assertIn('Capture + Deauth', summary)
        self.assertNotIn('wlan1', summary)
    
    def test_str_representation(self):
        """Test __str__() method."""
        assignment = InterfaceAssignment(
            attack_type='evil_twin',
            primary='wlan0',
            secondary='wlan1',
            primary_role='Rogue AP',
            secondary_role='Deauth'
        )
        
        str_repr = str(assignment)
        self.assertIn('Evil_Twin', str_repr)  # title() converts to Evil_Twin
        self.assertIn('wlan0', str_repr)
        self.assertIn('wlan1', str_repr)


if __name__ == '__main__':
    unittest.main()

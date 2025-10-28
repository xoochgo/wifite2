#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, '..')

from wifite.tools.hcxdumptool import HcxDumpTool
from wifite.config import Configuration


class TestHcxDumpToolMultiInterface(unittest.TestCase):
    """Test suite for HcxDumpTool multi-interface support"""

    def setUp(self):
        """Set up test fixtures"""
        # Mock configuration to avoid argument parsing issues
        Configuration.interface = None

    @patch('wifite.tools.hcxdumptool.Configuration.initialize')
    def test_single_interface_string(self, mock_config_init):
        """Test single interface initialization with string (backward compatibility)"""
        tool = HcxDumpTool(interface='wlan0', output_file='/tmp/test.pcapng')
        
        # Should store as list internally
        self.assertEqual(tool.interfaces, ['wlan0'])
        # Should maintain backward compatibility with single interface attribute
        self.assertEqual(tool.interface, 'wlan0')

    @patch('wifite.tools.hcxdumptool.Configuration.initialize')
    def test_dual_interface_list(self, mock_config_init):
        """Test dual interface initialization with list"""
        tool = HcxDumpTool(interface=['wlan0', 'wlan1'], output_file='/tmp/test.pcapng')
        
        # Should store both interfaces
        self.assertEqual(tool.interfaces, ['wlan0', 'wlan1'])
        # First interface should be primary
        self.assertEqual(tool.interface, 'wlan0')

    @patch('wifite.tools.hcxdumptool.Configuration.initialize')
    def test_triple_interface_list(self, mock_config_init):
        """Test triple interface initialization with list"""
        tool = HcxDumpTool(interface=['wlan0', 'wlan1', 'wlan2'], output_file='/tmp/test.pcapng')
        
        # Should store all three interfaces
        self.assertEqual(tool.interfaces, ['wlan0', 'wlan1', 'wlan2'])
        # First interface should be primary
        self.assertEqual(tool.interface, 'wlan0')

    @patch('wifite.tools.hcxdumptool.Configuration.initialize')
    def test_empty_list_raises_error(self, mock_config_init):
        """Test that empty interface list raises ValueError"""
        with self.assertRaises(ValueError) as context:
            HcxDumpTool(interface=[], output_file='/tmp/test.pcapng')
        
        self.assertIn('cannot be empty', str(context.exception))

    @patch('wifite.tools.hcxdumptool.Configuration.initialize')
    def test_invalid_type_raises_error(self, mock_config_init):
        """Test that invalid interface parameter type raises ValueError"""
        with self.assertRaises(ValueError) as context:
            HcxDumpTool(interface=123, output_file='/tmp/test.pcapng')
        
        self.assertIn('must be a string or list', str(context.exception))

    @patch('wifite.tools.hcxdumptool.Configuration.initialize')
    def test_none_interface_uses_config(self, mock_config_init):
        """Test that None interface uses Configuration.interface"""
        Configuration.interface = 'wlan0'
        tool = HcxDumpTool(interface=None, output_file='/tmp/test.pcapng')
        
        self.assertEqual(tool.interfaces, ['wlan0'])
        self.assertEqual(tool.interface, 'wlan0')

    @patch('wifite.tools.hcxdumptool.Configuration.initialize')
    def test_none_interface_no_config_raises_error(self, mock_config_init):
        """Test that None interface with no config raises error"""
        Configuration.interface = None
        
        with self.assertRaises(Exception) as context:
            HcxDumpTool(interface=None, output_file='/tmp/test.pcapng')
        
        self.assertIn('must be defined', str(context.exception))

    @patch('wifite.tools.hcxdumptool.Configuration.initialize')
    @patch('wifite.tools.hcxdumptool.Process')
    def test_command_building_single_interface(self, mock_process, mock_config_init):
        """Test command building with single interface"""
        mock_proc_instance = MagicMock()
        mock_proc_instance.pid.pid = 12345
        mock_proc_instance.poll.return_value = None
        mock_process.return_value = mock_proc_instance
        
        tool = HcxDumpTool(interface='wlan0', channel=6, output_file='/tmp/test.pcapng')
        
        with tool:
            # Get the command that was passed to Process
            call_args = mock_process.call_args[0][0]
            
            # Should have single -i flag
            self.assertIn('-i', call_args)
            i_index = call_args.index('-i')
            self.assertEqual(call_args[i_index + 1], 'wlan0')
            
            # Should have output file
            self.assertIn('-o', call_args)
            o_index = call_args.index('-o')
            self.assertEqual(call_args[o_index + 1], '/tmp/test.pcapng')
            
            # Should have channel
            self.assertIn('-c', call_args)
            c_index = call_args.index('-c')
            self.assertEqual(call_args[c_index + 1], '6')

    @patch('wifite.tools.hcxdumptool.Configuration.initialize')
    @patch('wifite.tools.hcxdumptool.Process')
    def test_command_building_dual_interface(self, mock_process, mock_config_init):
        """Test command building with dual interfaces"""
        mock_proc_instance = MagicMock()
        mock_proc_instance.pid.pid = 12345
        mock_proc_instance.poll.return_value = None
        mock_process.return_value = mock_proc_instance
        
        tool = HcxDumpTool(interface=['wlan0', 'wlan1'], channel=6, output_file='/tmp/test.pcapng')
        
        with tool:
            # Get the command that was passed to Process
            call_args = mock_process.call_args[0][0]
            
            # Should have two -i flags
            i_indices = [i for i, x in enumerate(call_args) if x == '-i']
            self.assertEqual(len(i_indices), 2)
            
            # Should have both interfaces
            self.assertEqual(call_args[i_indices[0] + 1], 'wlan0')
            self.assertEqual(call_args[i_indices[1] + 1], 'wlan1')
            
            # Should have output file
            self.assertIn('-o', call_args)

    @patch('wifite.tools.hcxdumptool.Configuration.initialize')
    @patch('wifite.tools.hcxdumptool.Process')
    def test_command_building_triple_interface(self, mock_process, mock_config_init):
        """Test command building with triple interfaces"""
        mock_proc_instance = MagicMock()
        mock_proc_instance.pid.pid = 12345
        mock_proc_instance.poll.return_value = None
        mock_process.return_value = mock_proc_instance
        
        tool = HcxDumpTool(interface=['wlan0', 'wlan1', 'wlan2'], output_file='/tmp/test.pcapng')
        
        with tool:
            # Get the command that was passed to Process
            call_args = mock_process.call_args[0][0]
            
            # Should have three -i flags
            i_indices = [i for i, x in enumerate(call_args) if x == '-i']
            self.assertEqual(len(i_indices), 3)
            
            # Should have all three interfaces
            self.assertEqual(call_args[i_indices[0] + 1], 'wlan0')
            self.assertEqual(call_args[i_indices[1] + 1], 'wlan1')
            self.assertEqual(call_args[i_indices[2] + 1], 'wlan2')


if __name__ == '__main__':
    unittest.main()

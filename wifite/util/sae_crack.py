#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SAE Cracking Module

This module provides functionality to crack WPA3-SAE handshakes using hashcat.
Supports dictionary attacks, rule-based attacks, and mask attacks.
"""

import os
import re
import time
from typing import Optional, Dict, Any, List

from ..config import Configuration
from ..model.sae_handshake import SAEHandshake
from ..tools.hashcat import Hashcat, HcxPcapngTool
from ..util.color import Color
from ..util.process import Process


class SAECracker:
    """
    Handles cracking of WPA3-SAE handshakes using hashcat mode 22000.
    
    Supports:
    - Dictionary attacks
    - Rule-based attacks
    - Mask attacks
    - Progress monitoring
    - GPU acceleration
    """
    
    # Hashcat mode for WPA3-SAE
    HASHCAT_MODE = '22000'
    
    def __init__(self, sae_handshake: SAEHandshake, wordlist: Optional[str] = None):
        """
        Initialize SAE cracker.
        
        Args:
            sae_handshake: SAEHandshake object to crack
            wordlist: Path to wordlist file (uses config default if None)
        """
        self.sae_handshake = sae_handshake
        self.wordlist = wordlist or Configuration.wordlist
        self.hash_file = None
        self.cracked_key = None
        self.progress_data = {}
        
    @staticmethod
    def crack_sae_handshake(
        sae_handshake: SAEHandshake,
        wordlist: Optional[str] = None,
        rules: Optional[str] = None,
        mask: Optional[str] = None,
        show_command: bool = False,
        verbose: bool = True
    ) -> Optional[str]:
        """
        Crack a SAE handshake using hashcat mode 22000.
        
        Args:
            sae_handshake: SAEHandshake object to crack
            wordlist: Path to wordlist file
            rules: Path to hashcat rules file (optional)
            mask: Hashcat mask for mask attack (optional)
            show_command: Whether to display the hashcat command
            verbose: Whether to display progress information
        
        Returns:
            Cracked password if successful, None otherwise
        """
        cracker = SAECracker(sae_handshake, wordlist)
        
        # Convert handshake to hashcat format
        if not cracker._prepare_hash_file():
            return None
        
        # Determine attack type
        if mask:
            return cracker._crack_with_mask(mask, show_command, verbose)
        elif rules:
            return cracker._crack_with_rules(rules, show_command, verbose)
        else:
            return cracker._crack_with_wordlist(show_command, verbose)
    
    def _prepare_hash_file(self) -> bool:
        """
        Convert SAE handshake to hashcat format.
        
        Returns:
            True if conversion successful, False otherwise
        """
        if not Process.exists('hcxpcapngtool'):
            Color.pl('{!} {R}hcxpcapngtool not found - cannot convert SAE handshake{W}')
            return False
        
        # Generate hash file
        essid_part = self.sae_handshake.essid.replace(' ', '_') if self.sae_handshake.essid else 'unknown'
        bssid_part = self.sae_handshake.bssid.replace(':', '-') if self.sae_handshake.bssid else 'unknown'
        self.hash_file = Configuration.temp(f'sae_{essid_part}_{bssid_part}.22000')
        
        try:
            command = [
                'hcxpcapngtool',
                '-o', self.hash_file,
                self.sae_handshake.capfile
            ]
            
            # Add BSSID filter
            if self.sae_handshake.bssid:
                command.extend(['--bssid', self.sae_handshake.bssid.replace(':', '')])
            
            # Add ESSID filter
            if self.sae_handshake.essid:
                command.extend(['--essid', self.sae_handshake.essid])
            
            proc = Process(command, devnull=False)
            proc.wait()
            
            # Verify hash file was created
            if not os.path.exists(self.hash_file) or os.path.getsize(self.hash_file) == 0:
                Color.pl('{!} {R}Failed to generate hash file from SAE handshake{W}')
                return False
            
            return True
            
        except Exception as e:
            Color.pl('{!} {R}Error preparing hash file:{W} %s' % str(e))
            return False
    
    def _crack_with_wordlist(self, show_command: bool = False, verbose: bool = True) -> Optional[str]:
        """
        Crack SAE handshake using dictionary attack.
        
        Args:
            show_command: Whether to display the hashcat command
            verbose: Whether to display progress
        
        Returns:
            Cracked password if successful, None otherwise
        """
        if not self.wordlist or not os.path.exists(self.wordlist):
            Color.pl('{!} {R}Wordlist not found:{W} %s' % self.wordlist)
            return None
        
        if verbose:
            Color.pl('{+} {C}Attempting to crack WPA3-SAE handshake using dictionary attack{W}')
        
        # Try cracking (first attempt)
        key = self._run_hashcat(
            attack_mode='0',  # Dictionary attack
            wordlist=self.wordlist,
            show_command=show_command,
            verbose=verbose
        )
        
        if key:
            return key
        
        # Try --show to check if already in pot file
        key = self._check_pot_file(show_command)
        
        return key
    
    def _crack_with_rules(self, rules: str, show_command: bool = False, verbose: bool = True) -> Optional[str]:
        """
        Crack SAE handshake using rule-based attack.
        
        Args:
            rules: Path to hashcat rules file
            show_command: Whether to display the hashcat command
            verbose: Whether to display progress
        
        Returns:
            Cracked password if successful, None otherwise
        """
        if not os.path.exists(rules):
            Color.pl('{!} {R}Rules file not found:{W} %s' % rules)
            return None
        
        if verbose:
            Color.pl('{+} {C}Attempting to crack WPA3-SAE handshake using rule-based attack{W}')
        
        key = self._run_hashcat(
            attack_mode='0',  # Dictionary attack with rules
            wordlist=self.wordlist,
            rules=rules,
            show_command=show_command,
            verbose=verbose
        )
        
        if not key:
            key = self._check_pot_file(show_command)
        
        return key
    
    def _crack_with_mask(self, mask: str, show_command: bool = False, verbose: bool = True) -> Optional[str]:
        """
        Crack SAE handshake using mask attack.
        
        Args:
            mask: Hashcat mask (e.g., '?d?d?d?d?d?d?d?d' for 8 digits)
            show_command: Whether to display the hashcat command
            verbose: Whether to display progress
        
        Returns:
            Cracked password if successful, None otherwise
        """
        if verbose:
            Color.pl('{+} {C}Attempting to crack WPA3-SAE handshake using mask attack{W}')
        
        key = self._run_hashcat(
            attack_mode='3',  # Mask attack
            mask=mask,
            show_command=show_command,
            verbose=verbose
        )
        
        if not key:
            key = self._check_pot_file(show_command)
        
        return key
    
    def _run_hashcat(
        self,
        attack_mode: str,
        wordlist: Optional[str] = None,
        rules: Optional[str] = None,
        mask: Optional[str] = None,
        show_command: bool = False,
        verbose: bool = True
    ) -> Optional[str]:
        """
        Run hashcat with specified parameters.
        
        Args:
            attack_mode: Hashcat attack mode (0=dictionary, 3=mask)
            wordlist: Path to wordlist (for dictionary attacks)
            rules: Path to rules file (optional)
            mask: Mask pattern (for mask attacks)
            show_command: Whether to display the command
            verbose: Whether to display progress
        
        Returns:
            Cracked password if successful, None otherwise
        """
        command = [
            'hashcat',
            '-m', self.HASHCAT_MODE,
            '-a', attack_mode,
            self.hash_file
        ]
        
        # Add wordlist for dictionary attacks
        if attack_mode == '0' and wordlist:
            command.append(wordlist)
        
        # Add mask for mask attacks
        if attack_mode == '3' and mask:
            command.append(mask)
        
        # Add rules if specified
        if rules:
            command.extend(['-r', rules])
        
        # Add GPU workload profile
        if Configuration.wpa_attack_timeout > 0:
            command.extend(['-w', '3'])  # High performance
        
        # Add force flag if needed
        if Hashcat.should_use_force():
            command.append('--force')
        
        # Add status output for progress monitoring
        if verbose:
            command.extend(['--status', '--status-timer', '5'])
        else:
            command.append('--quiet')
        
        if show_command:
            Color.pl('{+} {D}Running: {W}{P}%s{W}' % ' '.join(command))
        
        # Run hashcat
        proc = Process(command, devnull=False)
        
        if verbose:
            # Monitor progress
            self._monitor_progress(proc)
        else:
            proc.wait()
        
        # Check output for cracked password
        stdout = proc.stdout()
        stderr = proc.stderr()
        
        return self._parse_cracked_password(stdout, stderr)
    
    def _check_pot_file(self, show_command: bool = False) -> Optional[str]:
        """
        Check if password is already in hashcat pot file.
        
        Args:
            show_command: Whether to display the command
        
        Returns:
            Cracked password if found in pot file, None otherwise
        """
        command = [
            'hashcat',
            '-m', self.HASHCAT_MODE,
            self.hash_file,
            '--show'
        ]
        
        if show_command:
            Color.pl('{+} {D}Checking pot file: {W}{P}%s{W}' % ' '.join(command))
        
        proc = Process(command, devnull=False)
        stdout = proc.stdout()
        
        return self._parse_cracked_password(stdout, '')
    
    def _parse_cracked_password(self, stdout: str, stderr: str) -> Optional[str]:
        """
        Parse cracked password from hashcat output.
        
        Args:
            stdout: Hashcat stdout
            stderr: Hashcat stderr
        
        Returns:
            Cracked password if found, None otherwise
        """
        # Check for errors
        if 'No hashes loaded' in stdout or 'No hashes loaded' in stderr:
            return None
        
        # Parse output for password
        # Format: hash:password
        lines = stdout.strip().split('\n')
        for line in lines:
            # Skip status lines and headers
            if any(skip in line.lower() for skip in ['session', 'status', 'hash.mode', 'hash.target', 
                                                       'time.started', 'time.estimated', 'guess.base',
                                                       'speed.', 'recovered', 'progress', 'rejected',
                                                       'restore.point', 'candidates', 'hardware.mon']):
                continue
            
            if ':' in line and not line.startswith('The plugin') and 'hashcat.net' not in line:
                # Extract password (last part after last colon)
                parts = line.split(':')
                if len(parts) >= 2:
                    password = parts[-1].strip()
                    if password and len(password) > 0:
                        self.cracked_key = password
                        return password
        
        return None
    
    def _monitor_progress(self, proc: Process):
        """
        Monitor hashcat progress and display updates.
        
        Args:
            proc: Running hashcat process
        """
        last_update = time.time()
        update_interval = 5  # seconds
        
        while proc.poll() is None:
            time.sleep(0.5)
            
            # Update progress every interval
            if time.time() - last_update >= update_interval:
                progress = self._get_progress(proc)
                if progress:
                    self._display_progress(progress)
                last_update = time.time()
        
        # Final update
        progress = self._get_progress(proc)
        if progress:
            self._display_progress(progress)
    
    def _get_progress(self, proc: Process) -> Optional[Dict[str, Any]]:
        """
        Extract progress information from hashcat output.
        
        Args:
            proc: Running hashcat process
        
        Returns:
            Dictionary with progress data, or None if unavailable
        """
        try:
            output = proc.stdout()
            
            progress_data = {}
            
            # Parse status output
            for line in output.split('\n'):
                line = line.strip()
                
                # Extract progress percentage
                if 'Progress' in line and '/' in line:
                    match = re.search(r'(\d+)/(\d+)\s*\((\d+\.\d+)%\)', line)
                    if match:
                        progress_data['current'] = int(match.group(1))
                        progress_data['total'] = int(match.group(2))
                        progress_data['percent'] = float(match.group(3))
                
                # Extract time remaining
                if 'Time.Estimated' in line:
                    match = re.search(r'Time\.Estimated\.+:\s*(.+)', line)
                    if match:
                        progress_data['eta'] = match.group(1).strip()
                
                # Extract speed
                if 'Speed.#' in line or 'Speed.Dev' in line:
                    match = re.search(r'Speed\..*:\s*(\d+\.?\d*\s*\w+/s)', line)
                    if match:
                        progress_data['speed'] = match.group(1).strip()
                
                # Extract recovered count
                if 'Recovered' in line:
                    match = re.search(r'Recovered\.+:\s*(\d+)/(\d+)', line)
                    if match:
                        progress_data['recovered'] = int(match.group(1))
                        progress_data['total_hashes'] = int(match.group(2))
            
            return progress_data if progress_data else None
            
        except Exception:
            return None
    
    def _display_progress(self, progress: Dict[str, Any]):
        """
        Display progress information to user.
        
        Args:
            progress: Dictionary with progress data
        """
        self.progress_data = progress
        
        # Build progress message
        msg_parts = []
        
        if 'percent' in progress:
            msg_parts.append('{C}Progress:{W} {G}%.1f%%{W}' % progress['percent'])
        
        if 'speed' in progress:
            msg_parts.append('{C}Speed:{W} {G}%s{W}' % progress['speed'])
        
        if 'eta' in progress:
            msg_parts.append('{C}ETA:{W} {G}%s{W}' % progress['eta'])
        
        if 'recovered' in progress and 'total_hashes' in progress:
            msg_parts.append('{C}Recovered:{W} {G}%d{W}/{C}%d{W}' % 
                           (progress['recovered'], progress['total_hashes']))
        
        if msg_parts:
            Color.pl('{+} ' + ' | '.join(msg_parts))
    
    @staticmethod
    def check_dependencies() -> Dict[str, bool]:
        """
        Check if required tools for SAE cracking are available.
        
        Returns:
            Dictionary with tool availability status
        """
        return {
            'hashcat': Process.exists('hashcat'),
            'hcxpcapngtool': Process.exists('hcxpcapngtool')
        }
    
    @staticmethod
    def print_dependency_status():
        """Print status of required tools for SAE cracking."""
        deps = SAECracker.check_dependencies()
        
        Color.pl('\n{+} {C}SAE Cracking Tool Status:{W}')
        for tool, available in deps.items():
            status = '{G}Available{W}' if available else '{R}Not Found{W}'
            Color.pl(f'    {tool}: {status}')
        
        if not deps['hashcat']:
            Color.pl('\n{!} {O}Warning:{W} hashcat is required for SAE cracking')
            Color.pl('    Install: {C}apt install hashcat{W} or visit {C}https://hashcat.net{W}')
        
        if not deps['hcxpcapngtool']:
            Color.pl('\n{!} {O}Warning:{W} hcxpcapngtool is required for hash conversion')
            Color.pl('    Install: {C}apt install hcxtools{W}')


if __name__ == '__main__':
    # Test SAECracker functionality
    SAECracker.print_dependency_status()

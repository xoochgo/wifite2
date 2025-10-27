#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Dragonblood Vulnerability Detection

This module detects potential Dragonblood vulnerabilities in WPA3-SAE networks.
It performs passive detection only - no active exploitation.

Dragonblood vulnerabilities (CVE-2019-13377 and related):
- Timing-based side-channel attacks
- Weak SAE group configurations
- Cache-based side-channel attacks
- Denial of service vulnerabilities

References:
- https://wpa3.mathyvanhoef.com/
- https://papers.mathyvanhoef.com/dragonblood.pdf
"""

from typing import Dict, List, Optional
from ..util.color import Color


class DragonbloodDetector:
    """
    Detects potential Dragonblood vulnerabilities in WPA3 networks.
    
    Detection is based on:
    - SAE group configuration (weak groups)
    - Known vulnerable implementations
    - Configuration patterns
    """
    
    # Weak SAE groups vulnerable to timing attacks
    WEAK_SAE_GROUPS = {
        22: "1024-bit MODP (Weak - timing attack vulnerable)",
        23: "2048-bit MODP (Weak - timing attack vulnerable)", 
        24: "2048-bit MODP (Weak - timing attack vulnerable)",
        1: "256-bit Random ECP (Weak - small subgroup attack)",
        2: "384-bit Random ECP (Weak - small subgroup attack)"
    }
    
    # Recommended secure groups
    SECURE_SAE_GROUPS = {
        19: "256-bit Random ECP (Secure - recommended)",
        20: "384-bit Random ECP (Secure - recommended)",
        21: "521-bit Random ECP (Secure - recommended)"
    }
    
    # Known vulnerable implementations (pre-patch)
    VULNERABLE_PATTERNS = {
        'hostapd': {
            'versions': ['< 2.9'],
            'vulnerabilities': ['CVE-2019-13377', 'CVE-2019-13456']
        },
        'wpa_supplicant': {
            'versions': ['< 2.9'],
            'vulnerabilities': ['CVE-2019-13377']
        }
    }
    
    @staticmethod
    def check_vulnerability(wpa3_info: Dict) -> Dict:
        """
        Check if a WPA3 network is potentially vulnerable to Dragonblood.
        
        Args:
            wpa3_info: Dictionary containing WPA3 network information
                      Expected keys: sae_groups, pmf_status, transition_mode
        
        Returns:
            Dictionary with vulnerability assessment:
            {
                'vulnerable': bool,
                'risk_level': str,  # 'high', 'medium', 'low', 'none'
                'vulnerabilities': List[str],
                'weak_groups': List[int],
                'recommendations': List[str]
            }
        """
        result = {
            'vulnerable': False,
            'risk_level': 'none',
            'vulnerabilities': [],
            'weak_groups': [],
            'recommendations': []
        }
        
        if not wpa3_info:
            return result
        
        sae_groups = wpa3_info.get('sae_groups', [])
        pmf_status = wpa3_info.get('pmf_status', 'unknown')
        transition_mode = wpa3_info.get('transition_mode', False)
        
        # Check for weak SAE groups
        for group in sae_groups:
            if group in DragonbloodDetector.WEAK_SAE_GROUPS:
                result['weak_groups'].append(group)
                result['vulnerable'] = True
                result['vulnerabilities'].append(
                    f"Weak SAE Group {group}: {DragonbloodDetector.WEAK_SAE_GROUPS[group]}"
                )
        
        # Assess risk level
        if result['weak_groups']:
            # Check if any MODP groups (timing attack vulnerable)
            modp_groups = [g for g in result['weak_groups'] if g in [22, 23, 24]]
            if modp_groups:
                result['risk_level'] = 'high'
                result['vulnerabilities'].append('CVE-2019-13377: Timing-based side-channel attack')
                result['recommendations'].append(
                    'Disable MODP groups (22, 23, 24) and use only ECP groups (19, 20, 21)'
                )
            else:
                result['risk_level'] = 'medium'
                result['recommendations'].append(
                    'Use recommended SAE groups: 19 (256-bit ECP), 20 (384-bit ECP), or 21 (521-bit ECP)'
                )
        
        # Check transition mode (potential downgrade vulnerability)
        if transition_mode:
            result['vulnerabilities'].append(
                'Transition Mode: Vulnerable to downgrade attacks (WPA3 → WPA2)'
            )
            if result['risk_level'] == 'none':
                result['risk_level'] = 'low'
            result['recommendations'].append(
                'Disable WPA2 support and use WPA3-only mode'
            )
        
        # Check PMF status
        if pmf_status == 'optional':
            result['vulnerabilities'].append(
                'PMF Optional: Clients may connect without Protected Management Frames'
            )
            if result['risk_level'] == 'none':
                result['risk_level'] = 'low'
            result['recommendations'].append(
                'Enable PMF required mode for better security'
            )
        
        return result
    
    @staticmethod
    def print_vulnerability_report(target_essid: str, target_bssid: str, 
                                   vulnerability_info: Dict, verbose: bool = False):
        """
        Print a formatted vulnerability report.
        
        Args:
            target_essid: Network ESSID
            target_bssid: Network BSSID
            vulnerability_info: Vulnerability assessment from check_vulnerability()
            verbose: Show detailed information
        """
        if not vulnerability_info['vulnerable']:
            if verbose:
                Color.pl('\n{+} {G}Dragonblood Check:{W} Network appears secure')
            return
        
        Color.pl('\n{!} {O}Dragonblood Vulnerability Detected{W}')
        Color.pl('{+} {C}Target:{W} {G}%s{W} ({C}%s{W})' % (target_essid, target_bssid))
        Color.pl('{+} {C}Risk Level:{W} {R}%s{W}' % vulnerability_info['risk_level'].upper())
        
        if vulnerability_info['vulnerabilities']:
            Color.pl('\n{+} {C}Detected Vulnerabilities:{W}')
            for vuln in vulnerability_info['vulnerabilities']:
                Color.pl('    {O}•{W} %s' % vuln)
        
        if vulnerability_info['weak_groups']:
            Color.pl('\n{+} {C}Weak SAE Groups:{W}')
            for group in vulnerability_info['weak_groups']:
                desc = DragonbloodDetector.WEAK_SAE_GROUPS.get(group, 'Unknown')
                Color.pl('    {R}•{W} Group {R}%d{W}: %s' % (group, desc))
        
        if vulnerability_info['recommendations']:
            Color.pl('\n{+} {C}Recommendations:{W}')
            for rec in vulnerability_info['recommendations']:
                Color.pl('    {G}•{W} %s' % rec)
        
        Color.pl('\n{!} {O}Note:{W} This is detection only. No exploitation attempted.')
        Color.pl('{!} {O}Reference:{W} https://wpa3.mathyvanhoef.com/')
    
    @staticmethod
    def get_group_description(group_id: int) -> str:
        """Get human-readable description of SAE group."""
        if group_id in DragonbloodDetector.WEAK_SAE_GROUPS:
            return DragonbloodDetector.WEAK_SAE_GROUPS[group_id]
        elif group_id in DragonbloodDetector.SECURE_SAE_GROUPS:
            return DragonbloodDetector.SECURE_SAE_GROUPS[group_id]
        else:
            return f"Unknown group {group_id}"
    
    @staticmethod
    def is_group_weak(group_id: int) -> bool:
        """Check if a SAE group is considered weak."""
        return group_id in DragonbloodDetector.WEAK_SAE_GROUPS
    
    @staticmethod
    def get_secure_groups() -> List[int]:
        """Get list of recommended secure SAE groups."""
        return list(DragonbloodDetector.SECURE_SAE_GROUPS.keys())
    
    @staticmethod
    def scan_mode_check(targets: List) -> Dict:
        """
        Scan multiple targets for Dragonblood vulnerabilities.
        
        Args:
            targets: List of Target objects with wpa3_info
        
        Returns:
            Dictionary with scan results:
            {
                'total_checked': int,
                'vulnerable_count': int,
                'vulnerable_targets': List[Dict]
            }
        """
        results = {
            'total_checked': 0,
            'vulnerable_count': 0,
            'vulnerable_targets': []
        }
        
        for target in targets:
            if not hasattr(target, 'wpa3_info') or not target.wpa3_info:
                continue
            
            results['total_checked'] += 1
            vuln_info = DragonbloodDetector.check_vulnerability(target.wpa3_info)
            
            if vuln_info['vulnerable']:
                results['vulnerable_count'] += 1
                results['vulnerable_targets'].append({
                    'essid': target.essid,
                    'bssid': target.bssid,
                    'vulnerability_info': vuln_info
                })
        
        return results
    
    @staticmethod
    def print_scan_summary(scan_results: Dict):
        """Print summary of vulnerability scan."""
        Color.pl('\n{+} {C}Dragonblood Vulnerability Scan Summary{W}')
        Color.pl('{+} Networks checked: {G}%d{W}' % scan_results['total_checked'])
        Color.pl('{+} Vulnerable networks: {R}%d{W}' % scan_results['vulnerable_count'])
        
        if scan_results['vulnerable_count'] > 0:
            Color.pl('\n{!} {O}Vulnerable Networks:{W}')
            for target in scan_results['vulnerable_targets']:
                risk = target['vulnerability_info']['risk_level']
                risk_color = '{R}' if risk == 'high' else '{O}' if risk == 'medium' else '{Y}'
                Color.pl('    %s%s{W} ({C}%s{W}) - Risk: %s%s{W}' % 
                       (risk_color, target['essid'], target['bssid'], 
                        risk_color, risk.upper()))
        else:
            Color.pl('\n{+} {G}No vulnerable networks detected{W}')


if __name__ == '__main__':
    # Test the detector
    print("Dragonblood Detector - Test Mode")
    print("=" * 50)
    
    # Test case 1: Vulnerable network with weak MODP group
    test_wpa3_info_weak = {
        'sae_groups': [19, 22],  # 22 is weak MODP
        'pmf_status': 'optional',
        'transition_mode': True
    }
    
    result = DragonbloodDetector.check_vulnerability(test_wpa3_info_weak)
    DragonbloodDetector.print_vulnerability_report(
        "TestNetwork_Weak", "AA:BB:CC:DD:EE:FF", result, verbose=True
    )
    
    # Test case 2: Secure network
    test_wpa3_info_secure = {
        'sae_groups': [19],  # Secure ECP group
        'pmf_status': 'required',
        'transition_mode': False
    }
    
    result = DragonbloodDetector.check_vulnerability(test_wpa3_info_secure)
    DragonbloodDetector.print_vulnerability_report(
        "TestNetwork_Secure", "11:22:33:44:55:66", result, verbose=True
    )

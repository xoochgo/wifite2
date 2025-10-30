#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .dependency import Dependency
from ..model.target import WPSState
from ..util.process import Process
import re


class Tshark(Dependency):
    """ Wrapper for Tshark program. """
    dependency_required = False
    dependency_name = 'tshark'
    dependency_url = 'apt install tshark'

    def __init__(self):
        pass

    @staticmethod
    def _extract_src_dst_index_total(line):
        # Extract BSSIDs, handshake # (1-4) and handshake 'total' (4)
        mac_regex = ('[a-zA-Z0-9]{2}:' * 6)[:-1]
        match = re.search(r'(%s)\s*.*\s*(%s).*Message.*(\d).*of.*(\d)' % (mac_regex, mac_regex), line)
        if match is None:
            # Line doesn't contain src, dst, Message numbers
            return None, None, None, None
        (src, dst, index, total) = match.groups()
        return src, dst, index, total

    @staticmethod
    def _build_target_client_handshake_map(output, bssid=None):
        # Map of target_ssid,client_ssid -> handshake #s
        # E.g. 12:34:56,21:43:65 -> 3
        target_client_msg_nums = {}

        for line in output.split('\n'):
            src, dst, index, total = Tshark._extract_src_dst_index_total(line)
            if src is None:
                continue  # Skip

            index = int(index)
            total = int(total)

            if total != 4:
                continue  # Handshake X of 5? X of 3? Skip it.

            # Identify the client and target MAC addresses
            if index % 2 == 1:
                # First and Third messages
                target = src
                client = dst
            else:
                # Second and Fourth messages
                client = src
                target = dst

            if bssid is not None and bssid.lower() != target.lower():
                # We know the BSSID and this msg was not for the target
                continue

            target_client_key = f'{target},{client}'

            # Ensure all 4 messages are:
            # Between the same client and target (not different clients connecting).
            # In numeric & chronological order (Message 1, then 2, then 3, then 4)
            if index == 1:
                target_client_msg_nums[target_client_key] = 1  # First message

            elif target_client_key not in target_client_msg_nums \
                    or index - 1 != target_client_msg_nums[target_client_key]:
                continue  # Not first message. We haven't gotten the first message yet. Skip.

            else:
                # Happy case: Message is > 1 and is received in-order
                target_client_msg_nums[target_client_key] = index

        return target_client_msg_nums

    @staticmethod
    def bssids_with_handshakes(capfile, bssid=None):
        if not Tshark.exists():
            return []

        # Returns list of BSSIDs for which we have valid handshakes in the capfile.
        command = [
            'tshark',
            '-r', capfile,
            '-n',  # Don't resolve addresses
            '-Y', 'eapol'  # Filter for only handshakes
        ]
        tshark = Process(command, devnull=False)

        target_client_msg_nums = Tshark._build_target_client_handshake_map(tshark.stdout(), bssid=bssid)

        bssids = set()
        # Check if we have all 4 messages for the handshake between the same MACs
        for (target_client, num) in list(target_client_msg_nums.items()):
            if num == 4:
                # We got a handshake!
                this_bssid = target_client.split(',')[0]
                bssids.add(this_bssid)

        return list(bssids)

    @staticmethod
    def bssid_essid_pairs(capfile, bssid):
        # Finds all BSSIDs (with corresponding ESSIDs) from cap file.
        # Returns list of tuples(BSSID, ESSID)
        if not Tshark.exists():
            return []

        ssid_pairs = set()

        command = [
            'tshark',
            '-r', capfile,  # Path to cap file
            '-n',  # Don't resolve addresses
            # Extract beacon frames
            '-Y', '"wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05"',
        ]

        tshark = Process(command, devnull=False)

        for line in tshark.stdout().split('\n'):
            # Extract src, dst, and essid
            mac_regex = ('[a-zA-Z0-9]{2}:' * 6)[:-1]
            match = re.search(f'({mac_regex}) [^ ]* ({mac_regex}).*.*SSID=(.*)$', line)
            if match is None:
                continue  # Line doesn't contain src, dst, ssid

            (src, dst, essid) = match.groups()

            if dst.lower() == 'ff:ff:ff:ff:ff:ff':
                continue  # Skip broadcast packets

            if (bssid is not None and bssid.lower() == src.lower()) or bssid is None:
                ssid_pairs.add((src, essid))  # This is our BSSID, add it

        return list(ssid_pairs)

    @staticmethod
    def check_for_wps_and_update_targets(capfile, targets):
        """
            Given a cap file and list of targets, use TShark to
            find which BSSIDs in the cap file use WPS.
            Then update the 'wps' flag for those BSSIDs in the targets.

            Args:
                capfile - .cap file from airodump containing packets
                targets - list of Targets from scan, to be updated
        """

        if not Tshark.exists():
            raise ValueError('Cannot detect WPS networks: Tshark does not exist')

        command = [
            'tshark',
            '-r', capfile,  # Path to cap file
            '-n',  # Don't resolve addresses
            # Filter WPS broadcast packets
            '-Y', 'wps.wifi_protected_setup_state && wlan.da == ff:ff:ff:ff:ff:ff',
            '-T', 'fields',  # Only output certain fields
            '-e', 'wlan.ta',  # BSSID
            '-e', 'wps.ap_setup_locked',  # Locked status
            '-E', 'separator=,'  # CSV
        ]
        p = Process(command)

        try:
            p.wait()
            lines = p.stdout()
        except Exception as e:
            if isinstance(e, KeyboardInterrupt):
                raise KeyboardInterrupt from e
            return
        wps_bssids = set()
        locked_bssids = set()
        for line in lines.split('\n'):
            if ',' not in line:
                continue
            bssid, locked = line.split(',')
            if '1' not in locked:
                wps_bssids.add(bssid.upper())
            else:
                locked_bssids.add(bssid.upper())

        for t in targets:
            target_bssid = t.bssid.upper()
            if target_bssid in wps_bssids:
                t.wps = WPSState.UNLOCKED
            elif target_bssid in locked_bssids:
                t.wps = WPSState.LOCKED
            else:
                t.wps = WPSState.NONE


class TsharkMonitor:
    """
    Wrapper for tshark in monitoring mode for attack detection.
    Captures deauth and disassoc frames in real-time.
    """
    
    def __init__(self, interface, channel=None):
        """
        Initialize TsharkMonitor.
        
        Args:
            interface: Wireless interface to monitor
            channel: Optional channel to monitor (None = current channel)
        """
        self.interface = interface
        self.channel = channel
        self.proc = None
    
    def start(self):
        """
        Start tshark with filters for deauth/disassoc frames.
        
        Filter: wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a
        - 0x0c = Deauthentication
        - 0x0a = Disassociation
        
        Returns:
            Process object for the tshark process
        """
        import subprocess
        
        command = [
            'tshark',
            '-i', self.interface,
            '-l',  # Line buffered output
            '-T', 'fields',
            '-e', 'frame.time_epoch',
            '-e', 'wlan.fc.type_subtype',
            '-e', 'wlan.sa',  # Source address
            '-e', 'wlan.da',  # Destination address
            '-e', 'wlan.bssid',
            '-e', 'wlan_radio.channel',
            '-Y', '(wlan.fc.type_subtype == 0x0c) || (wlan.fc.type_subtype == 0x0a)'
        ]
        
        self.proc = Process(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return self.proc
    
    def read_frame(self):
        """
        Read and parse next frame from tshark output.
        
        Returns:
            Dictionary with frame data or None if no frame available:
            {
                'timestamp': float,
                'frame_type': str,
                'source_mac': str,
                'dest_mac': str,
                'bssid': str,
                'channel': str
            }
        """
        if not self.proc or not self.proc.pid or not self.proc.pid.stdout:
            return None
        
        try:
            line = self.proc.pid.stdout.readline()
            if not line:
                return None
            
            # Decode if bytes
            if isinstance(line, bytes):
                line = line.decode('utf-8', errors='ignore')
            
            line = line.strip()
            if not line:
                return None
            
            fields = line.split('\t')
            if len(fields) < 5:
                return None
            
            return {
                'timestamp': float(fields[0]) if fields[0] else 0.0,
                'frame_type': fields[1] if len(fields) > 1 else '',
                'source_mac': fields[2] if len(fields) > 2 else '',
                'dest_mac': fields[3] if len(fields) > 3 else '',
                'bssid': fields[4] if len(fields) > 4 else '',
                'channel': fields[5] if len(fields) > 5 else ''
            }
        except Exception:
            return None
    
    def stop(self):
        """Stop tshark process gracefully."""
        if self.proc:
            self.proc.interrupt()
            self.proc = None


if __name__ == '__main__':
    test_file = './tests/files/contains_wps_network.cap'

    target_bssid = 'A4:2B:8C:16:6B:3A'
    from ..model.target import Target
    fields = [
        'A4:2B:8C:16:6B:3A',  # BSSID
        '2015-05-27 19:28:44', '2015-05-27 19:28:46',  # Dates
        '11',  # Channel
        '54',  # throughput
        'WPA2', 'CCMP TKIP', 'PSK',  # AUTH
        '-58', '2', '0', '0.0.0.0', '9',  # ???
        'Test Router Please Ignore',  # SSID
    ]
    t = Target(fields)
    targets = [t]

    # Should update 'wps' field of a target
    Tshark.check_for_wps_and_update_targets(test_file, targets)

    print(f'Target(BSSID={targets[0].bssid}).wps = {targets[0].wps} (Expected: 1)')
    assert targets[0].wps == WPSState.UNLOCKED

    print((Tshark.bssids_with_handshakes(test_file, bssid=target_bssid)))

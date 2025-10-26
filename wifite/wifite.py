#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from .config import Configuration
except (ValueError, ImportError) as e:
    raise Exception("You may need to run wifite from the root directory (which includes README.md)", e) from e


from .util.color import Color

import os
import subprocess


class Wifite(object):

    def __init__(self):
        """
        Initializes Wifite.
        Checks that its running under *nix, with root permissions and ensures dependencies are installed.
        """

        self.print_banner()

        Configuration.initialize(load_interface=False)

        # Initialize TUI logger if debug mode is enabled
        from .util.tui_logger import TUILogger
        if hasattr(Configuration, 'tui_debug') and Configuration.tui_debug:
            TUILogger.initialize(enabled=True, debug_mode=True)

        # Initialize output manager based on configuration
        from .util.output import OutputManager
        if Configuration.use_tui is True:
            OutputManager.initialize('tui')
        else:
            # Default to classic mode (use_tui is False or None)
            OutputManager.initialize('classic')

        if os.name == 'nt':
            Color.pl('{!} {R}error: {O}wifite{R} must be run under a {O}*NIX{W}{R} like OS')
            Configuration.exit_gracefully()
        if os.getuid() != 0:
            Color.pl('{!} {R}error: {O}wifite{R} must be run as {O}root{W}')
            Color.pl('{!} {R}re-run with {O}sudo{W}')
            Configuration.exit_gracefully()

        from .tools.dependency import Dependency
        Dependency.run_dependency_check()
        
        # Automatic cleanup of old session files on startup
        self.cleanup_old_sessions()

    def start(self):
        """
        Starts target-scan + attack loop, or launches utilities depending on user input.
        """
        from .model.result import CrackResult
        from .model.handshake import Handshake
        from .util.crack import CrackHelper
        from .util.dbupdater import DBUpdater
        from .util.session import SessionManager

        # Handle session cleanup
        if Configuration.clean_sessions:
            self.clean_sessions()
            return

        # Handle session resume
        if Configuration.resume or Configuration.resume_latest or Configuration.resume_id:
            self.resume_session()
            return

        if Configuration.show_cracked:
            CrackResult.display('cracked')

        elif Configuration.show_ignored:
            CrackResult.display('ignored')

        elif Configuration.check_handshake:
            Handshake.check()

        elif Configuration.crack_handshake:
            CrackHelper.run()

        elif Configuration.update_db:
            DBUpdater.run()

        elif Configuration.wpa3_check_dragonblood:
            # Dragonblood vulnerability scan mode
            Configuration.get_monitor_mode_interface()
            self.dragonblood_scan()

        elif hasattr(Configuration, 'owe_scan') and Configuration.owe_scan:
            # OWE transition mode vulnerability scan
            Configuration.get_monitor_mode_interface()
            self.owe_scan()

        else:
            Configuration.get_monitor_mode_interface()
            self.scan_and_attack()

    @staticmethod
    def cleanup_old_sessions():
        """Automatically cleanup old session files on startup (silent)."""
        try:
            from .util.session import SessionManager
            session_mgr = SessionManager()
            deleted = session_mgr.cleanup_old_sessions(days=7)
            
            # Only log if verbose mode is enabled and sessions were deleted
            if deleted > 0 and Configuration.verbose > 0:
                Color.pl('{+} {D}Cleaned up {C}%d{D} old session file(s){W}' % deleted)
        except Exception:
            # Silently ignore cleanup errors on startup
            pass
    
    @staticmethod
    def clean_sessions():
        """Clean up old session files (manual command)."""
        from .util.session import SessionManager
        
        Color.pl('{+} Cleaning up old session files...')
        
        session_mgr = SessionManager()
        deleted = session_mgr.cleanup_old_sessions(days=7)
        
        if deleted > 0:
            Color.pl('{+} Deleted {C}%d{W} old session file(s)' % deleted)
        else:
            Color.pl('{+} No old session files to clean up')
    
    @staticmethod
    def resume_session():
        """Resume a previously interrupted attack session."""
        from .util.session import SessionManager
        from .attack.all import AttackAll
        
        Color.pl('')
        Color.pl('{+} {C}Resuming previous attack session...{W}')
        
        session_mgr = SessionManager()
        
        try:
            # Determine which session to load
            if Configuration.resume_id:
                session = session_mgr.load_session(Configuration.resume_id)
            elif Configuration.resume_latest:
                session = session_mgr.load_session()  # Load latest
            else:
                # List available sessions and let user choose
                sessions = session_mgr.list_sessions()
                
                if not sessions:
                    Color.pl('{!} {R}No session files found{W}')
                    Color.pl('{!} {O}Start a new attack session first{W}')
                    return
                
                if len(sessions) == 1:
                    # Only one session, use it
                    session = session_mgr.load_session(sessions[0]['session_id'])
                else:
                    # Multiple sessions, let user choose
                    Color.pl('{+} Found {C}%d{W} session(s):' % len(sessions))
                    for i, s in enumerate(sessions, 1):
                        Color.pl('  {G}%d{W}. %s - {C}%d{W} targets ({G}%d{W} completed, {R}%d{W} failed, {O}%d{W} remaining)' % (
                            i, s['session_id'], s['total_targets'], 
                            s['completed'], s['failed'], s['remaining']
                        ))
                    
                    Color.p('{+} Select session to resume [{G}1{W}]: ')
                    try:
                        choice = input().strip()
                        if not choice:
                            choice = '1'
                        idx = int(choice) - 1
                        if idx < 0 or idx >= len(sessions):
                            Color.pl('{!} {R}Invalid selection{W}')
                            return
                        session = session_mgr.load_session(sessions[idx]['session_id'])
                    except (ValueError, KeyboardInterrupt):
                        Color.pl('\n{!} {O}Cancelled{W}')
                        return
            
            # Display session information
            summary = session.get_progress_summary()
            Color.pl('')
            Color.pl('{+} {C}Session Information:{W}')
            Color.pl('  {W}Session ID: {C}%s{W}' % session.session_id)
            Color.pl('  {W}Created: {C}%s{W}' % summary['created_at'])
            Color.pl('  {W}Last Updated: {C}%s{W}' % summary['updated_at'])
            Color.pl('  {W}Total Targets: {C}%d{W}' % summary['total'])
            Color.pl('  {W}Completed: {G}%d{W}' % summary['completed'])
            Color.pl('  {W}Failed: {R}%d{W}' % summary['failed'])
            Color.pl('  {W}Remaining: {O}%d{W}' % summary['remaining'])
            Color.pl('  {W}Progress: {C}%.1f%%{W}' % summary['progress_percent'])
            
            # Display original configuration
            Color.pl('')
            Color.pl('{+} {C}Original Configuration:{W}')
            config = session.config
            
            # Interface
            if config.get('interface'):
                Color.pl('  {W}Interface: {C}%s{W}' % config['interface'])
            
            # Attack types
            attack_types = []
            if config.get('wps_pixie'):
                attack_types.append('WPS Pixie')
            if config.get('wps_pin'):
                attack_types.append('WPS PIN')
            if config.get('use_pmkid'):
                attack_types.append('PMKID')
            if not config.get('use_pmkid_only') and not config.get('wps_only'):
                attack_types.append('Handshake')
            
            if attack_types:
                Color.pl('  {W}Attack Types: {C}%s{W}' % ', '.join(attack_types))
            
            # Wordlist
            if config.get('wordlist'):
                wordlist = config['wordlist']
                # Shorten path if too long
                if len(wordlist) > 50:
                    wordlist = '...' + wordlist[-47:]
                Color.pl('  {W}Wordlist: {C}%s{W}' % wordlist)
            
            # Timeout
            if config.get('wpa_attack_timeout'):
                Color.pl('  {W}WPA Timeout: {C}%d{W} seconds' % config['wpa_attack_timeout'])
            
            # Special modes
            if config.get('infinite_mode'):
                Color.pl('  {W}Mode: {C}Infinite{W}')
            elif config.get('attack_max') and config['attack_max'] > 0:
                Color.pl('  {W}Max Targets: {C}%d{W}' % config['attack_max'])
            
            Color.pl('')
            
            if summary['remaining'] == 0:
                Color.pl('{+} {G}All targets in this session have been attacked{W}')
                Color.p('{+} Delete this session? [{G}Y{W}/n]: ')
                try:
                    if input().strip().lower() != 'n':
                        session_mgr.delete_session(session.session_id)
                        Color.pl('{+} Session deleted')
                except KeyboardInterrupt:
                    Color.pl('')
                return
            
            # Restore configuration from session
            Color.pl('{+} {C}Restoring attack configuration...{W}')
            restore_result = session_mgr.restore_configuration(session, Configuration)
            
            # Display warnings about configuration restoration
            if restore_result['warnings']:
                Color.pl('')
                Color.pl('{!} {O}Configuration warnings:{W}')
                for warning in restore_result['warnings']:
                    Color.pl('  {O}•{W} %s' % warning)
            
            # Display conflicts with command-line flags
            if restore_result['conflicts']:
                Color.pl('')
                Color.pl('{!} {O}Command-line flags overridden by session:{W}')
                for conflict in restore_result['conflicts']:
                    Color.pl('  {O}•{W} %s' % conflict)
            
            if restore_result['warnings'] or restore_result['conflicts']:
                Color.pl('')
            
            # Confirm resumption
            Color.p('{+} Resume this session? [{G}Y{W}/n]: ')
            try:
                if input().strip().lower() == 'n':
                    Color.pl('{!} {O}Cancelled{W}')
                    return
            except KeyboardInterrupt:
                Color.pl('\n{!} {O}Cancelled{W}')
                return
            
            # Get remaining targets
            remaining_targets = session_mgr.get_remaining_targets(session)
            
            if not remaining_targets:
                Color.pl('{!} {O}No remaining targets to attack{W}')
                return
            
            Color.pl('')
            Color.pl('{+} Resuming attack on {C}%d{W} remaining target(s)...' % len(remaining_targets))
            
            # TODO: Convert TargetState objects back to Target objects
            # TODO: Attack remaining targets
            # TODO: Update session after each target
            
            Color.pl('{!} {O}Resume functionality not fully implemented yet{W}')
            Color.pl('{!} {O}Session loading works, but target attack resumption is pending{W}')
            
        except FileNotFoundError as e:
            Color.pl('{!} {R}Error:{W} %s' % str(e))
            Color.pl('{!} {O}No session files found to resume{W}')
            Color.pl('{!} {O}Start a new attack session first, then use {C}--resume{O} if interrupted{W}')
        except ValueError as e:
            Color.pl('{!} {R}Corrupted session file:{W} %s' % str(e))
            Color.pl('')
            Color.p('{+} Delete corrupted session? [{G}Y{W}/n]: ')
            try:
                response = input().strip().lower()
                if response != 'n':
                    # Try to delete the corrupted session
                    try:
                        # Determine which session to delete
                        if Configuration.resume_id:
                            session_id = Configuration.resume_id
                        elif Configuration.resume_latest:
                            # Get the latest session ID
                            sessions = session_mgr.list_sessions()
                            if sessions:
                                session_id = sessions[0]['session_id']
                            else:
                                Color.pl('{!} {O}Could not determine session to delete{W}')
                                return
                        else:
                            Color.pl('{!} {O}Could not determine session to delete{W}')
                            return
                        
                        session_mgr.delete_session(session_id)
                        Color.pl('{+} {G}Corrupted session deleted{W}')
                    except Exception as del_error:
                        Color.pl('{!} {R}Failed to delete session:{W} %s' % str(del_error))
                        Color.pl('{!} {O}Use {C}--clean-sessions{O} to manually remove corrupted files{W}')
                else:
                    Color.pl('{!} {O}Session not deleted. Use {C}--clean-sessions{O} to remove it later{W}')
            except KeyboardInterrupt:
                Color.pl('\n{!} {O}Cancelled{W}')
        except PermissionError as e:
            Color.pl('{!} {R}Permission error:{W} %s' % str(e))
            Color.pl('{!} {O}Check file permissions and try again{W}')
        except Exception as e:
            Color.pl('{!} {R}Unexpected error:{W} %s' % str(e))
            if Configuration.verbose > 0:
                import traceback
                Color.pl('{!} {D}%s{W}' % traceback.format_exc())
    
    @staticmethod
    def print_banner():
        """Displays ASCII art of the highest caliber."""
        Color.pl(r' {G}  .     {GR}{D}     {W}{G}     .    {W}')
        Color.pl(r' {G}.´  ·  .{GR}{D}     {W}{G}.  ·  `.  {G}wifite2 {D}%s{W}' % Configuration.version)
        Color.pl(r' {G}:  :  : {GR}{D} (¯) {W}{G} :  :  :  {W}{D}a wireless auditor by derv82{W}')
        Color.pl(r' {G}`.  ·  `{GR}{D} /¯\ {W}{G}´  ·  .´  {W}{D}maintained by kimocoder{W}')
        Color.pl(r' {G}  `     {GR}{D}/¯¯¯\{W}{G}     ´    {C}{D}https://github.com/kimocoder/wifite2{W}')
        Color.pl('')

    @staticmethod
    def dragonblood_scan():
        """
        Scan for Dragonblood vulnerabilities in WPA3 networks.
        Detection only - no attacks performed.
        """
        from .util.scanner import Scanner
        from .util.dragonblood_scanner import DragonbloodScanner

        Color.pl('')
        Color.pl('{+} {C}Dragonblood Vulnerability Scanner{W}')
        Color.pl('{+} {O}Detection mode - no attacks will be performed{W}')
        Color.pl('')

        # Scan for targets
        s = Scanner()
        s.find_targets()
        
        # Get all targets (don't ask user to select)
        targets = s.get_all_targets()
        
        if not targets:
            Color.pl('{!} {R}No targets found{W}')
            return
        
        # Scan for Dragonblood vulnerabilities
        results = DragonbloodScanner.scan_targets(targets)
        
        # Display summary
        Color.pl('')
        if results['vulnerable_count'] > 0:
            Color.pl('{!} {O}Found {R}%d{O} vulnerable network(s){W}' % results['vulnerable_count'])
            Color.pl('{!} {O}Consider updating firmware on vulnerable devices{W}')
            Color.pl('{!} {O}Reference: {C}https://wpa3.mathyvanhoef.com/{W}')
        else:
            Color.pl('{+} {G}No Dragonblood vulnerabilities detected{W}')
        
        Color.pl('')

    @staticmethod
    def owe_scan():
        """
        Scan for OWE transition mode vulnerabilities.
        Detection only - no attacks performed.
        """
        from .util.scanner import Scanner
        from .util.owe_scanner import OWEScanner

        Color.pl('')
        Color.pl('{+} {C}OWE Transition Mode Vulnerability Scanner{W}')
        Color.pl('{+} {O}Detection mode - no attacks will be performed{W}')
        Color.pl('')

        # Scan for targets
        s = Scanner()
        s.find_targets()
        
        # Get all targets (don't ask user to select)
        targets = s.get_all_targets()
        
        if not targets:
            Color.pl('{!} {R}No targets found{W}')
            return
        
        # Scan for OWE vulnerabilities
        results = OWEScanner.scan_targets(targets)
        
        # Display summary
        Color.pl('')
        if results['vulnerable_count'] > 0:
            Color.pl('{!} {O}Found {R}%d{O} vulnerable network(s){W}' % results['vulnerable_count'])
            Color.pl('{!} {O}Recommendation: Disable Open mode on OWE networks{W}')
            Color.pl('{!} {O}Reference: {C}RFC 8110 - Opportunistic Wireless Encryption{W}')
        else:
            Color.pl('{+} {G}No OWE transition mode vulnerabilities detected{W}')
        
        Color.pl('')

    @staticmethod
    def scan_and_attack():
        """
        1) Scans for targets, asks user to select targets
        2) Attacks each target
        """
        from .util.scanner import Scanner
        from .attack.all import AttackAll
        from .util.session import SessionManager

        Color.pl('')

        # Scan (no signal handler during scanning to allow proper target selection)
        s = Scanner()
        do_continue = s.find_targets()
        targets = s.select_targets()

        # Create session after target selection
        session_mgr = SessionManager()
        session = session_mgr.create_session(targets, Configuration)
        session_mgr.save_session(session)
        
        Color.pl('{+} Created session {C}%s{W}' % session.session_id)

        # Attack modules handle KeyboardInterrupt properly, no global handler needed

        if Configuration.infinite_mode:
            while do_continue:
                AttackAll.attack_multiple(targets, session, session_mgr)
                do_continue = s.update_targets()
                if not do_continue:
                    break
                targets = s.select_targets()
            attacked_targets = s.get_num_attacked()
        else:
            # Attack
            attacked_targets = AttackAll.attack_multiple(targets, session, session_mgr)

        Color.pl('{+} Finished attacking {C}%d{W} target(s), exiting' % attacked_targets)
        
        # Delete session on successful completion
        # Only delete if all targets were attacked (completed or failed)
        summary = session.get_progress_summary()
        if summary['remaining'] == 0:
            # All targets were processed, safe to delete session
            try:
                session_mgr.delete_session(session.session_id)
                Color.pl('{+} {G}Session completed and cleaned up{W}')
            except (OSError, IOError) as e:
                Color.pl('{!} {O}Warning: Could not delete session file: %s{W}' % str(e))
            except Exception as e:
                Color.pl('{!} {O}Warning: Unexpected error during session cleanup: %s{W}' % str(e))
        else:
            # Some targets remain, preserve session for resume
            Color.pl('{+} {C}Session preserved for resume{W} ({O}%d{W} target(s) remaining)' % summary['remaining'])
            Color.pl('{+} Use {C}--resume{W} to continue this session')




def force_exit_handler(signum, frame):
    """Force exit on multiple Ctrl+C during cleanup"""
    import sys
    print('\n[!] Force exiting...')
    sys.exit(1)

def main():
    try:
        wifite = Wifite()
        wifite.start()
    except (OSError, IOError) as e:
        Color.pl('\n{!} {R}System Error{W}: %s' % str(e))
        Color.pl('\n{!} {R}Exiting{W}\n')
    except subprocess.CalledProcessError as e:
        Color.pl('\n{!} {R}Command Failed{W}: %s' % str(e))
        Color.pl('\n{!} {R}Exiting{W}\n')
    except PermissionError as e:
        Color.pl('\n{!} {R}Permission Error{W}: %s' % str(e))
        Color.pl('\n{!} {R}Try running with sudo{W}\n')
    except KeyboardInterrupt:
        Color.pl('\n{!} {O}Interrupted, Shutting down...{W}')
        # Set up force exit handler for cleanup phase
        import signal
        signal.signal(signal.SIGINT, force_exit_handler)
    except Exception as e:
        Color.pl('\n{!} {R}Unexpected Error{W}: %s' % str(e))
        Color.pexception(e)
        Color.pl('\n{!} {R}Exiting{W}\n')

    finally:
        # Set up aggressive force exit handler during cleanup
        import signal
        import sys

        def emergency_exit(signum, frame):
            print('\n[!] Emergency exit!')
            # Disable atexit callbacks and suppress stderr to prevent ugly exception messages
            import atexit
            import os
            atexit._clear()
            # Redirect stderr to devnull to hide any remaining cleanup exceptions
            os.dup2(os.open(os.devnull, os.O_WRONLY), 2)
            sys.exit(1)

        signal.signal(signal.SIGINT, emergency_exit)

        # Quick cleanup with short timeouts
        try:
            from .util.process import ProcessManager
            import threading

            # Run cleanup in thread with timeout
            cleanup_thread = threading.Thread(target=ProcessManager().cleanup_all)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            cleanup_thread.join(timeout=3)  # 3 second timeout
        except:
            pass  # Ignore cleanup errors

        # Delete Reaver .pcap quickly
        try:
            subprocess.run(["rm", "-f", "reaver_output.pcap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except:
            pass

        # Try graceful exit with timeout
        try:
            import threading

            def graceful_exit():
                Configuration.exit_gracefully()

            exit_thread = threading.Thread(target=graceful_exit)
            exit_thread.daemon = True
            exit_thread.start()
            exit_thread.join(timeout=2)  # 2 second timeout
        except:
            pass

        # Force exit regardless
        sys.exit(0)


if __name__ == '__main__':
    main()

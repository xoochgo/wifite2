#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Session management for wifite2.
Handles persistence and restoration of attack sessions for resume functionality.
"""

import os
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class TargetState:
    """Represents the state of a single target in a session."""
    
    bssid: str
    essid: Optional[str]
    channel: int
    encryption: str
    power: int
    wps: bool
    status: str = "pending"  # pending, in_progress, completed, failed
    attempts: int = 0
    last_attempt: Optional[float] = None
    
    @classmethod
    def from_target(cls, target) -> 'TargetState':
        """
        Create TargetState from a Target object.
        
        Args:
            target: Target object from scanner
            
        Returns:
            TargetState instance
        """
        return cls(
            bssid=target.bssid,
            essid=target.essid if hasattr(target, 'essid') else None,
            channel=int(target.channel) if target.channel else -1,
            encryption=target.encryption if hasattr(target, 'encryption') else 'Unknown',
            power=int(target.power) if hasattr(target, 'power') else 0,
            wps=bool(target.wps) if hasattr(target, 'wps') else False
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TargetState':
        """Create TargetState from dictionary."""
        return cls(**data)


@dataclass
class SessionState:
    """Represents the complete state of an attack session."""
    
    session_id: str
    created_at: float
    updated_at: float
    config: Dict[str, Any]
    targets: List[TargetState] = field(default_factory=list)
    completed_targets: List[str] = field(default_factory=list)  # BSSIDs
    failed_targets: Dict[str, str] = field(default_factory=dict)  # BSSID -> reason
    current_target_index: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON storage."""
        return {
            'session_id': self.session_id,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'config': self.config,
            'targets': [t.to_dict() for t in self.targets],
            'completed_targets': self.completed_targets,
            'failed_targets': self.failed_targets,
            'current_target_index': self.current_target_index
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SessionState':
        """Deserialize from dictionary."""
        targets = [TargetState.from_dict(t) for t in data.get('targets', [])]
        return cls(
            session_id=data['session_id'],
            created_at=data['created_at'],
            updated_at=data['updated_at'],
            config=data.get('config', {}),
            targets=targets,
            completed_targets=data.get('completed_targets', []),
            failed_targets=data.get('failed_targets', {}),
            current_target_index=data.get('current_target_index', 0)
        )
    
    def get_progress_summary(self) -> Dict[str, Any]:
        """Get summary of session progress."""
        total = len(self.targets)
        completed = len(self.completed_targets)
        failed = len(self.failed_targets)
        remaining = total - completed - failed
        
        return {
            'total': total,
            'completed': completed,
            'failed': failed,
            'remaining': remaining,
            'progress_percent': (completed / total * 100) if total > 0 else 0,
            'created_at': datetime.fromtimestamp(self.created_at).strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': datetime.fromtimestamp(self.updated_at).strftime('%Y-%m-%d %H:%M:%S'),
            'age_hours': (time.time() - self.created_at) / 3600
        }


class SessionManager:
    """Manages session lifecycle, persistence, and restoration."""
    
    def __init__(self, session_dir: str = None):
        """
        Initialize session manager.
        
        Args:
            session_dir: Directory for session storage (default: ~/.wifite/sessions)
        """
        if session_dir is None:
            home = os.path.expanduser('~')
            session_dir = os.path.join(home, '.wifite', 'sessions')
        
        self.session_dir = session_dir
        self._ensure_session_dir()
    
    def _ensure_session_dir(self):
        """Create session directory if it doesn't exist with proper permissions."""
        if not os.path.exists(self.session_dir):
            os.makedirs(self.session_dir, mode=0o700)
        else:
            # Ensure proper permissions on existing directory
            os.chmod(self.session_dir, 0o700)
    
    def _get_session_path(self, session_id: str) -> str:
        """Get full path to session file."""
        return os.path.join(self.session_dir, f'{session_id}.json')
    
    def create_session(self, targets: List, config) -> SessionState:
        """
        Create a new session from targets and configuration.
        
        Args:
            targets: List of Target objects
            config: Configuration object or dictionary
            
        Returns:
            SessionState instance
        """
        timestamp = time.time()
        session_id = f"session_{datetime.fromtimestamp(timestamp).strftime('%Y%m%d_%H%M%S')}"
        
        target_states = [TargetState.from_target(t) for t in targets]
        
        # Extract configuration as dictionary
        if isinstance(config, dict):
            config_dict = config
        else:
            # Extract relevant configuration from Configuration object
            config_dict = {
                'interface': getattr(config, 'interface', None),
                'wordlist': getattr(config, 'wordlist', None),
                'wpa_attack_timeout': getattr(config, 'wpa_attack_timeout', 500),
                'wps_pixie': getattr(config, 'wps_pixie', True),
                'wps_pin': getattr(config, 'wps_pin', True),
                'use_pmkid': not getattr(config, 'dont_use_pmkid', False),
                'infinite_mode': getattr(config, 'infinite_mode', False),
                'attack_max': getattr(config, 'attack_max', 0),
                'use_tui': getattr(config, 'use_tui', True),
                'wps_only': getattr(config, 'wps_only', False),
                'use_pmkid_only': getattr(config, 'use_pmkid_only', False),
                'verbose': getattr(config, 'verbose', 0)
            }
        
        session = SessionState(
            session_id=session_id,
            created_at=timestamp,
            updated_at=timestamp,
            config=config_dict,
            targets=target_states
        )
        
        return session
    
    def save_session(self, session: SessionState) -> None:
        """
        Persist session state to disk.
        
        Args:
            session: SessionState to save
        """
        session.updated_at = time.time()
        session_path = self._get_session_path(session.session_id)
        
        # Write to temporary file first, then rename (atomic operation)
        temp_path = session_path + '.tmp'
        with open(temp_path, 'w') as f:
            json.dump(session.to_dict(), f, indent=2)
        
        # Set proper permissions (owner read/write only)
        os.chmod(temp_path, 0o600)
        
        # Atomic rename
        os.rename(temp_path, session_path)
    
    def load_session(self, session_id: str = None) -> SessionState:
        """
        Load session from disk with validation.
        
        Args:
            session_id: Session ID to load. If None, load latest session.
            
        Returns:
            SessionState instance
            
        Raises:
            FileNotFoundError: If no session file found
            ValueError: If session file is corrupted or invalid
            PermissionError: If session file has incorrect permissions
        """
        if session_id is None:
            # Load latest session
            sessions = self.list_sessions()
            if not sessions:
                raise FileNotFoundError("No session files found")
            session_id = sessions[0]['session_id']
        
        session_path = self._get_session_path(session_id)
        
        if not os.path.exists(session_path):
            raise FileNotFoundError(f"Session file not found: {session_id}")
        
        # Validate file permissions
        self._validate_file_permissions(session_path)
        
        try:
            with open(session_path, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Corrupted session file (invalid JSON): {e}")
        except (OSError, IOError) as e:
            raise ValueError(f"Cannot read session file: {e}")
        
        # Validate session data structure
        self._validate_session_data(data, session_id)
        
        try:
            return SessionState.from_dict(data)
        except (KeyError, TypeError, AttributeError) as e:
            raise ValueError(f"Corrupted session file (invalid structure): {e}")
    
    def _validate_file_permissions(self, session_path: str) -> None:
        """
        Validate that session file has secure permissions.
        
        Args:
            session_path: Path to session file
            
        Raises:
            PermissionError: If permissions are insecure
        """
        try:
            stat_info = os.stat(session_path)
            mode = stat_info.st_mode & 0o777
            
            # Check if file is readable by others (world-readable)
            if mode & 0o004:
                raise PermissionError(
                    f"Session file has insecure permissions ({oct(mode)}). "
                    "File should not be world-readable. "
                    f"Run: chmod 600 {session_path}"
                )
            
            # Check if file is readable by group
            if mode & 0o040:
                # Warning only, not critical
                import warnings
                warnings.warn(
                    f"Session file has group-readable permissions ({oct(mode)}). "
                    f"Consider running: chmod 600 {session_path}",
                    UserWarning
                )
        except OSError:
            # If we can't check permissions, continue anyway
            pass
    
    def _validate_session_data(self, data: Dict[str, Any], session_id: str) -> None:
        """
        Validate session data structure and content.
        
        Args:
            data: Session data dictionary
            session_id: Expected session ID
            
        Raises:
            ValueError: If data is invalid
        """
        # Check required fields
        required_fields = ['session_id', 'created_at', 'updated_at', 'config', 'targets']
        for field in required_fields:
            if field not in data:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate session ID matches
        if data['session_id'] != session_id:
            raise ValueError(
                f"Session ID mismatch: expected {session_id}, got {data['session_id']}"
            )
        
        # Validate timestamps
        if not isinstance(data['created_at'], (int, float)) or data['created_at'] <= 0:
            raise ValueError(f"Invalid created_at timestamp: {data['created_at']}")
        
        if not isinstance(data['updated_at'], (int, float)) or data['updated_at'] <= 0:
            raise ValueError(f"Invalid updated_at timestamp: {data['updated_at']}")
        
        # Validate config is a dictionary
        if not isinstance(data['config'], dict):
            raise ValueError(f"Invalid config type: expected dict, got {type(data['config'])}")
        
        # Validate targets is a list
        if not isinstance(data['targets'], list):
            raise ValueError(f"Invalid targets type: expected list, got {type(data['targets'])}")
        
        # Validate at least one target exists
        if len(data['targets']) == 0:
            raise ValueError("Session has no targets")
        
        # Validate each target has required fields
        for i, target in enumerate(data['targets']):
            if not isinstance(target, dict):
                raise ValueError(f"Target {i} is not a dictionary")
            
            required_target_fields = ['bssid', 'channel', 'encryption', 'power', 'wps', 'status']
            for field in required_target_fields:
                if field not in target:
                    raise ValueError(f"Target {i} missing required field: {field}")
            
            # Validate BSSID format (basic check)
            bssid = target['bssid']
            if not isinstance(bssid, str) or len(bssid) != 17:
                raise ValueError(f"Target {i} has invalid BSSID format: {bssid}")
            
            # Validate status is valid
            valid_statuses = ['pending', 'in_progress', 'completed', 'failed']
            if target['status'] not in valid_statuses:
                raise ValueError(f"Target {i} has invalid status: {target['status']}")
        
        # Validate completed_targets and failed_targets if present
        if 'completed_targets' in data:
            if not isinstance(data['completed_targets'], list):
                raise ValueError("completed_targets must be a list")
        
        if 'failed_targets' in data:
            if not isinstance(data['failed_targets'], dict):
                raise ValueError("failed_targets must be a dictionary")
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        List all available sessions with metadata.
        
        Returns:
            List of session metadata dictionaries, sorted by creation time (newest first)
        """
        sessions = []
        
        if not os.path.exists(self.session_dir):
            return sessions
        
        for filename in os.listdir(self.session_dir):
            if not filename.endswith('.json'):
                continue
            
            session_path = os.path.join(self.session_dir, filename)
            
            try:
                with open(session_path, 'r') as f:
                    data = json.load(f)
                
                session_state = SessionState.from_dict(data)
                summary = session_state.get_progress_summary()
                
                sessions.append({
                    'session_id': session_state.session_id,
                    'created_at': session_state.created_at,
                    'updated_at': session_state.updated_at,
                    'total_targets': summary['total'],
                    'completed': summary['completed'],
                    'failed': summary['failed'],
                    'remaining': summary['remaining'],
                    'progress_percent': summary['progress_percent'],
                    'age_hours': summary['age_hours']
                })
            except (json.JSONDecodeError, KeyError, TypeError):
                # Skip corrupted files
                continue
        
        # Sort by creation time, newest first
        sessions.sort(key=lambda x: x['created_at'], reverse=True)
        
        return sessions
    
    def delete_session(self, session_id: str) -> None:
        """
        Delete a specific session file.
        
        Args:
            session_id: Session ID to delete
        """
        session_path = self._get_session_path(session_id)
        if os.path.exists(session_path):
            os.remove(session_path)
    
    def cleanup_old_sessions(self, days: int = 7) -> int:
        """
        Remove sessions older than specified days.
        
        Args:
            days: Age threshold in days
            
        Returns:
            Number of sessions deleted
        """
        threshold = time.time() - (days * 24 * 3600)
        deleted = 0
        
        sessions = self.list_sessions()
        for session in sessions:
            if session['created_at'] < threshold:
                self.delete_session(session['session_id'])
                deleted += 1
        
        return deleted
    
    def mark_target_complete(self, session: SessionState, bssid: str, crack_result=None) -> None:
        """
        Mark a target as successfully completed.
        
        Args:
            session: SessionState to update
            bssid: BSSID of completed target
            crack_result: Optional CrackResult object (not stored in session)
        """
        if bssid not in session.completed_targets:
            session.completed_targets.append(bssid)
        
        # Update target status
        for target in session.targets:
            if target.bssid == bssid:
                target.status = 'completed'
                target.last_attempt = time.time()
                target.attempts += 1
                break
    
    def mark_target_failed(self, session: SessionState, bssid: str, reason: str) -> None:
        """
        Mark a target as failed.
        
        Args:
            session: SessionState to update
            bssid: BSSID of failed target
            reason: Failure reason
        """
        session.failed_targets[bssid] = reason
        
        # Update target status
        for target in session.targets:
            if target.bssid == bssid:
                target.status = 'failed'
                target.last_attempt = time.time()
                target.attempts += 1
                break
    
    def get_remaining_targets(
        self, session: SessionState, include_failed: bool = False
    ) -> List[TargetState]:
        """
        Get list of targets that still need to be attacked.
        
        Filters targets based on their status:
        - Excludes completed targets (successfully attacked)
        - Excludes failed targets by default (unless include_failed=True)
        - Includes pending targets (not yet attacked)
        - Includes in_progress targets (interrupted during attack)
        - Preserves original target order from session
        
        Args:
            session: SessionState to query
            include_failed: If True, include previously failed targets for retry
            
        Returns:
            List of TargetState objects for remaining targets, in original order
        """
        remaining = []
        
        for target in session.targets:
            # Skip completed targets (successfully attacked)
            if target.bssid in session.completed_targets:
                continue
            
            # Skip failed targets unless retry is enabled
            if target.bssid in session.failed_targets and not include_failed:
                continue
            
            # Include pending and in_progress targets
            remaining.append(target)
        
        return remaining
    
    def restore_configuration(self, session: SessionState, config_obj) -> Dict[str, Any]:
        """
        Restore attack parameters from session to Configuration object.
        
        This method:
        1. Validates interface availability
        2. Restores attack parameters from session
        3. Detects and warns about conflicting command-line flags
        4. Returns a dictionary of warnings/changes for display
        
        Args:
            session: SessionState containing saved configuration
            config_obj: Configuration object to update
            
        Returns:
            Dictionary with keys:
                - 'warnings': List of warning messages
                - 'interface_changed': Boolean indicating if interface was changed
                - 'conflicts': List of conflicting flags that were overridden
        """
        from ..util.color import Color
        
        warnings = []
        conflicts = []
        interface_changed = False
        
        saved_config = session.config
        
        # 1. Validate and restore interface
        saved_interface = saved_config.get('interface')
        current_interface = getattr(config_obj, 'interface', None)
        
        if saved_interface:
            # Check if saved interface is available
            try:
                import subprocess
                result = subprocess.run(
                    ['iw', 'dev'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                available_interfaces = result.stdout
                
                if saved_interface not in available_interfaces:
                    warnings.append(
                        f"Original interface '{saved_interface}' not found"
                    )
                    
                    # If user specified a different interface via command line, use it
                    if current_interface and current_interface != saved_interface:
                        warnings.append(
                            f"Using command-line interface '{current_interface}' instead"
                        )
                        interface_changed = True
                    else:
                        # Prompt will happen in wifite.py, just note it here
                        warnings.append(
                            "Will use current monitor mode interface"
                        )
                        interface_changed = True
                else:
                    # Interface is available, restore it
                    if current_interface and current_interface != saved_interface:
                        conflicts.append(
                            f"--interface: command-line value '{current_interface}' "
                            f"overridden by session value '{saved_interface}'"
                        )
                    config_obj.interface = saved_interface
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                # Can't check interface availability, use current
                warnings.append(
                    "Could not verify interface availability, using current interface"
                )
                interface_changed = True
        
        # 2. Restore attack parameters
        # Check for conflicts with command-line flags
        
        # Wordlist
        saved_wordlist = saved_config.get('wordlist')
        current_wordlist = getattr(config_obj, 'wordlist', None)
        if saved_wordlist:
            if current_wordlist and current_wordlist != saved_wordlist:
                conflicts.append(
                    f"--wordlist: command-line value overridden by session value"
                )
            config_obj.wordlist = saved_wordlist
        
        # WPA attack timeout
        saved_timeout = saved_config.get('wpa_attack_timeout')
        if saved_timeout is not None:
            current_timeout = getattr(config_obj, 'wpa_attack_timeout', 500)
            if current_timeout != saved_timeout and current_timeout != 500:
                conflicts.append(
                    f"--wpa-attack-timeout: command-line value overridden by session value"
                )
            config_obj.wpa_attack_timeout = saved_timeout
        
        # WPS Pixie
        saved_wps_pixie = saved_config.get('wps_pixie')
        if saved_wps_pixie is not None:
            config_obj.wps_pixie = saved_wps_pixie
        
        # WPS PIN
        saved_wps_pin = saved_config.get('wps_pin')
        if saved_wps_pin is not None:
            config_obj.wps_pin = saved_wps_pin
        
        # PMKID
        saved_use_pmkid = saved_config.get('use_pmkid')
        if saved_use_pmkid is not None:
            config_obj.dont_use_pmkid = not saved_use_pmkid
        
        # WPS only
        saved_wps_only = saved_config.get('wps_only')
        if saved_wps_only is not None:
            config_obj.wps_only = saved_wps_only
        
        # PMKID only
        saved_pmkid_only = saved_config.get('use_pmkid_only')
        if saved_pmkid_only is not None:
            config_obj.use_pmkid_only = saved_pmkid_only
        
        # Infinite mode
        saved_infinite = saved_config.get('infinite_mode')
        if saved_infinite is not None:
            config_obj.infinite_mode = saved_infinite
        
        # Attack max
        saved_attack_max = saved_config.get('attack_max')
        if saved_attack_max is not None:
            config_obj.attack_max = saved_attack_max
        
        # TUI mode
        saved_use_tui = saved_config.get('use_tui')
        if saved_use_tui is not None:
            current_use_tui = getattr(config_obj, 'use_tui', True)
            if current_use_tui != saved_use_tui:
                conflicts.append(
                    f"UI mode: command-line value overridden by session value"
                )
            config_obj.use_tui = saved_use_tui
        
        # Verbose level
        saved_verbose = saved_config.get('verbose')
        if saved_verbose is not None:
            config_obj.verbose = saved_verbose
        
        return {
            'warnings': warnings,
            'interface_changed': interface_changed,
            'conflicts': conflicts
        }

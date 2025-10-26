#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Attack View for wifite2 TUI.
Displays real-time attack progress with target info, status, and logs.
"""

import time
from typing import Optional, Dict, Any
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align

from .components import ProgressPanel, LogPanel, EncryptionBadge, SignalStrengthBar


class AttackView:
    """Interactive attack progress interface with real-time updates."""

    def __init__(self, tui_controller, target, session=None, target_state=None):
        """
        Initialize attack view.

        Args:
            tui_controller: TUIController instance for rendering
            target: Target object being attacked
            session: Optional SessionState for resumed sessions
            target_state: Optional TargetState for this specific target from session
        """
        self.tui = tui_controller
        self.target = target
        self.attack_type = "Unknown"
        self.attack_start_time = time.time()
        self.progress_percent = 0.0
        self.status_message = "Initializing..."
        self.metrics = {}
        self.log_panel = LogPanel(max_entries=1000)
        self.total_time = None  # Expected total time (optional)
        self._update_counter = 0  # Track updates for periodic cleanup
        self._last_render_time = 0  # Track last render for auto-refresh
        self._auto_refresh_interval = 0.5  # Auto-refresh every 0.5 seconds (faster updates)
        self.session = session  # Store session for resume status display
        self.target_state = target_state  # Store target state for attempt tracking

    def start(self):
        """Start the attack view and TUI controller."""
        if not self.tui.is_running:
            self.tui.start()
        self.attack_start_time = time.time()
        self._last_render_time = time.time()
        self._render()

    def stop(self):
        """Stop the attack view."""
        # View cleanup if needed
        pass

    def set_attack_type(self, attack_type: str):
        """
        Set the type of attack being performed.

        Args:
            attack_type: Attack type string (e.g., "WPA Handshake Capture")
        """
        self.attack_type = attack_type
        self._render()

    def update_progress(self, progress_data: Dict[str, Any]):
        """
        Update attack progress with new data.

        Args:
            progress_data: Dictionary containing progress information
                - progress: float (0.0 to 1.0) - optional
                - status: str - status message
                - metrics: dict - attack-specific metrics
                - total_time: int - expected total time in seconds (optional)
        """
        if 'progress' in progress_data:
            self.progress_percent = max(0.0, min(1.0, progress_data['progress']))

        if 'status' in progress_data:
            self.status_message = progress_data['status']

        if 'metrics' in progress_data:
            self.metrics.update(progress_data['metrics'])

        if 'total_time' in progress_data:
            self.total_time = progress_data['total_time']

        # Periodic memory cleanup
        self._update_counter += 1
        if self._update_counter % 100 == 0:
            self._cleanup_memory()

        self._render()

    def _cleanup_memory(self):
        """Clean up old data to prevent memory bloat during long attacks."""
        # Clean up old log entries (keep last 500)
        self.log_panel.cleanup_old_entries(keep_count=500)
        
        # Limit metrics dictionary size
        if len(self.metrics) > 50:
            # Keep only the most recent metrics (arbitrary limit)
            keys = list(self.metrics.keys())
            for key in keys[:-50]:
                del self.metrics[key]

    def add_log(self, message: str, timestamp: bool = True):
        """
        Add a log entry.

        Args:
            message: Log message to add
            timestamp: Whether to prepend timestamp
        """
        if timestamp:
            current_time = time.strftime("%H:%M:%S")
            formatted_message = f"[{current_time}] {message}"
        else:
            formatted_message = message

        self.log_panel.add_log(formatted_message)
        self._render()

    def clear_logs(self):
        """Clear all log entries."""
        self.log_panel.clear()
        self._render()

    def _should_auto_refresh(self) -> bool:
        """
        Check if view should auto-refresh to update elapsed time.
        
        Returns:
            True if enough time has passed since last render
        """
        current_time = time.time()
        return (current_time - self._last_render_time) >= self._auto_refresh_interval
    
    def refresh_if_needed(self):
        """
        Refresh the view if auto-refresh interval has passed.
        Call this periodically from attack loops to keep elapsed time updated.
        """
        if self._should_auto_refresh():
            self._render()
    
    def _render(self):
        """Render the complete attack interface."""
        if not self.tui.is_running:
            return

        # Update last render time
        self._last_render_time = time.time()

        # Create main layout
        layout = Layout()
        layout.split_column(
            Layout(name="target_info", size=4),  # Reduced from 5 to 4
            Layout(name="progress", size=8),     # Reduced from 10 to 8
            Layout(name="logs"),                 # Takes remaining space (more room now)
            Layout(name="footer", size=3)
        )

        # Render each section
        layout["target_info"].update(self._render_target_info())
        layout["progress"].update(self._render_progress())
        layout["logs"].update(self._render_logs())
        layout["footer"].update(self._render_footer())

        # Update TUI
        self.tui.update(layout)

    def _render_target_info(self) -> Panel:
        """
        Render target information panel.

        Returns:
            Rich Panel with target details
        """
        # Create target info table
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Label", style="bold cyan", width=12)
        table.add_column("Value", style="white")

        # ESSID
        essid = self.target.essid if self.target.essid else "<hidden>"
        table.add_row("ESSID:", essid)

        # BSSID
        table.add_row("BSSID:", self.target.bssid)

        # Channel and Encryption
        enc_badge = EncryptionBadge.render(self.target.encryption, self.target)
        table.add_row("Channel:", f"{self.target.channel}")
        
        # Add resume info if this is a resumed target
        if self.session and self.target_state:
            # Show attempt number
            attempt_text = Text()
            attempt_text.append("Attempt #", style="bold yellow")
            attempt_text.append(str(self.target_state.attempts + 1), style="yellow")
            table.add_row("Resume:", attempt_text)
            
            # Show original attack time if available
            if self.target_state.last_attempt:
                from datetime import datetime
                last_time = datetime.fromtimestamp(self.target_state.last_attempt)
                time_str = last_time.strftime("%Y-%m-%d %H:%M:%S")
                table.add_row("Last Try:", time_str)
        
        # Create a second column for encryption and power
        info_text = Text()
        info_text.append("Encryption: ", style="bold cyan")
        info_text.append(enc_badge)
        info_text.append("  |  ", style="bright_black")
        info_text.append("Power: ", style="bold cyan")
        
        # Power level
        power_dbm = self.target.power - 100 if self.target.power > 0 else self.target.power
        info_text.append(SignalStrengthBar.render(power_dbm))

        # Add resume indicator to title if this is a resumed session
        title_text = f"[bold cyan]Target: {essid}[/bold cyan]"
        if self.session:
            title_text = f"[bold magenta]RESUMED[/bold magenta] | {title_text}"

        return Panel(
            table,
            title=title_text,
            subtitle=info_text,
            border_style="cyan",
            padding=(0, 1)
        )

    def _render_progress(self) -> Panel:
        """
        Render attack progress panel.

        Returns:
            Rich Panel with progress information
        """
        elapsed_time = int(time.time() - self.attack_start_time)

        return ProgressPanel.render(
            attack_type=self.attack_type,
            elapsed_time=elapsed_time,
            progress_percent=self.progress_percent,
            status_message=self.status_message,
            metrics=self.metrics,
            total_time=self.total_time
        )

    def _render_logs(self) -> Panel:
        """
        Render log panel.

        Returns:
            Rich Panel with log entries
        """
        return self.log_panel.render(height=10)

    def _render_footer(self) -> Panel:
        """
        Render footer with keyboard shortcuts.

        Returns:
            Rich Panel with footer information
        """
        footer = Text()
        footer.append("[", style="bright_black")
        footer.append("Ctrl+C", style="bold yellow")
        footer.append("]", style="bright_black")
        footer.append(" Interrupt → (", style="white")
        footer.append("c", style="bold green")
        footer.append("ontinue / ", style="white")
        footer.append("s", style="bold yellow")
        footer.append("kip / ", style="white")
        footer.append("i", style="bold magenta")
        footer.append("gnore / ", style="white")
        footer.append("e", style="bold red")
        footer.append("xit)", style="white")

        return Panel(
            Align.center(footer),
            border_style="blue",
            padding=(0, 1)
        )

    def handle_input(self, key: str) -> Optional[str]:
        """
        Handle keyboard input during attack.

        Args:
            key: Key pressed by user

        Returns:
            Action string or None ('skip', 'help', etc.)
        """
        if key == '?':
            self.show_help()
            return 'help'
        # Ctrl+C is handled by the attack module itself
        return None

    def show_help(self):
        """Display help overlay."""
        from .components import HelpOverlay
        from ..util.input import KeyboardInput
        
        # Render help overlay
        help_panel = HelpOverlay.render(context='attack')
        
        # Update display with help
        self.tui.update(help_panel)
        
        # Wait for any key to dismiss
        with KeyboardInput() as kb:
            kb.get_key(timeout=30)  # 30 second timeout
        
        # Re-render normal view
        self._render()


class WEPAttackView(AttackView):
    """Specialized view for WEP attacks."""

    def __init__(self, tui_controller, target, session=None, target_state=None):
        super().__init__(tui_controller, target, session, target_state)
        self.attack_type = "WEP Attack"
        self.ivs_collected = 0
        self.ivs_needed = 10000  # Default
        self.crack_attempts = 0
        self.replay_active = False

    def update_ivs(self, ivs_collected: int, ivs_needed: int = None):
        """
        Update IVs collected for WEP attack.

        Args:
            ivs_collected: Number of IVs collected
            ivs_needed: Number of IVs needed (optional, uses stored value if not provided)
        """
        self.ivs_collected = ivs_collected
        if ivs_needed is not None:
            self.ivs_needed = ivs_needed

        progress = min(1.0, self.ivs_collected / self.ivs_needed) if self.ivs_needed > 0 else 0.0
        
        status = f'Collecting IVs ({self.ivs_collected:,}/{self.ivs_needed:,})'
        if self.replay_active:
            status += " [Replay active]"

        self.update_progress({
            'progress': progress,
            'status': status,
            'metrics': {
                'IVs Collected': f'{self.ivs_collected:,}',
                'IVs Needed': f'{self.ivs_needed:,}',
                'Crack Attempts': self.crack_attempts,
                'Replay': '✓' if self.replay_active else '✗'
            }
        })

    def update_crack_attempt(self, attempt_number: int, success: bool = False):
        """
        Update crack attempt status.

        Args:
            attempt_number: Current crack attempt number
            success: Whether the crack was successful
        """
        self.crack_attempts = attempt_number
        
        if success:
            status = "Key cracked successfully!"
            progress = 1.0
        else:
            status = f'Attempting to crack (attempt #{attempt_number})'
            progress = min(0.95, self.ivs_collected / self.ivs_needed) if self.ivs_needed > 0 else 0.5

        self.update_progress({
            'progress': progress,
            'status': status,
            'metrics': {
                'IVs Collected': f'{self.ivs_collected:,}',
                'Crack Attempts': attempt_number,
                'Status': 'Success' if success else 'In Progress'
            }
        })

    def set_replay_active(self, active: bool):
        """
        Set whether ARP replay is active.

        Args:
            active: Whether replay is active
        """
        self.replay_active = active
        self.update_ivs(self.ivs_collected)


class WPAAttackView(AttackView):
    """Specialized view for WPA attacks."""

    def __init__(self, tui_controller, target, session=None, target_state=None):
        super().__init__(tui_controller, target, session, target_state)
        self.attack_type = "WPA Handshake Capture"
        self.has_handshake = False
        self.clients = 0
        self.deauths_sent = 0
        self.capture_method = "airodump-ng"

    def update_handshake_status(self, has_handshake: bool, clients: int = None, deauths_sent: int = None):
        """
        Update handshake capture status.

        Args:
            has_handshake: Whether handshake has been captured
            clients: Number of clients detected (optional)
            deauths_sent: Number of deauth packets sent (optional)
        """
        self.has_handshake = has_handshake
        if clients is not None:
            self.clients = clients
        if deauths_sent is not None:
            self.deauths_sent = deauths_sent

        if has_handshake:
            status = "Handshake captured!"
            progress = 1.0
        elif self.clients == 0:
            status = "Waiting for clients..."
            progress = 0.2
        elif self.deauths_sent > 0:
            status = f"Deauthing clients (sent {self.deauths_sent})"
            progress = 0.6
        else:
            status = "Monitoring for handshake"
            progress = 0.4

        self.update_progress({
            'progress': progress,
            'status': status,
            'metrics': {
                'Clients': self.clients,
                'Deauths Sent': self.deauths_sent,
                'Handshake': '✓' if has_handshake else '✗',
                'Method': self.capture_method
            }
        })

    def set_capture_method(self, method: str):
        """
        Set the capture method being used.

        Args:
            method: Capture method (e.g., "airodump-ng", "tshark")
        """
        self.capture_method = method
        self.update_handshake_status(self.has_handshake)

    def increment_deauths(self, count: int = 1):
        """
        Increment deauth counter.

        Args:
            count: Number of deauths to add
        """
        self.deauths_sent += count
        self.update_handshake_status(self.has_handshake)


class WPSAttackView(AttackView):
    """Specialized view for WPS attacks."""

    def __init__(self, tui_controller, target, session=None, target_state=None):
        super().__init__(tui_controller, target, session, target_state)
        self.attack_type = "WPS Attack"
        self.pins_tried = 0
        self.total_pins = 11000  # Default for full PIN space
        self.current_pin = None
        self.pixie_dust_mode = False
        self.locked_out = False

    def update_pin_attempts(self, pins_tried: int, total_pins: int = None, current_pin: Optional[str] = None):
        """
        Update WPS PIN attempt progress.

        Args:
            pins_tried: Number of PINs tried
            total_pins: Total number of PINs to try (optional)
            current_pin: Current PIN being tested (optional)
        """
        self.pins_tried = pins_tried
        if total_pins is not None:
            self.total_pins = total_pins
        if current_pin is not None:
            self.current_pin = current_pin

        progress = self.pins_tried / self.total_pins if self.total_pins > 0 else 0.0
        
        if self.locked_out:
            status = "WPS locked out - attack stopped"
            progress = 0.0
        elif self.pixie_dust_mode:
            status = f'Pixie Dust attack in progress'
            progress = 0.5  # Indeterminate for pixie dust
        else:
            status = f'Testing PINs ({self.pins_tried:,}/{self.total_pins:,})'

        metrics = {
            'PINs Tried': f'{self.pins_tried:,}',
            'Total PINs': f'{self.total_pins:,}',
            'Mode': 'Pixie Dust' if self.pixie_dust_mode else 'PIN Brute Force'
        }
        
        if current_pin:
            metrics['Current PIN'] = current_pin

        if self.locked_out:
            metrics['Status'] = 'Locked Out'

        self.update_progress({
            'progress': progress,
            'status': status,
            'metrics': metrics
        })

    def set_pixie_dust_mode(self, enabled: bool):
        """
        Set whether pixie dust attack mode is active.

        Args:
            enabled: Whether pixie dust mode is active
        """
        self.pixie_dust_mode = enabled
        if enabled:
            self.attack_type = "WPS Pixie Dust Attack"
        else:
            self.attack_type = "WPS PIN Attack"
        self.update_pin_attempts(self.pins_tried)

    def set_locked_out(self, locked: bool):
        """
        Set whether WPS is locked out.

        Args:
            locked: Whether WPS is locked out
        """
        self.locked_out = locked
        self.update_pin_attempts(self.pins_tried)

    def update_pixie_dust_status(self, status: str):
        """
        Update pixie dust attack status.

        Args:
            status: Status message for pixie dust attack
        """
        self.update_progress({
            'progress': 0.5,
            'status': status,
            'metrics': {
                'Mode': 'Pixie Dust',
                'Status': status
            }
        })


class PMKIDAttackView(AttackView):
    """Specialized view for PMKID attacks."""

    def __init__(self, tui_controller, target, session=None, target_state=None):
        super().__init__(tui_controller, target, session, target_state)
        self.attack_type = "PMKID Capture"
        self.has_pmkid = False
        self.attempts = 0
        self.max_attempts = 10
        self.capture_tool = "hcxdumptool"

    def update_pmkid_status(self, has_pmkid: bool, attempts: int = None):
        """
        Update PMKID capture status.

        Args:
            has_pmkid: Whether PMKID has been captured
            attempts: Number of capture attempts (optional)
        """
        self.has_pmkid = has_pmkid
        if attempts is not None:
            self.attempts = attempts

        if has_pmkid:
            status = "PMKID captured successfully!"
            progress = 1.0
        elif self.attempts >= self.max_attempts:
            status = f"Failed to capture PMKID after {self.attempts} attempts"
            progress = 0.0
        else:
            status = f"Attempting to capture PMKID (attempt {self.attempts}/{self.max_attempts})"
            progress = min(0.9, self.attempts / self.max_attempts)

        self.update_progress({
            'progress': progress,
            'status': status,
            'metrics': {
                'Attempts': f'{self.attempts}/{self.max_attempts}',
                'PMKID': '✓' if has_pmkid else '✗',
                'Tool': self.capture_tool
            }
        })

    def set_capture_tool(self, tool: str):
        """
        Set the capture tool being used.

        Args:
            tool: Capture tool name (e.g., "hcxdumptool", "hcxpcaptool")
        """
        self.capture_tool = tool
        self.update_pmkid_status(self.has_pmkid)

    def increment_attempts(self):
        """Increment the attempt counter."""
        self.attempts += 1
        self.update_pmkid_status(self.has_pmkid)

    def set_max_attempts(self, max_attempts: int):
        """
        Set maximum number of attempts.

        Args:
            max_attempts: Maximum attempts to try
        """
        self.max_attempts = max_attempts
        self.update_pmkid_status(self.has_pmkid)


class WPA3AttackView(AttackView):
    """Specialized view for WPA3-SAE attacks."""

    def __init__(self, tui_controller, target, session=None, target_state=None):
        super().__init__(tui_controller, target, session, target_state)
        self.attack_type = "WPA3-SAE Attack"
        self.attack_strategy = "Unknown"
        self.downgrade_attempted = False
        self.downgrade_success = False
        self.sae_frames_captured = 0
        self.has_sae_handshake = False
        self.pmf_status = "unknown"
        self.is_transition = False
        self.clients = 0
        self.deauths_sent = 0

    def set_attack_strategy(self, strategy: str):
        """
        Set the WPA3 attack strategy being used.

        Args:
            strategy: Strategy name (e.g., "downgrade", "sae_capture", "passive", "dragonblood")
        """
        self.attack_strategy = strategy
        
        # Update attack type based on strategy
        if strategy == "downgrade":
            self.attack_type = "WPA3 Downgrade Attack"
        elif strategy == "sae_capture":
            self.attack_type = "WPA3-SAE Handshake Capture"
        elif strategy == "passive":
            self.attack_type = "WPA3-SAE Passive Capture"
        elif strategy == "dragonblood":
            self.attack_type = "WPA3 Dragonblood Exploit"
        else:
            self.attack_type = f"WPA3 Attack ({strategy})"
        
        self._update_display()

    def update_downgrade_status(self, attempted: bool, success: bool = False):
        """
        Update downgrade attack status.

        Args:
            attempted: Whether downgrade was attempted
            success: Whether downgrade was successful
        """
        self.downgrade_attempted = attempted
        self.downgrade_success = success
        self._update_display()

    def update_sae_capture_status(self, frames_captured: int, has_handshake: bool = False):
        """
        Update SAE handshake capture status.

        Args:
            frames_captured: Number of SAE frames captured
            has_handshake: Whether complete handshake has been captured
        """
        self.sae_frames_captured = frames_captured
        self.has_sae_handshake = has_handshake
        self._update_display()

    def update_client_status(self, clients: int, deauths_sent: int = None):
        """
        Update client and deauth status.

        Args:
            clients: Number of clients detected
            deauths_sent: Number of deauth packets sent (optional)
        """
        self.clients = clients
        if deauths_sent is not None:
            self.deauths_sent = deauths_sent
        self._update_display()

    def set_pmf_status(self, pmf_status: str):
        """
        Set PMF (Protected Management Frames) status.

        Args:
            pmf_status: PMF status ('required', 'optional', 'disabled')
        """
        self.pmf_status = pmf_status
        self._update_display()

    def set_transition_mode(self, is_transition: bool):
        """
        Set whether target is in WPA3 transition mode.

        Args:
            is_transition: Whether target supports both WPA2 and WPA3
        """
        self.is_transition = is_transition
        self._update_display()

    def _update_display(self):
        """Update the display with current WPA3 attack status."""
        # Determine status message based on attack strategy and state
        if self.attack_strategy == "downgrade":
            if self.downgrade_success:
                status = "Downgrade successful! Capturing WPA2 handshake..."
                progress = 0.7
            elif self.downgrade_attempted:
                status = "Downgrade failed, falling back to SAE capture"
                progress = 0.3
            else:
                status = "Attempting WPA3 → WPA2 downgrade..."
                progress = 0.2
        elif self.attack_strategy == "passive":
            if self.has_sae_handshake:
                status = "SAE handshake captured (passive mode)!"
                progress = 1.0
            else:
                status = f"Passive capture (PMF required) - waiting for clients..."
                progress = 0.4
        elif self.attack_strategy == "dragonblood":
            status = "Attempting Dragonblood vulnerability exploit..."
            progress = 0.5
        else:  # sae_capture or other
            if self.has_sae_handshake:
                status = "SAE handshake captured successfully!"
                progress = 1.0
            elif self.sae_frames_captured > 0:
                status = f"Capturing SAE frames ({self.sae_frames_captured} captured)..."
                progress = 0.6
            elif self.clients == 0:
                status = "Waiting for clients..."
                progress = 0.2
            else:
                status = "Monitoring for SAE authentication..."
                progress = 0.4

        # Build metrics dictionary
        metrics = {
            'Strategy': self.attack_strategy.replace('_', ' ').title(),
            'Clients': self.clients,
        }

        # Add transition mode indicator
        if self.is_transition:
            metrics['Mode'] = 'Transition (WPA2/WPA3)'
        else:
            metrics['Mode'] = 'WPA3-Only'

        # Add PMF status
        if self.pmf_status == 'required':
            metrics['PMF'] = '✓ Required (deauth disabled)'
        elif self.pmf_status == 'optional':
            metrics['PMF'] = '~ Optional'
        else:
            metrics['PMF'] = '✗ Disabled'

        # Add downgrade status if applicable
        if self.attack_strategy == "downgrade" or self.downgrade_attempted:
            if self.downgrade_success:
                metrics['Downgrade'] = '✓ Success'
            elif self.downgrade_attempted:
                metrics['Downgrade'] = '✗ Failed'
            else:
                metrics['Downgrade'] = 'In Progress'

        # Add SAE capture status
        if self.attack_strategy in ["sae_capture", "passive"] or self.sae_frames_captured > 0:
            metrics['SAE Frames'] = self.sae_frames_captured
            metrics['SAE Handshake'] = '✓' if self.has_sae_handshake else '✗'

        # Add deauth count if applicable
        if self.pmf_status != 'required' and self.deauths_sent > 0:
            metrics['Deauths Sent'] = self.deauths_sent

        self.update_progress({
            'progress': progress,
            'status': status,
            'metrics': metrics
        })

    def increment_deauths(self, count: int = 1):
        """
        Increment deauth counter.

        Args:
            count: Number of deauths to add
        """
        self.deauths_sent += count
        self._update_display()

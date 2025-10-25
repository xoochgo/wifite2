#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
TUI logging and debugging utilities for wifite2.
Provides logging capabilities for TUI events and errors.
"""

import os
import time
from datetime import datetime


class TUILogger:
    """Logger for TUI events and debugging."""

    _instance = None
    _enabled = False
    _log_file = None
    _debug_mode = False

    @classmethod
    def initialize(cls, enabled: bool = False, debug_mode: bool = False, log_file: str = None):
        """
        Initialize TUI logger.

        Args:
            enabled: Whether logging is enabled
            debug_mode: Whether debug mode is active
            log_file: Path to log file (default: /tmp/wifite_tui.log)
        """
        cls._enabled = enabled
        cls._debug_mode = debug_mode
        
        if enabled:
            if log_file is None:
                log_file = '/tmp/wifite_tui.log'
            cls._log_file = log_file
            
            # Create/clear log file
            try:
                with open(cls._log_file, 'w') as f:
                    f.write(f"=== Wifite TUI Log Started: {datetime.now()} ===\n")
            except Exception:
                cls._enabled = False

    @classmethod
    def log(cls, message: str, level: str = 'INFO'):
        """
        Log a message.

        Args:
            message: Message to log
            level: Log level (INFO, DEBUG, WARNING, ERROR)
        """
        if not cls._enabled:
            return

        if level == 'DEBUG' and not cls._debug_mode:
            return

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        log_line = f"[{timestamp}] [{level}] {message}\n"

        try:
            with open(cls._log_file, 'a') as f:
                f.write(log_line)
        except Exception:
            pass

    @classmethod
    def debug(cls, message: str):
        """Log a debug message."""
        cls.log(message, 'DEBUG')

    @classmethod
    def info(cls, message: str):
        """Log an info message."""
        cls.log(message, 'INFO')

    @classmethod
    def warning(cls, message: str):
        """Log a warning message."""
        cls.log(message, 'WARNING')

    @classmethod
    def error(cls, message: str, exception: Exception = None):
        """
        Log an error message.

        Args:
            message: Error message
            exception: Optional exception object
        """
        if exception:
            message = f"{message}: {str(exception)}"
        cls.log(message, 'ERROR')

    @classmethod
    def log_event(cls, event_type: str, details: str = None):
        """
        Log a TUI event.

        Args:
            event_type: Type of event (e.g., 'VIEW_CHANGE', 'KEY_PRESS', 'RENDER')
            details: Optional event details
        """
        message = f"EVENT: {event_type}"
        if details:
            message += f" - {details}"
        cls.debug(message)

    @classmethod
    def log_performance(cls, operation: str, duration: float):
        """
        Log performance metrics.

        Args:
            operation: Operation name
            duration: Duration in seconds
        """
        cls.debug(f"PERF: {operation} took {duration:.3f}s")

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if logging is enabled."""
        return cls._enabled

    @classmethod
    def is_debug_mode(cls) -> bool:
        """Check if debug mode is active."""
        return cls._debug_mode


# Convenience functions
def log_tui_event(event_type: str, details: str = None):
    """Log a TUI event."""
    TUILogger.log_event(event_type, details)


def log_tui_error(message: str, exception: Exception = None):
    """Log a TUI error."""
    TUILogger.error(message, exception)


def log_tui_debug(message: str):
    """Log a TUI debug message."""
    TUILogger.debug(message)

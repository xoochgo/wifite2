#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Output abstraction layer for wifite2
Manages switching between TUI and classic text output modes
"""

import sys
import os


class OutputManager:
    """
    Manages output mode selection and provides unified interface
    for both TUI and classic text output
    """
    
    _instance = None
    _mode = None
    _controller = None
    
    @classmethod
    def initialize(cls, mode='auto'):
        """
        Initialize output mode based on configuration
        
        Args:
            mode: 'auto', 'tui', or 'classic'
                - auto: Detect terminal capabilities and choose best mode
                - tui: Force TUI mode (will fail if not supported)
                - classic: Force classic text mode
        
        Returns:
            True if TUI mode is active, False if classic mode
        """
        try:
            if mode == 'auto':
                if cls._check_terminal_support():
                    try:
                        # Try to initialize TUI mode
                        cls._mode = 'tui'
                        # Test that we can create a controller
                        controller = cls.get_controller()
                        if controller is None:
                            raise RuntimeError("Failed to create TUI controller")
                        return True
                    except Exception as e:
                        # TUI initialization failed, fall back to classic
                        from ..util.color import Color
                        Color.pl('{!} {O}TUI initialization failed: %s{W}' % str(e))
                        Color.pl('{!} {O}Falling back to classic mode{W}')
                        cls._mode = 'classic'
                        cls._controller = None
                        return False
                else:
                    cls._mode = 'classic'
                    return False
            elif mode == 'tui':
                if not cls._check_terminal_support():
                    from ..util.color import Color
                    Color.pl('{!} {R}TUI mode requested but terminal does not support it{W}')
                    raise RuntimeError('TUI mode not supported by terminal')
                cls._mode = 'tui'
                return True
            else:  # classic
                cls._mode = 'classic'
                return False
        except Exception as e:
            # Any unexpected error - fall back to classic mode
            cls._mode = 'classic'
            cls._controller = None
            if mode == 'tui':
                # Re-raise if TUI was explicitly requested
                raise
            return False
    
    @classmethod
    def _check_terminal_support(cls):
        """
        Check if terminal supports TUI features
        
        Returns:
            True if terminal supports TUI, False otherwise
        """
        try:
            # Check if we're in a terminal (not piped/redirected)
            if not sys.stdout.isatty():
                return False
            
            # Check if TERM is set (required for terminal features)
            if not os.environ.get('TERM'):
                return False
            
            # Check for dumb terminal
            if os.environ.get('TERM') == 'dumb':
                return False
            
            # Try to import and test rich
            try:
                from rich.console import Console
                console = Console()
                
                # Check minimum terminal size (80x24)
                if console.width < 80 or console.height < 24:
                    return False
                
                # Check if terminal is actually interactive
                if not console.is_terminal:
                    return False
                
                return True
            except ImportError:
                # Rich library not available
                return False
            except Exception:
                # Any other error with rich
                return False
        except Exception:
            # Catch-all for any unexpected errors
            return False
    
    @classmethod
    def get_mode(cls):
        """
        Get current output mode
        
        Returns:
            'tui' or 'classic'
        """
        if cls._mode is None:
            cls.initialize()
        return cls._mode
    
    @classmethod
    def is_tui_mode(cls):
        """
        Check if TUI mode is active
        
        Returns:
            True if TUI mode, False if classic mode
        """
        # If not initialized, default to classic mode (safe default)
        if cls._mode is None:
            cls._mode = 'classic'
            return False
        return cls._mode == 'tui'
    
    @classmethod
    def get_controller(cls):
        """
        Get the TUI controller instance (only in TUI mode)
        
        Returns:
            TUIController instance or None if in classic mode
        """
        if cls._mode == 'tui' and cls._controller is None:
            try:
                from ..ui.tui import TUIController
                cls._controller = TUIController()
            except Exception as e:
                # Failed to create controller - fall back to classic
                from ..util.color import Color
                Color.pl('{!} {O}Failed to create TUI controller: %s{W}' % str(e))
                Color.pl('{!} {O}Falling back to classic mode{W}')
                cls._mode = 'classic'
                cls._controller = None
        return cls._controller
    
    @classmethod
    def get_scanner_view(cls):
        """
        Get appropriate scanner view based on current mode
        
        Returns:
            ScannerView (TUI) or ClassicScannerOutput (classic)
        """
        if cls.is_tui_mode():
            from ..ui.scanner_view import ScannerView
            return ScannerView(cls.get_controller())
        else:
            from ..ui.classic import ClassicScannerOutput
            return ClassicScannerOutput()
    
    @classmethod
    def get_selector_view(cls, targets):
        """
        Get appropriate selector view based on current mode
        
        Args:
            targets: List of Target objects to select from
        
        Returns:
            SelectorView (TUI) or ClassicSelectorOutput (classic)
        """
        if cls.is_tui_mode():
            from ..ui.selector_view import SelectorView
            return SelectorView(cls.get_controller(), targets)
        else:
            from ..ui.classic import ClassicSelectorOutput
            return ClassicSelectorOutput(targets)
    
    @classmethod
    def get_attack_view(cls, target):
        """
        Get appropriate attack view based on current mode
        
        Args:
            target: Target object being attacked
        
        Returns:
            AttackView (TUI) or ClassicAttackOutput (classic)
        """
        if cls.is_tui_mode():
            from ..ui.attack_view import AttackView
            return AttackView(cls.get_controller(), target)
        else:
            from ..ui.classic import ClassicAttackOutput
            return ClassicAttackOutput(target)
    
    @classmethod
    def cleanup(cls):
        """
        Clean up output resources
        Should be called on exit
        """
        try:
            if cls._controller:
                cls._controller.stop()
                cls._controller = None
        except Exception:
            # Ignore errors during cleanup
            pass
        finally:
            cls._mode = None
            cls._controller = None


# Convenience function for checking terminal support
def check_terminal_support():
    """
    Check if terminal supports TUI features
    
    Returns:
        True if terminal supports TUI, False otherwise
    """
    return OutputManager._check_terminal_support()

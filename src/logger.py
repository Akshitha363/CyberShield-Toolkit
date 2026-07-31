"""
Security Logger Module
----------------------
Purpose:
    Provides centralized security logging to record security incidents, authentication 
    attempts, anomalies, and administrative events. Logs are formatted with 
    precise ISO 8601 timestamps and written to both standard output and a persistent log file.

Cybersecurity Relevance:
    Audit trails and log files are crucial for digital forensics, incident response, 
    and compliance. Without reliable timestamps and level classification (e.g., INFO, 
    WARNING, ALERT), security operations center (SOC) analysts cannot reconstruct 
    timelines or detect security breaches.

Algorithms:
    - Custom formatter configuration for the built-in python logging library.
    - Automated directory creation to prevent pathing issues.
"""

import logging
import os
from datetime import datetime

class SecurityLogger:
    """
    Handles file-based and terminal-based logging of security events with precise timestamps.
    """
    
    def __init__(self, log_file: str = "logs/security.log", log_level: str = "INFO"):
        """
        Initializes the logger, sets up directories, and attaches stream and file handlers.
        
        Args:
            log_file (str): Path to write the security log file.
            log_level (str): The threshold level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL).
        """
        self.log_file = log_file
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Ensure target logging directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except OSError as e:
                print(f"[!] Error creating log directory {log_dir}: {e}")

        # Initialize logging
        self.logger = logging.getLogger("CyberAuthLogger")
        self.logger.setLevel(self.log_level)
        
        # Prevent adding duplicate handlers if logger is already configured
        if not self.logger.handlers:
            self._setup_handlers()

    def _setup_handlers(self):
        """
        Configures file and terminal output formatting with precise timestamp.
        """
        # Formatter format: [YYYY-MM-DD HH:MM:SS] [LEVEL] Message
        # We manually specify the date format to avoid standard millisecond output if not required,
        # but keep it precise and ISO-compliant.
        formatter = logging.Formatter(
            fmt='[%(asctime)s] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # File Handler (append mode)
        try:
            file_handler = logging.FileHandler(self.log_file, mode='a', encoding='utf-8')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(self.log_level)
            self.logger.addHandler(file_handler)
        except (IOError, PermissionError) as e:
            print(f"[!] Warning: Could not write logs to file {self.log_file} ({e}). Logging to console only.")

        # Console Handler (standard output)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(self.log_level)
        self.logger.addHandler(console_handler)

    def log_info(self, message: str):
        """Logs informational events, such as regular user actions or program startup."""
        self.logger.info(message)

    def log_warning(self, message: str):
        """Logs warnings, such as minor validation errors or anomalous patterns."""
        self.logger.warning(message)

    def log_alert(self, message: str):
        """Logs severe events requiring immediate action, such as account lockouts or active attacks."""
        self.logger.critical(f"ALERT: {message}")

    def log_error(self, message: str):
        """Logs runtime errors, exception recoveries, or file access issues."""
        self.logger.error(message)

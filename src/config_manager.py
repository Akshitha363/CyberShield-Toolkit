"""
Config Manager Module
---------------------
Purpose:
    Provides centralized loading and parsing of the `config.json` file.
    Ensures safe default configurations are loaded in case of errors.

Cybersecurity Relevance:
    In security tools, hardcoded values (like thresholds, file paths, and retry limits)
    reduce adaptability and prevent operators from customizing settings for different environments.
    Centralizing configuration prevents hardcoding secrets and facilitates auditing.

Algorithms:
    - JSON parsing with exception handling.
    - Fallback mechanism to ensure stability if config.json is corrupted or absent.
"""

import json
import os

class ConfigManager:
    """
    Manages loading and retrieval of configuration settings for the toolkit.
    """
    
    DEFAULT_CONFIG = {
        "project_name": "Cybersecurity Authentication Toolkit",
        "version": "1.0.0",
        "logging": {
            "log_file": "logs/security.log",
            "log_level": "INFO"
        },
        "lockout_simulator": {
            "max_attempts": 3,
            "cooldown_seconds": 15
        },
        "brute_force_detector": {
            "fail_threshold": 5,
            "csv_path": "data/sample_logins.csv"
        },
        "password_guessing_detector": {
            "unique_password_threshold": 3,
            "csv_path": "data/sample_logins.csv"
        },
        "password_checker": {
            "dictionary_path": "data/dictionary.txt",
            "min_length": 8
        }
    }

    def __init__(self, config_path: str = "config.json"):
        """
        Initializes the ConfigManager and loads configurations.
        
        Args:
            config_path (str): Path to the JSON configuration file.
        """
        self.config_path = config_path
        self.config = self.load_config()

    def load_config(self) -> dict:
        """
        Loads configuration from the specified JSON file. Falls back to default values on error.
        
        Returns:
            dict: The dictionary loaded from config.json or the DEFAULT_CONFIG.
        """
        if not os.path.exists(self.config_path):
            # If config file is missing, return fallback defaults
            return self.DEFAULT_CONFIG
        
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                loaded_data = json.load(f)
                
                # Basic validation: ensure critical sections are present
                validated_config = self.DEFAULT_CONFIG.copy()
                for key, val in loaded_data.items():
                    if isinstance(val, dict) and key in validated_config:
                        # Deep merge dictionary configurations
                        validated_config[key].update(val)
                    else:
                        validated_config[key] = val
                return validated_config
        except (json.JSONDecodeError, IOError, PermissionError):
            # Return defaults if JSON is corrupted or file reading fails
            return self.DEFAULT_CONFIG

    def get(self, key: str, default=None):
        """
        Retrieves a top-level configuration key.
        
        Args:
            key (str): The configuration section/setting name.
            default: The fallback value if key does not exist.
            
        Returns:
            Any value associated with the key.
        """
        return self.config.get(key, default)

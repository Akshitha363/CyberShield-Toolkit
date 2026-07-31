"""
Module 4: Brute Force Attack Detector
-------------------------------------
Purpose:
    Analyzes historical or current authentication logs in CSV format to identify
    suspicious source IPs that exhibit signatures of automated brute-force attacks.

Cybersecurity Relevance:
    Brute-force attacks involve systematically testing multiple credentials from a single host.
    By parsing authentication logs, security tools can identify and dynamically block
    (e.g., using firewalls/iptables) offending IPs. A critical security signature
    is a high fail-to-success ratio, or a success occurring immediately after many failures (compromise).

Algorithms:
    - Log aggregation: Grouping log entries by `ip_address` in a dictionary (Hash Map).
    - Threshold comparisons: Filtering records where failed attempt count exceeds the defined limits.
    - Time Complexity: O(N) where N is the number of rows in the CSV log file.
"""

import csv
import os
from datetime import datetime
from typing import Dict, List, Tuple

class BruteForceDetector:
    """
    Ingests authentication CSV files to analyze brute-force attack trends and flag malicious IPs.
    """
    
    def __init__(self, csv_path: str = "data/sample_logins.csv", fail_threshold: int = 3):
        """
        Initializes the detector with configuration parameters.
        """
        self.csv_path = csv_path
        self.fail_threshold = fail_threshold

    def parse_logs(self) -> List[Dict[str, str]]:
        """
        Reads and parses the login attempts CSV file.
        
        Returns:
            List[Dict]: List of raw login attempts logs.
        """
        attempts = []
        if not os.path.exists(self.csv_path):
            return attempts
            
        try:
            with open(self.csv_path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Clean keys to prevent formatting discrepancies
                    cleaned_row = {key.strip(): val.strip() for key, val in row.items()}
                    attempts.append(cleaned_row)
        except (IOError, csv.Error, PermissionError) as e:
            print(f"[!] Error parsing CSV file {self.csv_path}: {e}")
            
        return attempts

    def analyze(self) -> Tuple[Dict[str, Dict[str, any]], List[str]]:
        """
        Analyzes log entries for brute-force indicators.
        
        Returns:
            Tuple[Dict, List]: (IP statistics dictionary, list of alert messages)
        """
        logs = self.parse_logs()
        ip_stats: Dict[str, Dict[str, any]] = {}
        alerts: List[str] = []
        
        # Aggregate logs by IP Address
        for entry in logs:
            ip = entry.get("ip_address")
            status = entry.get("status", "").upper()
            username = entry.get("username", "")
            timestamp = entry.get("timestamp", "")
            
            if not ip:
                continue
                
            if ip not in ip_stats:
                ip_stats[ip] = {
                    "total_attempts": 0,
                    "failures": 0,
                    "successes": 0,
                    "targeted_usernames": set(),
                    "compromised": False,
                    "last_attempt_time": timestamp
                }
                
            stats = ip_stats[ip]
            stats["total_attempts"] += 1
            stats["targeted_usernames"].add(username)
            stats["last_attempt_time"] = timestamp
            
            if status == "FAILURE":
                stats["failures"] += 1
            elif status == "SUCCESS":
                stats["successes"] += 1
                # If an IP has already failed a lot, and then gets a success, it could be a compromise!
                if stats["failures"] >= self.fail_threshold:
                    stats["compromised"] = True

        # Generate Alerts for IPs exceeding limits
        for ip, stats in ip_stats.items():
            # Convert set of usernames to list for JSON/dictionary serializability
            stats["targeted_usernames"] = list(stats["targeted_usernames"])
            
            if stats["failures"] >= self.fail_threshold:
                alert_msg = (
                    f"Suspicious IP: {ip} exceeded failure threshold "
                    f"({stats['failures']}/{self.fail_threshold} failures). "
                    f"Targeted usernames: {', '.join(stats['targeted_usernames'])}."
                )
                if stats["compromised"]:
                    alert_msg += " WARNING: Success observed after failures. Potential breach!"
                    
                alerts.append(alert_msg)
                
        return ip_stats, alerts

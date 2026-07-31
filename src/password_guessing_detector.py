"""
Module 5: Password Guessing / Dictionary Attack Detector
---------------------------------------------------------
Purpose:
    Analyzes authentication logs to identify usernames experiencing multiple password
    guesses. Detects patterns typical of dictionary attacks and credential stuffing,
    where a single target username is hit with a variety of passwords.

Cybersecurity Relevance:
    Unlike simple brute force (which checks many combinations from a single IP),
    password guessing/dictionary attacks might be distributed across multiple IPs
    (botnets) targeting specific accounts. Identifying usernames targeted by multiple
    unique passwords helps identify targeted accounts that need reset/MFA enforcement.

Algorithms:
    - Group log attempts by `username`.
    - Keep track of unique passwords tried per username using a Hash Set.
    - Check passwords against common dictionary files to tag dictionary attacks.
    - Time Complexity: O(N) where N is the number of rows in the CSV log file.
"""

import csv
import os
from typing import Dict, List, Tuple

class PasswordGuessingDetector:
    """
    Analyzes authentication attempts to spot dictionary attacks and credential guessing targeting users.
    """

    def __init__(self, csv_path: str = "data/sample_logins.csv", unique_password_threshold: int = 3, dictionary_path: str = "data/dictionary.txt"):
        """
        Initializes the detector with threshold configurations.
        """
        self.csv_path = csv_path
        self.unique_password_threshold = unique_password_threshold
        self.dictionary_path = dictionary_path
        self.common_passwords = self._load_dictionary()

    def _load_dictionary(self) -> set:
        """Loads dictionary list for O(1) matching checks."""
        common_set = set()
        if os.path.exists(self.dictionary_path):
            try:
                with open(self.dictionary_path, "r", encoding="utf-8") as f:
                    for line in f:
                        cleaned = line.strip().lower()
                        if cleaned:
                            common_set.add(cleaned)
            except IOError:
                pass
        return common_set

    def parse_logs(self) -> List[Dict[str, str]]:
        """Parses login attempts CSV."""
        attempts = []
        if not os.path.exists(self.csv_path):
            return attempts
        try:
            with open(self.csv_path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cleaned_row = {key.strip(): val.strip() for key, val in row.items()}
                    attempts.append(cleaned_row)
        except IOError as e:
            print(f"[!] Error parsing CSV file {self.csv_path}: {e}")
        return attempts

    def analyze(self) -> Tuple[Dict[str, Dict[str, any]], List[str]]:
        """
        Identifies usernames experiencing credential stuffing or dictionary attacks.
        
        Returns:
            Tuple[Dict, List]: (Username statistics dictionary, list of alert messages)
        """
        logs = self.parse_logs()
        user_stats: Dict[str, Dict[str, any]] = {}
        alerts: List[str] = []

        for entry in logs:
            username = entry.get("username")
            password = entry.get("password_tried", "")
            status = entry.get("status", "").upper()
            ip = entry.get("ip_address", "")
            
            if not username:
                continue
                
            username = username.strip().lower()
            
            if username not in user_stats:
                user_stats[username] = {
                    "total_attempts": 0,
                    "unique_passwords": set(),
                    "failures": 0,
                    "successes": 0,
                    "ips": set(),
                    "dictionary_words_used": 0
                }
                
            stats = user_stats[username]
            stats["total_attempts"] += 1
            stats["ips"].add(ip)
            
            if password:
                stats["unique_passwords"].add(password)
                if password.lower() in self.common_passwords:
                    stats["dictionary_words_used"] += 1
                    
            if status == "FAILURE":
                stats["failures"] += 1
            elif status == "SUCCESS":
                stats["successes"] += 1

        # Check thresholds and raise alerts
        for username, stats in user_stats.items():
            stats["unique_passwords"] = list(stats["unique_passwords"])
            stats["ips"] = list(stats["ips"])
            unique_pw_count = len(stats["unique_passwords"])
            
            if unique_pw_count >= self.unique_password_threshold:
                alert_msg = (
                    f"Credential Guessing: User '{username}' was targeted with {unique_pw_count} "
                    f"unique passwords across {len(stats['ips'])} IP addresses. "
                    f"Dictionary words tried: {stats['dictionary_words_used']}."
                )
                if stats["dictionary_words_used"] > 0:
                    alert_msg += " SIGNATURE: Dictionary Attack behavior identified."
                    
                alerts.append(alert_msg)

        return user_stats, alerts

"""
Module 1: Password Strength Checker
-----------------------------------
Purpose:
    Analyzes user-supplied passwords to calculate entropy, assess strength,
    identify vulnerabilities (sequential runs, repeated characters, dictionary matches),
    and estimate theoretical offline cracking time.

Cybersecurity Relevance:
    Weak passwords are a primary vector for identity theft and corporate breaches.
    By quantifying the strength of a password via entropy and dictionary detection,
    organizations can enforce compliance with security standards (e.g., NIST SP 800-63).

Mathematical Formula (Entropy):
    H = L * log2(R)
    where:
        L = length of the password
        R = size of the character pool (charset size)
            - Lowercase letters (a-z): 26
            - Uppercase letters (A-Z): 26
            - Digits (0-9): 10
            - Special symbols: 32 (standard printable symbols)
"""

import math
import os
from typing import Tuple, List, Dict

class PasswordChecker:
    """
    Evaluates password security, patterns, and brute-force resistance.
    """
    
    def __init__(self, dictionary_path: str = "data/dictionary.txt"):
        """
        Initializes the PasswordChecker and loads the local dictionary list.
        
        Args:
            dictionary_path (str): File path to a list of weak/common passwords.
        """
        self.dictionary_path = dictionary_path
        self.common_passwords = self._load_dictionary()

    def _load_dictionary(self) -> set:
        """
        Loads the list of common weak passwords to memory for O(1) average lookup times.
        
        Returns:
            set: Set of lowercase common passwords.
        """
        common_set = set()
        if os.path.exists(self.dictionary_path):
            try:
                with open(self.dictionary_path, "r", encoding="utf-8") as f:
                    for line in f:
                        cleaned = line.strip().lower()
                        if cleaned:
                            common_set.add(cleaned)
            except (IOError, PermissionError) as e:
                # Silently proceed; common password list will be empty
                pass
        return common_set

    def calculate_entropy(self, password: str) -> Tuple[float, int]:
        """
        Determines the mathematical entropy of a password.
        
        Entropy represents the bits of uncertainty. A high entropy indicates
        high randomness and resistance to guessing.
        
        Time Complexity: O(N) where N is password length, to analyze characters.
        
        Args:
            password (str): The password string.
            
        Returns:
            Tuple[float, int]: (Entropy bits, Charset pool size R)
        """
        if not password:
            return 0.0, 0
            
        has_lower = False
        has_upper = False
        has_digit = False
        has_special = False
        
        for char in password:
            if char.islower():
                has_lower = True
            elif char.isupper():
                has_upper = True
            elif char.isdigit():
                has_digit = True
            else:
                has_special = True
                
        # Calculate charset size (R)
        r_pool = 0
        if has_lower:
            r_pool += 26
        if has_upper:
            r_pool += 26
        if has_digit:
            r_pool += 10
        if has_special:
            r_pool += 32
            
        if r_pool == 0:
            return 0.0, 0
            
        length = len(password)
        entropy = length * math.log2(r_pool)
        return round(entropy, 2), r_pool

    def detect_sequential_patterns(self, password: str) -> List[str]:
        """
        Detects sequential patterns like alphabetical, numerical, or keyboard runs.
        
        Algorithms:
            Looks for sequences of 3 or more characters that have contiguous ASCII values,
            or common keyboard runs like 'qwerty'.
        
        Time Complexity: O(N) where N is password length.
        """
        issues = []
        lower_pass = password.lower()
        
        # 1. Keyboard sequences
        keyboard_runs = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
        for run in keyboard_runs:
            for i in range(len(lower_pass) - 2):
                triple = lower_pass[i:i+3]
                if triple in run:
                    issues.append(f"Keyboard sequence found: '{triple}'")
                    break  # Stop checking this run once a match is found
                    
        # 2. ASCII sequential sequences (e.g. 'abc', '123', 'cba')
        for i in range(len(password) - 2):
            char1, char2, char3 = password[i], password[i+1], password[i+2]
            val1, val2, val3 = ord(char1), ord(char2), ord(char3)
            
            # Forward sequence (abc, 123)
            if val2 - val1 == 1 and val3 - val2 == 1:
                issues.append(f"Sequential sequence found: '{char1}{char2}{char3}'")
                break
            # Backward sequence (cba, 321)
            elif val1 - val2 == 1 and val2 - val3 == 1:
                issues.append(f"Reverse sequential sequence found: '{char1}{char2}{char3}'")
                break
                
        return list(set(issues)) # Return unique issues

    def detect_repeated_characters(self, password: str) -> List[str]:
        """
        Checks for contiguous repeating characters (e.g., 'aaa', '1111').
        
        Time Complexity: O(N).
        """
        issues = []
        count = 1
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                count += 1
                if count == 3:
                    issues.append(f"Repeated character group detected: '{password[i]}'")
            else:
                count = 1
        return list(set(issues))

    def check_dictionary_match(self, password: str) -> bool:
        """
        Checks if the password itself is in the weak common passwords file.
        
        Time Complexity: O(1) average lookup in hashset.
        """
        return password.lower() in self.common_passwords

    def estimate_crack_time(self, entropy: float) -> str:
        """
        Estimates the time required to crack the password using standard offline attacks.
        
        Assumptions:
            An attacker is conducting a fast offline brute-force attack (e.g., hashcat on
            a high-end multi-GPU cluster capable of 10 billion (10^10) attempts per second).
            
        Calculation:
            Number of attempts = 2^entropy
            Time (seconds) = attempts / hash_rate
        """
        if entropy == 0:
            return "Instantaneous"
            
        attempts = 2 ** entropy
        hash_rate = 10**10  # 10 billion guesses/second (modern GPU cluster)
        seconds = attempts / hash_rate
        
        if seconds < 1:
            return "Instantaneous (less than a second)"
        elif seconds < 60:
            return f"{round(seconds, 2)} seconds"
        elif seconds < 3600:
            return f"{round(seconds / 60, 2)} minutes"
        elif seconds < 86400:
            return f"{round(seconds / 3600, 2)} hours"
        elif seconds < 31536000:
            return f"{round(seconds / 86400, 2)} days"
        elif seconds < 3153600000:
            return f"{round(seconds / 31536000, 2)} years"
        else:
            return "Centuries (virtually uncrackable by pure brute-force)"

    def evaluate_strength(self, password: str) -> Dict[str, any]:
        """
        Compiles the complete safety evaluation details for a password.
        
        Returns:
            Dict: Contains entropy, strength level, crack time, and recommendations.
        """
        length = len(password)
        entropy, pool = self.calculate_entropy(password)
        is_common = self.check_dictionary_match(password)
        sequential = self.detect_sequential_patterns(password)
        repeated = self.detect_repeated_characters(password)
        
        # Base rating logic
        # Weak: entropy < 30 or length < 8 or is common
        # Moderate: entropy 30-59 and length >= 8
        # Strong: entropy 60-79 and no major patterns
        # Excellent: entropy >= 80 and no patterns
        
        rating = "Weak"
        color_code = "RED"
        
        if length >= 8 and not is_common and entropy >= 30:
            if entropy < 60:
                rating = "Moderate"
                color_code = "YELLOW"
            elif entropy < 80:
                rating = "Strong"
                color_code = "GREEN"
            else:
                rating = "Excellent"
                color_code = "CYAN"
                
        # Generate recommendations
        recommendations = []
        if length < 12:
            recommendations.append("Increase length to at least 12-16 characters (length is the best way to boost entropy).")
        if is_common:
            recommendations.append("This password is on the common blacklist! Choose a unique password.")
        if pool < 50:
            recommendations.append("Combine uppercase, lowercase, numbers, and special symbols to increase character diversity.")
        if sequential:
            recommendations.append("Avoid sequences like '123', 'abc', or contiguous keyboard structures.")
        if repeated:
            recommendations.append("Avoid repeating characters consecutively (e.g. 'aaa').")
            
        return {
            "password_length": length,
            "entropy": entropy,
            "pool_size": pool,
            "rating": rating,
            "color_code": color_code,
            "is_common": is_common,
            "sequential_issues": sequential,
            "repeated_issues": repeated,
            "estimated_crack_time": self.estimate_crack_time(entropy),
            "recommendations": recommendations
        }

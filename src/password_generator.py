"""
Module 3: Secure Password Generator
-----------------------------------
Purpose:
    Generates cryptographically secure, randomized passwords based on custom criteria 
    (length, character sets). Ensures that at least one character from each selected
    pool is included to guarantee complexity, and evaluates the resulting strength.

Cybersecurity Relevance:
    Standard random generators (like Python's `random` module) use Mersenne Twister,
    which is predictable if a sequence of generated values is observed.
    This module uses Python's `secrets` module, which utilizes system-level CSPRNGs 
    (Cryptographically Secure Pseudo-Random Number Generators) like `/dev/urandom`.
    These are unpredictable and suitable for security keys, salts, and passwords.

Algorithms:
    - Fisher-Yates shuffle equivalent (`secrets.SystemRandom().shuffle`) to mix character selection.
    - Guaranteed inclusion enforcement.
"""

import string
import secrets
from typing import Tuple, Dict

# Attempt to import pyperclip for clipboard operations
try:
    import pyperclip
    PYCLIPPER_SUPPORTED = True
except ImportError:
    PYCLIPPER_SUPPORTED = False

class SecurePasswordGenerator:
    """
    Creates high-entropy passwords using system-level cryptographic randomness.
    """
    
    def __init__(self):
        """Initializes generator settings."""
        # Cryptographically secure randomizer selection
        self.crypto_rand = secrets.SystemRandom()

    def generate(self, length: int, use_upper: bool, use_lower: bool, use_digits: bool, use_symbols: bool) -> Tuple[str, str]:
        """
        Generates a secure password based on user choices.
        
        Args:
            length (int): Total character count.
            use_upper (bool): Include uppercase.
            use_lower (bool): Include lowercase.
            use_digits (bool): Include digits.
            use_symbols (bool): Include special characters.
            
        Returns:
            Tuple[str, str]: (Generated password, rating)
        """
        pools = []
        mandatory_chars = []
        
        if use_lower:
            pools.append(string.ascii_lowercase)
            mandatory_chars.append(self.crypto_rand.choice(string.ascii_lowercase))
        if use_upper:
            pools.append(string.ascii_uppercase)
            mandatory_chars.append(self.crypto_rand.choice(string.ascii_uppercase))
        if use_digits:
            pools.append(string.digits)
            mandatory_chars.append(self.crypto_rand.choice(string.digits))
        if use_symbols:
            symbols = "!@#$%^&*()-_=+[]{}|;:,.<>/?"
            pools.append(symbols)
            mandatory_chars.append(self.crypto_rand.choice(symbols))
            
        if not pools:
            raise ValueError("At least one character set must be selected.")
            
        if length < len(mandatory_chars):
            raise ValueError(f"Password length must be at least {len(mandatory_chars)} to contain all selected classes.")
            
        # Combine character sets
        full_pool = "".join(pools)
        
        # Fill remaining characters
        remaining_len = length - len(mandatory_chars)
        random_chars = [self.crypto_rand.choice(full_pool) for _ in range(remaining_len)]
        
        # Combine and shuffle so mandatory characters are not at the beginning
        assembled_list = mandatory_chars + random_chars
        self.crypto_rand.shuffle(assembled_list)
        
        generated_password = "".join(assembled_list)
        return generated_password

    def copy_to_clipboard(self, text: str) -> bool:
        """
        Saves the text to the clipboard if pyperclip is available.
        
        Returns:
            bool: Success status.
        """
        if PYCLIPPER_SUPPORTED:
            try:
                pyperclip.copy(text)
                return True
            except Exception:
                return False
        return False

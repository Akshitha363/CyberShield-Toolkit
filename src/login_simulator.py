"""
Module 2: Login Lockout Simulator
---------------------------------
Purpose:
    Simulates a secure authentication gateway that tracks consecutive failed logins,
    enforces a strict account lockout policy, and implements a temporary cooldown timer.

Cybersecurity Relevance:
    Account lockout policies mitigate brute-force and dictionary attacks on login portals.
    By enforcing a maximum attempt limit (e.g., 3 attempts) combined with a cooldown period,
    attacks are significantly slowed down, rendering automated tools ineffective.

Algorithms:
    - Time-based cooldown check: Lockout expires when `current_time - lockout_timestamp > cooldown_seconds`.
    - Counter reset on successful authentication.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

class LoginLockoutSimulator:
    """
    Simulates a secure user login process with attempt tracking, lockouts, and cooldown.
    """
    
    def __init__(self, max_attempts: int = 3, cooldown_seconds: int = 15):
        """
        Initializes the simulator with configuration settings.
        """
        self.max_attempts = max_attempts
        self.cooldown_seconds = cooldown_seconds
        
        # User base database representation (Simulated)
        # username: password
        self.user_database = {
            "sec_admin": "AdminPass123!",
            "analyst_bob": "AnalysisSec99#",
            "audit_alice": "Verification2026!"
        }
        
        # Security state tracking
        self.attempts_counter: Dict[str, int] = {}
        self.lockout_timestamp: Dict[str, float] = {}
        self.login_history: List[Dict[str, any]] = []

    def check_lockout_status(self, username: str) -> Tuple[bool, int]:
        """
        Determines if a user account is currently locked out and calculates remaining cooldown.
        
        Args:
            username (str): Target user name.
            
        Returns:
            Tuple[bool, int]: (is_locked, remaining_seconds)
        """
        if username not in self.lockout_timestamp:
            return False, 0
            
        lock_time = self.lockout_timestamp[username]
        elapsed = time.time() - lock_time
        remaining = int(self.cooldown_seconds - elapsed)
        
        if remaining > 0:
            return True, remaining
        else:
            # Cooldown duration expired; release lockout
            del self.lockout_timestamp[username]
            self.attempts_counter[username] = 0
            return False, 0

    def attempt_login(self, username: str, password_attempt: str) -> Tuple[bool, str]:
        """
        Executes a login attempt, evaluating credential match and account state.
        
        Args:
            username (str): Entered username.
            password_attempt (str): Plaintext password guess.
            
        Returns:
            Tuple[bool, str]: (Success status, log message)
        """
        # 1. Clean username input
        username = username.strip().lower()
        
        # 2. Check if account exists
        if username not in self.user_database:
            msg = f"Failed login attempt for non-existent user '{username}'."
            self._record_history(username, False, "NON_EXISTENT_USER")
            return False, msg
            
        # 3. Check lockout
        is_locked, remaining = self.check_lockout_status(username)
        if is_locked:
            msg = f"Login blocked for locked user '{username}'. Cooldown remaining: {remaining}s."
            self._record_history(username, False, "BLOCKED_BY_LOCKOUT")
            return False, msg

        # Get actual password
        actual_password = self.user_database[username]
        
        # 4. Validate credentials
        if password_attempt == actual_password:
            # Login Success
            self.attempts_counter[username] = 0
            msg = f"User '{username}' successfully authenticated."
            self._record_history(username, True, "SUCCESS")
            return True, msg
        else:
            # Login Failed
            current_failures = self.attempts_counter.get(username, 0) + 1
            self.attempts_counter[username] = current_failures
            
            if current_failures >= self.max_attempts:
                self.lockout_timestamp[username] = time.time()
                msg = f"User '{username}' exceeded max attempts. Account LOCKED for {self.cooldown_seconds}s."
                self._record_history(username, False, "LOCKOUT_TRIGGERED")
            else:
                remaining_attempts = self.max_attempts - current_failures
                msg = f"Failed credentials for user '{username}'. Attempts remaining: {remaining_attempts}."
                self._record_history(username, False, f"FAILURE ({remaining_attempts} remaining)")
                
            return False, msg

    def _record_history(self, username: str, success: bool, reason: str):
        """
        Stores attempts history internally with timestamping.
        """
        self.login_history.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "success": success,
            "status": reason
        })

    def get_login_history(self) -> List[Dict[str, any]]:
        """Returns the login history log array."""
        return self.login_history

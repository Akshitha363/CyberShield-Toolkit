"""
Cybersecurity Authentication Toolkit
-----------------------------------
Main CLI Dashboard Entrypoint

Purpose:
    Serves as the interactive CLI console dashboard connecting the modular features
    of the Cybersecurity Authentication Toolkit.

Cybersecurity Relevance:
    Security tools must be intuitive and easy to navigate for operators while
    adhering to clean security paradigms, detailed event logging, and configuration
    flexibility.
"""

import sys
import os
import json
from datetime import datetime

# Import local modules
from src.config_manager import ConfigManager
from src.logger import SecurityLogger
from src.utils import TerminalUI, InputValidator
from src.password_checker import PasswordChecker
from src.login_simulator import LoginLockoutSimulator
from src.password_generator import SecurePasswordGenerator
from src.brute_force_detector import BruteForceDetector
from src.password_guessing_detector import PasswordGuessingDetector

class SecurityToolkitApp:
    """
    Main application orchestrating toolkit logic and user menus.
    """
    
    def __init__(self):
        # 1. Load Configurations
        self.config_manager = ConfigManager("config.json")
        
        # 2. Setup Central Logging
        log_settings = self.config_manager.get("logging", {})
        self.logger = SecurityLogger(
            log_file=log_settings.get("log_file", "logs/security.log"),
            log_level=log_settings.get("log_level", "INFO")
        )
        
        # 3. Instantiate Sub-Modules
        self.password_checker = PasswordChecker(
            dictionary_path=self.config_manager.get("password_checker", {}).get("dictionary_path", "data/dictionary.txt")
        )
        
        lockout_settings = self.config_manager.get("lockout_simulator", {})
        self.lockout_simulator = LoginLockoutSimulator(
            max_attempts=lockout_settings.get("max_attempts", 3),
            cooldown_seconds=lockout_settings.get("cooldown_seconds", 15)
        )
        
        self.password_generator = SecurePasswordGenerator()
        
        # Load detector settings
        self.brute_force_settings = self.config_manager.get("brute_force_detector", {})
        self.guessing_settings = self.config_manager.get("password_guessing_detector", {})
        
        self.logger.log_info("Cybersecurity Authentication Toolkit initialized successfully.")

    def run(self):
        """Runs the main terminal UI event loop."""
        while True:
            TerminalUI.show_banner()
            print("Select an option from the security dashboard:\n")
            print(" [1] Password Strength Checker")
            print(" [2] Login Lockout Simulator")
            print(" [3] Secure Password Generator")
            print(" [4] Brute Force Attack Detection (CSV Logs)")
            print(" [5] Password Guessing / Dictionary Attack Detection")
            print(" [6] View Security Log File")
            print(" [7] Exit Toolkit")
            print("-" * 70)
            
            choice = InputValidator.get_validated_int("Select module [1-7]: ", 1, 7)
            
            if choice == 1:
                self.run_password_checker()
            elif choice == 2:
                self.run_login_simulator()
            elif choice == 3:
                self.run_password_generator()
            elif choice == 4:
                self.run_brute_force_detector()
            elif choice == 5:
                self.run_password_guessing_detector()
            elif choice == 6:
                self.view_security_logs()
            elif choice == 7:
                TerminalUI.print_info("Exiting Security Toolkit. Stay secure!")
                self.logger.log_info("Cybersecurity Authentication Toolkit closed by administrator.")
                sys.exit(0)
                
            input("\nPress [Enter] to return to the main dashboard...")

    # ==========================================
    # MODULE UI WRAPPERS
    # ==========================================

    def run_password_checker(self):
        """UI wrapper for Module 1."""
        TerminalUI.print_highlight("\n--- MODULE 1: Password Strength Checker ---")
        password = input("Enter password to evaluate (input is hidden or visible): ").strip()
        if not password:
            TerminalUI.print_error("Password cannot be empty!")
            return
            
        TerminalUI.show_progress_bar(duration=0.6, description="Analyzing password structure")
        
        eval_results = self.password_checker.evaluate_strength(password)
        
        print("\n" + "=" * 50)
        print(" PASSWORD SECURITY AUDIT REPORT")
        print("=" * 50)
        print(f"Length:               {eval_results['password_length']} chars")
        print(f"Unique Pool size (R): {eval_results['pool_size']}")
        print(f"Mathematical Entropy: {eval_results['entropy']} bits")
        
        # Color-coded strength rating display
        rating = eval_results['rating']
        if rating == "Excellent":
            TerminalUI.print_success(f"Strength Rating:      {rating}")
        elif rating == "Strong":
            TerminalUI.print_success(f"Strength Rating:      {rating}")
        elif rating == "Moderate":
            TerminalUI.print_warning(f"Strength Rating:      {rating}")
        else:
            TerminalUI.print_error(f"Strength Rating:      {rating}")
            
        print(f"Est. Crack Time:      {eval_results['estimated_crack_time']}")
        print(f"Dictionary Blacklist: {'MATCHED (CRITICAL VULNERABILITY)' if eval_results['is_common'] else 'CLEAN (Not in common database)'}")
        
        if eval_results['sequential_issues']:
            print(f"\nSequential Issues:")
            for issue in eval_results['sequential_issues']:
                TerminalUI.print_warning(f"  - {issue}")
                
        if eval_results['repeated_issues']:
            print(f"\nRepeating Issues:")
            for issue in eval_results['repeated_issues']:
                TerminalUI.print_warning(f"  - {issue}")
                
        if eval_results['recommendations']:
            print(f"\nRemediation Recommendations:")
            for rec in eval_results['recommendations']:
                print(f"  * {rec}")
                
        print("=" * 50)
        self.logger.log_info(f"Password checker executed. Evaluated strength: {rating} ({eval_results['entropy']} bits entropy).")

    def run_login_simulator(self):
        """UI wrapper for Module 2."""
        TerminalUI.print_highlight("\n--- MODULE 2: Login Lockout Simulator ---")
        TerminalUI.print_info("Simulating target portal users: 'sec_admin', 'analyst_bob', 'audit_alice'")
        
        username = InputValidator.get_non_empty_string("Enter username: ")
        password = input("Enter password: ")
        
        # Simulate Login
        success, message = self.lockout_simulator.attempt_login(username, password)
        
        if success:
            TerminalUI.print_success(message)
            self.logger.log_info(message)
        else:
            if "LOCKED" in message or "cooldown" in message.lower():
                TerminalUI.print_error(message)
                self.logger.log_alert(message)
            else:
                TerminalUI.print_warning(message)
                self.logger.log_warning(message)
                
        # Interactive Option to view system login attempt records
        if InputValidator.get_validated_bool("\nView simulator login attempt records? (y/n): "):
            history = self.lockout_simulator.get_login_history()
            print("\nTimestamp            | Username      | Success | Reason/Status")
            print("-" * 75)
            for record in history:
                success_str = "YES" if record['success'] else "NO"
                print(f"{record['timestamp']}  | {record['username']:<13} | {success_str:<7} | {record['status']}")

    def run_password_generator(self):
        """UI wrapper for Module 3."""
        TerminalUI.print_highlight("\n--- MODULE 3: Secure Password Generator ---")
        
        length = InputValidator.get_validated_int("Enter target password length (min 4, max 128): ", 4, 128)
        
        print("\nSelect character classes to include:")
        use_lower = InputValidator.get_validated_bool("Include Lowercase letters (a-z)? (y/n): ")
        use_upper = InputValidator.get_validated_bool("Include Uppercase letters (A-Z)? (y/n): ")
        use_digits = InputValidator.get_validated_bool("Include Numbers (0-9)? (y/n): ")
        use_symbols = InputValidator.get_validated_bool("Include Symbols (!@#$%^&*)? (y/n): ")
        
        try:
            password = self.password_generator.generate(
                length=length,
                use_upper=use_upper,
                use_lower=use_lower,
                use_digits=use_digits,
                use_symbols=use_symbols
            )
            
            # Strength Audit of generated password
            eval_res = self.password_checker.evaluate_strength(password)
            
            TerminalUI.print_success("\nPassword generated successfully!")
            print(f"Generated Password:  {password}")
            print(f"Entropy Score:       {eval_res['entropy']} bits")
            print(f"Audited Strength:    {eval_res['rating']}")
            
            # Clipboard copying helper
            copied = self.password_generator.copy_to_clipboard(password)
            if copied:
                TerminalUI.print_success("Password copied directly to your clipboard!")
            else:
                TerminalUI.print_info("Note: Clipboard access unsupported or disabled. Copy manually.")
                
            self.logger.log_info(f"Generated secure password of length {length} (entropy: {eval_res['entropy']} bits).")
            
        except ValueError as e:
            TerminalUI.print_error(str(e))

    def run_brute_force_detector(self):
        """UI wrapper for Module 4."""
        TerminalUI.print_highlight("\n--- MODULE 4: Brute Force Attack Detection ---")
        csv_file = self.brute_force_settings.get("csv_path", "data/sample_logins.csv")
        threshold = self.brute_force_settings.get("fail_threshold", 5)
        
        TerminalUI.print_info(f"Ingesting log CSV file: {csv_file}")
        TerminalUI.print_info(f"Configured failed threshold: {threshold} failures")
        
        TerminalUI.show_progress_bar(duration=0.8, description="Parsing CSV logs")
        
        # Ingest and analyze
        detector = BruteForceDetector(csv_path=csv_file, fail_threshold=threshold)
        ip_stats, alerts = detector.analyze()
        
        print("\n" + "=" * 60)
        print(" BRUTE FORCE SCAN REPORT SUMMARY")
        print("=" * 60)
        print(f"Log File Inspected:  {csv_file}")
        print(f"Total Unique IPs:     {len(ip_stats)}")
        print(f"Alerts Triggered:    {len(alerts)}")
        print("-" * 60)
        
        # Display aggregated results
        for ip, stats in ip_stats.items():
            targeted = ", ".join(stats['targeted_usernames'])
            comp_status = "COMPROMISED" if stats['compromised'] else "NO BREACH"
            print(f"IP: {ip:<15} | Fails: {stats['failures']:<2} | Targeted: {targeted:<15} | Status: {comp_status}")
            
        if alerts:
            TerminalUI.print_highlight("\nSYSTEM SECURITY ALERTS GENERATED:")
            for alert in alerts:
                TerminalUI.print_error(f"  [!] {alert}")
                self.logger.log_alert(alert)
        else:
            TerminalUI.print_success("\nNo suspicious brute-force activities detected.")
            
        # Optional report export
        if InputValidator.get_validated_bool("\nExport summary to JSON report? (y/n): "):
            report_name = f"reports/brute_force_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            os.makedirs("reports", exist_ok=True)
            try:
                with open(report_name, "w") as rf:
                    json.dump({"timestamp": datetime.now().isoformat(), "statistics": ip_stats, "alerts": alerts}, rf, indent=4)
                TerminalUI.print_success(f"Report exported to {report_name}")
            except IOError as e:
                TerminalUI.print_error(f"Export failed: {e}")

    def run_password_guessing_detector(self):
        """UI wrapper for Module 5."""
        TerminalUI.print_highlight("\n--- MODULE 5: Password Guessing Detection ---")
        csv_file = self.guessing_settings.get("csv_path", "data/sample_logins.csv")
        threshold = self.guessing_settings.get("unique_password_threshold", 3)
        dict_file = self.config_manager.get("password_checker", {}).get("dictionary_path", "data/dictionary.txt")
        
        TerminalUI.print_info(f"Ingesting log CSV file: {csv_file}")
        TerminalUI.print_info(f"Unique password threshold: {threshold}")
        
        TerminalUI.show_progress_bar(duration=0.8, description="Analyzing credential stuffing patterns")
        
        detector = PasswordGuessingDetector(
            csv_path=csv_file,
            unique_password_threshold=threshold,
            dictionary_path=dict_file
        )
        user_stats, alerts = detector.analyze()
        
        print("\n" + "=" * 60)
        print(" PASSWORD GUESSING SCAN REPORT SUMMARY")
        print("=" * 60)
        print(f"Log File Inspected:  {csv_file}")
        print(f"Total Unique Users:  {len(user_stats)}")
        print(f"Alerts Triggered:    {len(alerts)}")
        print("-" * 60)
        
        for username, stats in user_stats.items():
            ips = ", ".join(stats['ips'])
            print(f"User: {username:<13} | Fails: {stats['failures']:<2} | Unique Passwords tried: {len(stats['unique_passwords']):<2} | IPs: {ips}")
            
        if alerts:
            TerminalUI.print_highlight("\nSYSTEM SECURITY ALERTS GENERATED:")
            for alert in alerts:
                TerminalUI.print_error(f"  [!] {alert}")
                self.logger.log_alert(alert)
        else:
            TerminalUI.print_success("\nNo suspicious credential guessing attacks detected.")
            
        # Optional report export
        if InputValidator.get_validated_bool("\nExport summary to JSON report? (y/n): "):
            report_name = f"reports/guessing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            os.makedirs("reports", exist_ok=True)
            try:
                with open(report_name, "w") as rf:
                    # Clean sets and format for JSON
                    cleaned_stats = {}
                    for u, s in user_stats.items():
                        cleaned_stats[u] = s
                    json.dump({"timestamp": datetime.now().isoformat(), "statistics": cleaned_stats, "alerts": alerts}, rf, indent=4)
                TerminalUI.print_success(f"Report exported to {report_name}")
            except IOError as e:
                TerminalUI.print_error(f"Export failed: {e}")

    def view_security_logs(self):
        """Displays the tail of the security logs file."""
        log_settings = self.config_manager.get("logging", {})
        log_file = log_settings.get("log_file", "logs/security.log")
        
        TerminalUI.print_highlight(f"\n--- Reading security log: {log_file} ---")
        if not os.path.exists(log_file):
            TerminalUI.print_warning("No logs found yet. Perform some actions first!")
            return
            
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                # Print last 20 log entries
                print("-" * 80)
                for line in lines[-20:]:
                    print(line.strip())
                print("-" * 80)
        except (IOError, PermissionError) as e:
            TerminalUI.print_error(f"Could not read security log file: {e}")

if __name__ == "__main__":
    try:
        app = SecurityToolkitApp()
        app.run()
    except KeyboardInterrupt:
        print("\n\n[!] Program interrupted by administrative user. Shutting down securely.")
        sys.exit(0)

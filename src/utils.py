"""
Utility Module
--------------
Purpose:
    Provides formatting, interface, and input validation helper functions.
    Implements colored output support (using Colorama), secure/valid input prompts,
    custom ASCII arts, and terminal progress bar simulators.

Cybersecurity Relevance:
    Robust input validation prevents prompt-injection attacks, command-injection attacks, 
    and format-string vulnerabilities. Interactive terminal programs must handle all
    user responses gracefully without crashing, preserving service availability.
"""

import sys
import time
from colorama import init, Fore, Style

# Initialize colorama for Windows/Unix terminal coloring auto-reset
init(autoreset=True)

class TerminalUI:
    """
    Handles terminal styling, coloring, banners, progress bars, and formatted alerts.
    """
    
    @staticmethod
    def show_banner():
        """Displays the toolkit's main ASCII banner in terminal colors."""
        banner = f"""
{Fore.CYAN}{Style.BRIGHT}======================================================================
{Fore.RED}{Style.BRIGHT}   ______      __                 ___          __  __  
{Fore.RED}{Style.BRIGHT}  / ____/_  __/ /_  ___  _____   /   |  __  __/ /_/ /_ 
{Fore.RED}{Style.BRIGHT} / /   / / / / __ \\/ _ \\/ ___/  / /| | / / / / __/ __ \\
{Fore.RED}{Style.BRIGHT}/ /___/ /_/ / /_/ /  __/ /     / ___ |/ /_/ / /_/ / / /
{Fore.RED}{Style.BRIGHT}\\____/\\__, /_.___/\\___/_/     /_/  |_|\\__,_/\\__/_/ /_/ 
{Fore.RED}{Style.BRIGHT}     /____/                                            
{Fore.CYAN}{Style.BRIGHT}
         [+] Cybersecurity Authentication Toolkit v1.0.0 [+]
         [+] Developed for CyberSecurity Education       [+]
======================================================================{Style.RESET_ALL}"""
        print(banner)

    @staticmethod
    def print_success(message: str):
        """Prints a success message in green."""
        print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

    @staticmethod
    def print_error(message: str):
        """Prints an error message in red."""
        print(f"{Fore.RED}[!] {message}{Style.RESET_ALL}")

    @staticmethod
    def print_warning(message: str):
        """Prints a warning message in yellow."""
        print(f"{Fore.YELLOW}[*] {message}{Style.RESET_ALL}")

    @staticmethod
    def print_info(message: str):
        """Prints an informational message in cyan."""
        print(f"{Fore.CYAN}[i] {message}{Style.RESET_ALL}")

    @staticmethod
    def print_highlight(message: str):
        """Prints a highlighted message in magenta."""
        print(f"{Fore.MAGENTA}{Style.BRIGHT}{message}{Style.RESET_ALL}")

    @staticmethod
    def show_progress_bar(duration: float = 1.0, steps: int = 20, description: str = "Scanning"):
        """
        Displays a standard visual progress bar in the console to simulate processing.
        
        Args:
            duration (float): Total animation run duration in seconds.
            steps (int): Total number of segments in the progress bar.
            description (str): Label prefix.
        """
        delay = duration / steps
        for i in range(1, steps + 1):
            percent = int((i / steps) * 100)
            bar = "#" * i + "-" * (steps - i)
            sys.stdout.write(f"\r{Fore.CYAN}{description}: [{bar}] {percent}%")
            sys.stdout.flush()
            time.sleep(delay)
        print(f"\n{Fore.GREEN}[+] Done!{Style.RESET_ALL}")


class InputValidator:
    """
    Ensures program inputs are clean, secure, and conform to target types.
    """
    
    @staticmethod
    def get_validated_int(prompt: str, min_val: int = None, max_val: int = None) -> int:
        """
        Repeatedly prompts for a positive integer within bounds.
        """
        while True:
            try:
                user_input = input(prompt).strip()
                val = int(user_input)
                if min_val is not None and val < min_val:
                    TerminalUI.print_error(f"Input must be at least {min_val}.")
                    continue
                if max_val is not None and val > max_val:
                    TerminalUI.print_error(f"Input cannot exceed {max_val}.")
                    continue
                return val
            except ValueError:
                TerminalUI.print_error("Invalid input. Please enter a valid integer.")

    @staticmethod
    def get_validated_bool(prompt: str) -> bool:
        """
        Prompts for a Yes/No question and returns a boolean value.
        """
        while True:
            user_input = input(prompt).strip().lower()
            if user_input in ['y', 'yes', '1', 'true']:
                return True
            if user_input in ['n', 'no', '0', 'false']:
                return False
            TerminalUI.print_error("Invalid response. Please enter 'y' (yes) or 'n' (no).")

    @staticmethod
    def get_non_empty_string(prompt: str) -> str:
        """
        Prompts for a non-empty string.
        """
        while True:
            user_input = input(prompt).strip()
            if user_input:
                return user_input
            TerminalUI.print_error("Input cannot be empty. Please enter a value.")

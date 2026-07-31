# Cybersecurity Authentication Toolkit

A high-quality, professional terminal-based cybersecurity toolkit designed to evaluate, simulate, and analyze authentication vulnerabilities and attacks. Built with robust Object-Oriented and Modular Python paradigms.

## Features
1. **Password Strength Checker**: Computes mathematical entropy ($H = L \log_2 R$), estimates cracking time on standard GPU clusters, checks common blacklist words, and detects sequential and repeating characters.
2. **Login Lockout Simulator**: Simulates secure portal authentication, counts consecutive failures, enforces lockout policies, and implements a cooldown timer.
3. **Secure Password Generator**: Generates cryptographic secure passwords using `secrets` (CSPRNG) and rates entropy.
4. **Brute Force Detector**: Ingests authentication logs from CSV to spot aggressive IP failure attempts and flags potential intrusions.
5. **Password Guessing Detector**: Identifies credential stuffing attacks targeting specific usernames with multiple passwords.
6. **Detailed Log Auditor**: Standardized ISO 8601 logging mechanism recording actions to `logs/security.log`.

---

## Folder Structure
```
CyberAuth/
├── config.json                     # JSON Config Settings
├── requirements.txt                # Dependencies (colorama, pyperclip)
├── main.py                         # Program Console UI Entry point
├── README.md                       # Documentation
├── project_report.md               # High-quality academic project report
├── flowcharts_and_architecture.md  # Architectural layout & flowcharts
├── data/
│   ├── sample_logins.csv           # CSV dataset for brute force analysis
│   └── dictionary.txt              # Blacklisted weak passwords
├── logs/
│   └── security.log                # System security audit trail
└── src/
    ├── __init__.py
    ├── config_manager.py           # Configuration loader
    ├── logger.py                   # Central logging framework
    ├── utils.py                    # Terminal styling & validators
    ├── password_checker.py         # Password evaluation engine
    ├── login_simulator.py          # Portal lockout simulation
    ├── password_generator.py       # CSPRNG generator
    ├── brute_force_detector.py     # Aggregation and IP detector
    └── password_guessing_detector.py # Account stuffing detector
```

---

## Setup and Execution

### 🖥️ Option 1: Terminal Console Application (Python)

#### Prerequisites
- Python 3.8+ installed on your system.

#### Install Dependencies
Run the following command in your terminal to install the necessary libraries:
```bash
pip install -r requirements.txt
```

#### Run CLI Dashboard
Run the toolkit from the root directory:
```bash
python main.py
```

---

### 🌐 Option 2: Web Dashboard Console (HTML/JS)
To run the premium web dashboard, simply double-click the `web/index.html` file or open it in any web browser:
```
c:/Users/gasik/Desktop/CyberAuth/web/index.html
```
No installation or local web server is required. Runs entirely client-side.

---

## Configuration Settings (`config.json`)
You can tweak settings dynamically in `config.json` without modifying code:
- `cooldown_seconds`: The duration an account is locked after consecutive failures.
- `max_attempts`: Number of retries allowed before triggering lockout.
- `fail_threshold`: Number of failures from an IP required to trigger a brute force alert.
- `unique_password_threshold`: Limit of distinct password attempts on a single user.

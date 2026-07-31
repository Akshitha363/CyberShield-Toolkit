# PROJECT REPORT: Cybersecurity Authentication Toolkit

**Course Module**: Python for Cybersecurity  
**Target Audience**: Academic Evaluators & Security Practitioners  
**Developer**: Security Engineering Student  

---

## 1. Executive Summary
Authentication mechanisms form the primary gateway of modern software applications, making them primary targets for cybercriminals. Common attack vectors include automated brute-forcing, dictionary attacks, and credential stuffing. 

This project, titled **Cybersecurity Authentication Toolkit**, implements a comprehensive suite of utilities designed to analyze password robustness, simulate brute-force defense limits (account lockout and cooldowns), and detect patterns of attack from raw security log data. By applying strict Software Architecture principles, modular Object-Oriented Programming (OOP), and clean standard libraries, this codebase demonstrates how to model production-grade security logic.

---

## 2. System Architecture & Modular Design
The project is built around a decoupled architecture where concerns are strictly separated:

1. **Config & Log Layer**: `config_manager.py` loads dynamic parameters from `config.json` while `logger.py` enforces structured audit trails to prevent data mutation and simplify diagnostics.
2. **Logic Core**: Individual security components (`password_checker.py`, `login_simulator.py`, etc.) implement modular rules with clear exception containment.
3. **Presenter Interface**: `main.py` presents an interactive ASCII Dashboard and handles console coloring using `colorama`.

```
                    +---------------------------+
                    |          main.py          |
                    |    (Console Dashboard)    |
                    +-------------+-------------+
                                  |
            +---------------------+---------------------+
            |                     |                     |
  +---------v----------+ +--------v---------+ +---------v----------+
  | password_checker.py| |login_simulator.py| |password_generator.py|
  +---------+----------+ +--------+---------+ +---------+----------+
            |                     |                     |
            +---------------------+---------------------+
                                  |
            +---------------------+---------------------+
            |                                           |
  +---------v----------+                      +---------v----------+
  |  brute_force.py    |                      |guessing_detector.py|
  +--------------------+                      +--------------------+
```

---

## 3. Algorithm Specifications & Math Foundations

### A. Shannon Entropy Formula
To quantify the randomness of a password, we utilize Shannon's entropy calculation:
$$H = L \log_2 R$$
Where:
- $L$ is the length of the string.
- $R$ is the size of the character pool based on alphabet subsets present (uppercase, lowercase, numbers, symbols).

For example, a password `A1#b` has length 4 and contains characters from all four sets ($R = 94$ characters). Its entropy is:
$$H = 4 \log_2(94) \approx 26.22 \text{ bits}$$

### B. Crack Time Estimation
Crack time estimation assumes a high-speed offline dictionary or brute-force attack utilizing a multi-GPU cracking cluster (e.g., hashcat) operating at $10^{10}$ hashes per second.
$$\text{Seconds} = \frac{2^{H}}{10^{10}}$$

### C. Pattern Detection
To avoid simple patterns that bypass length filters:
- **Sequential Run Check**: Uses $O(N)$ ASCII comparison checking if three consecutive letters contain values with delta $= 1$ or $-1$ (e.g., `abc` or `321`).
- **Repeating Characters**: Counts matches where character $C_n == C_{n-1}$.

---

## 4. Evaluation and Security Analysis
From a security evaluation standpoint, this toolkit addresses the core issues highlighted by OWASP and NIST:
- **Lockout Policy**: Proving that lockouts stop automated attacks, but showing the trade-off of Denial-of-Service (DoS) where lockouts can be used to lock real users out maliciously.
- **CSPRNG over PRNG**: Using Python's `secrets` module ensures random selections cannot be predicted by external attackers observing past numbers.
- **Log Integrity**: System security logs must include timestamps and level tags so that they can be easily digested by SIEM (Security Information and Event Management) tools.

---

## 5. Challenges Encountered During Development
1. **Ensuring CSPRNG Distribution**: Guaranteeing that the secure password generator contained at least one character from each selected class without making the distribution pattern predictable (solved by generating required characters, filling the remaining length, and applying a secure shuffle).
2. **Decoupled Architecture for Web & Terminal**: Maintaining identical detection logic between a stateless web frontend (using JavaScript) and a stateful Python CLI console (solved by mapping identical structures for Shannon Entropy calculations and CSV parsing aggregators in both languages).
3. **Optimizing Log Aggregation**: Parsing large CSV arrays client-side without degrading web application responsiveness (solved by implementing $O(N)$ linear scans using JavaScript hash sets).

---

## 6. Suggestions for Future Improvements
1. **Dynamic Firewall Integration**: Implementing an automated active-defense module that calls local firewall APIs (like `iptables` or Windows Defender Firewall) to automatically block flagged attacker IPs.
2. **Cryptographic Salting and Hashing**: Storing user credentials in a persistent database using advanced hashing algorithms (e.g., Argon2id or bcrypt) instead of plaintext mock variables.
3. **Distributed Threat Intelligence Ingestion**: Allowing the detectors to parse multiple raw formats (JSON logs, Syslog, Web Server access logs) and query online threat feeds (like AlienVault OTX) to check flagged IP reputations.

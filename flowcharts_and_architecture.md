# Toolkit Workflows & Architecture Diagrams

This document contains flowcharts mapping out the logic implemented within the Cybersecurity Authentication Toolkit.

---

## 1. Password Strength Evaluation Flow

```mermaid
graph TD
    A[Start: User Enters Password] --> B[Check Dictionary Blacklist data/dictionary.txt]
    B -->|Found| C[Flag as CRITICAL WEAKNESS / Weak Rating]
    B -->|Not Found| D[Calculate Character Pool Size R]
    D --> E[Calculate Shannon Entropy H = L * log2 R]
    E --> F[Check Repeating Characters & Sequential Keyboard Patterns]
    F --> G[Categorize Rating: Weak, Moderate, Strong, Excellent]
    G --> H[Estimate Crack Time based on 10^10 hashes/sec]
    H --> I[Generate Remediation Suggestions]
    I --> J[Log Event & Display Report]
```

---

## 2. Login Lockout & Cooldown Flow

```mermaid
graph TD
    A[Start: Login Attempt] --> B{Account Locked?}
    B -->|Yes| C{Cooldown Expired?}
    C -->|No| D[Reject Login: Lockout Active]
    C -->|Yes| E[Reset Attempt Counter]
    B -->|No| F[Compare Input Password with Database]
    F -->|Match| G[Reset Counter & Authenticate Successfully]
    F -->|Mismatch| H[Increment Attempt Counter]
    H --> I{Attempts >= Max Attempts?}
    I -->|Yes| J[Set Lockout Timestamp & Flag Locked]
    I -->|No| K[Display Attempts Remaining]
```

---

## 3. Brute Force IP Detection Flow

```mermaid
graph TD
    A[Start: Ingest CSV Logs] --> B[Read Line by Line]
    B --> C[Aggregate Attempts & Failures per Source IP]
    C --> D{Failures >= Config Threshold?}
    D -->|Yes| E[Generate Warning Alert for IP]
    D -->|No| F[Keep as Low Risk]
    E --> G{Success recorded after failures?}
    G -->|Yes| H[Flag as HIGH ALERT: Potential Intrusion Breach]
    G -->|No| I[Flag as Suspicious Activity Only]
    H --> J[Export Security Reports & Log Alerts]
    I --> J
```

/**
 * Cybersecurity Authentication Toolkit - Frontend Dashboard Application
 * Implements Module 1 to 5 interactively.
 */

document.addEventListener("DOMContentLoaded", () => {
    // ==========================================
    // GLOBAL STATE & SYSTEM INITIALIZATION
    // ==========================================
    
    // Loaded dictionary set for O(1) common password checks
    const commonPasswords = new Set([
        "password", "123456", "123456789", "12345", "12345678", "1234",
        "qwerty", "password123", "admin", "letmein", "welcome", "login",
        "1234567", "security", "system", "root", "administrator",
        "password1", "pass123", "secret"
    ]);

    // Simulated user database for authentication lockout simulator
    const userDatabase = {
        "sec_admin": "AdminPass123!",
        "analyst_bob": "AnalysisSec99#",
        "audit_alice": "Verification2026!"
    };

    // System metrics counters
    let securityWarningCount = 0;
    let criticalAlertCount = 0;

    // Live clock loop
    function updateClock() {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');
        
        const clockEl = document.getElementById("live-clock");
        if (clockEl) {
            clockEl.querySelector("span").textContent = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
        }
    }
    setInterval(updateClock, 1000);
    updateClock();

    // Central logger function simulating python logs
    function appendCentralLog(level, message) {
        const container = document.getElementById("central-logs-container");
        if (!container) return;
        
        const now = new Date();
        const timeStr = now.toTimeString().split(' ')[0];
        
        const entry = document.createElement("div");
        entry.className = `log-entry log-${level.toLowerCase()}`;
        
        // Update stats warning cards
        if (level === "WARNING") {
            securityWarningCount++;
            document.getElementById("dash-warning-count").textContent = securityWarningCount;
        } else if (level === "ALERT" || level === "ERROR") {
            criticalAlertCount++;
            document.getElementById("dash-alert-count").textContent = criticalAlertCount;
        }

        entry.innerHTML = `<span class="log-time">[${timeStr}]</span> <span class="log-tag">[${level}]</span> ${message}`;
        container.appendChild(entry);
        container.scrollTop = container.scrollHeight;
    }

    // Navigation logic between tabs
    const navItems = document.querySelectorAll(".nav-item");
    const tabPanes = document.querySelectorAll(".tab-pane");
    const tabTitle = document.getElementById("current-tab-title");
    const tabSubtitle = document.getElementById("current-tab-subtitle");

    const tabMeta = {
        "dashboard": { title: "Overview Dashboard", subtitle: "Real-time security analytics and event logs" },
        "checker": { title: "Password Strength Checker", subtitle: "Live mathematical entropy audit (Module 1)" },
        "simulator": { title: "Login Lockout Simulator", subtitle: "Mock authentication gateway and rate limits (Module 2)" },
        "generator": { title: "Secure Password Generator", subtitle: "CSPRNG cryptographic password generation (Module 3)" },
        "bruteforce": { title: "Brute Force Detector", subtitle: "Parse authentication logs for rapid failures per IP (Module 4)" },
        "guessing": { title: "Password Guessing Detection", subtitle: "Audits usernames targeted by stuffing and dictionary attacks (Module 5)" }
    };

    navItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const tabId = item.getAttribute("data-tab");
            
            navItems.forEach(nav => nav.classList.remove("active"));
            tabPanes.forEach(pane => pane.classList.remove("active"));
            
            item.classList.add("active");
            document.getElementById(`tab-${tabId}`).classList.add("active");
            
            // Update titles
            tabTitle.textContent = tabMeta[tabId].title;
            tabSubtitle.textContent = tabMeta[tabId].subtitle;
            
            appendCentralLog("INFO", `Navigated to module: ${tabMeta[tabId].title}`);
        });
    });

    document.getElementById("clear-dashboard-logs").addEventListener("click", () => {
        const container = document.getElementById("central-logs-container");
        if (container) {
            container.innerHTML = "";
            securityWarningCount = 0;
            criticalAlertCount = 0;
            document.getElementById("dash-warning-count").textContent = 0;
            document.getElementById("dash-alert-count").textContent = 0;
            appendCentralLog("INFO", "Logs cleared by administrator.");
        }
    });


    // ==========================================
    // MODULE 1: PASSWORD STRENGTH CHECKER
    // ==========================================
    const checkerPasswordInput = document.getElementById("checker-password");
    const toggleCheckerVisibility = document.getElementById("toggle-checker-visibility");
    
    toggleCheckerVisibility.addEventListener("click", () => {
        const isPassword = checkerPasswordInput.type === "password";
        checkerPasswordInput.type = isPassword ? "text" : "password";
        toggleCheckerVisibility.innerHTML = isPassword ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
    });

    function calculateEntropy(password) {
        if (!password) return { entropy: 0, poolSize: 0 };
        
        let hasLower = false;
        let hasUpper = false;
        let hasDigit = false;
        let hasSpecial = false;
        
        for (let i = 0; i < password.length; i++) {
            const char = password[i];
            if (/[a-z]/.test(char)) hasLower = true;
            else if (/[A-Z]/.test(char)) hasUpper = true;
            else if (/[0-9]/.test(char)) hasDigit = true;
            else hasSpecial = true;
        }
        
        let poolSize = 0;
        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigit) poolSize += 10;
        if (hasSpecial) poolSize += 32;
        
        if (poolSize === 0) return { entropy: 0, poolSize: 0 };
        
        const entropy = password.length * Math.log2(poolSize);
        return { entropy: Math.round(entropy * 100) / 100, poolSize };
    }

    function checkSequentialPatterns(password) {
        const issues = [];
        const lower = password.toLowerCase();
        
        // Keyboard runs
        const keyboardRuns = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];
        keyboardRuns.forEach(run => {
            for (let i = 0; i < lower.length - 2; i++) {
                const triple = lower.substring(i, i + 3);
                if (run.includes(triple)) {
                    issues.push(`Keyboard pattern found: '${triple}'`);
                    break;
                }
            }
        });
        
        // ASCII sequences
        for (let i = 0; i < password.length - 2; i++) {
            const code1 = password.charCodeAt(i);
            const code2 = password.charCodeAt(i + 1);
            const code3 = password.charCodeAt(i + 2);
            
            if (code2 - code1 === 1 && code3 - code2 === 1) {
                issues.push(`Sequential sequence: '${password.substring(i, i+3)}'`);
                break;
            }
            if (code1 - code2 === 1 && code2 - code3 === 1) {
                issues.push(`Reverse sequence: '${password.substring(i, i+3)}'`);
                break;
            }
        }
        return [...new Set(issues)];
    }

    function checkRepeatedCharacters(password) {
        const issues = [];
        let consecutiveCount = 1;
        
        for (let i = 1; i < password.length; i++) {
            if (password[i] === password[i - 1]) {
                consecutiveCount++;
                if (consecutiveCount === 3) {
                    issues.push(`Repeated character sequence: '${password[i]}'`);
                }
            } else {
                consecutiveCount = 1;
            }
        }
        return [...new Set(issues)];
    }

    function estimateCrackTime(entropy) {
        if (entropy === 0) return "Instantaneous";
        
        const attempts = Math.pow(2, entropy);
        const hashRate = 10000000000; // 10 billion guesses/second
        const seconds = attempts / hashRate;
        
        if (seconds < 1) return "Instantaneous";
        if (seconds < 60) return `${Math.round(seconds * 100) / 100} seconds`;
        if (seconds < 3600) return `${Math.round((seconds / 60) * 100) / 100} minutes`;
        if (seconds < 86400) return `${Math.round((seconds / 3600) * 100) / 100} hours`;
        if (seconds < 31536000) return `${Math.round((seconds / 86400) * 100) / 100} days`;
        return `${Math.round((seconds / 31536000) * 100) / 100} years`;
    }

    checkerPasswordInput.addEventListener("input", () => {
        const password = checkerPasswordInput.value;
        const length = password.length;
        
        const { entropy, poolSize } = calculateEntropy(password);
        const isCommon = commonPasswords.has(password.toLowerCase());
        const sequential = checkSequentialPatterns(password);
        const repeated = checkRepeatedCharacters(password);
        
        // Update basic metrics
        document.getElementById("metric-length").textContent = length;
        document.getElementById("metric-pool").textContent = poolSize;
        document.getElementById("metric-entropy").innerHTML = `${entropy.toFixed(2)} <span class="unit">bits</span>`;
        document.getElementById("metric-crack-time").textContent = estimateCrackTime(entropy);
        
        // Rating evaluation
        let rating = "Weak";
        let colorClass = "bg-red";
        let textClass = "text-red";
        let fillWidth = "15%";
        
        if (length >= 8 && !isCommon && entropy >= 30) {
            if (entropy < 60) {
                rating = "Moderate";
                colorClass = "bg-yellow";
                textClass = "text-amber";
                fillWidth = "50%";
            } else if (entropy < 80) {
                rating = "Strong";
                colorClass = "bg-green";
                textClass = "text-green";
                fillWidth = "75%";
            } else {
                rating = "Excellent";
                colorClass = "bg-cyan";
                textClass = "text-cyan";
                fillWidth = "100%";
            }
        } else if (length > 0) {
            rating = "Weak";
            colorClass = "bg-red";
            textClass = "text-red";
            fillWidth = "30%";
        } else {
            rating = "Empty";
            colorClass = "";
            textClass = "text-red";
            fillWidth = "0%";
        }
        
        const meterFill = document.getElementById("strength-meter-fill");
        meterFill.className = `meter-fill ${colorClass}`;
        meterFill.style.width = fillWidth;
        
        const ratingText = document.getElementById("strength-rating-text");
        ratingText.className = `rating-text ${textClass}`;
        ratingText.textContent = rating;

        // Populate vulnerabilities
        const vulnsContainer = document.getElementById("vulnerabilities-container");
        vulnsContainer.innerHTML = "";
        
        let vulnFound = false;
        
        if (isCommon) {
            vulnFound = true;
            vulnsContainer.innerHTML += `
                <div class="vulnerability-item">
                    <i class="fa-solid fa-triangle-exclamation"></i>
                    <div><strong>Dictionary Match</strong>: This password is on the common blacklist. An attacker will crack it instantly.</div>
                </div>
            `;
        }
        
        sequential.forEach(issue => {
            vulnFound = true;
            vulnsContainer.innerHTML += `
                <div class="vulnerability-item">
                    <i class="fa-solid fa-triangle-exclamation"></i>
                    <div><strong>Sequence Pattern</strong>: ${issue}. Patterns bypass normal length calculations.</div>
                </div>
            `;
        });
        
        repeated.forEach(issue => {
            vulnFound = true;
            vulnsContainer.innerHTML += `
                <div class="vulnerability-item">
                    <i class="fa-solid fa-triangle-exclamation"></i>
                    <div><strong>Repeating Run</strong>: ${issue}. Repeated letters make brute-forcing faster.</div>
                </div>
            `;
        });
        
        if (!vulnFound) {
            vulnsContainer.innerHTML = `
                <div class="empty-placeholder">
                    <i class="fa-solid fa-circle-check text-green"></i>
                    <p>No major pattern or dictionary issues found.</p>
                </div>
            `;
        }

        // Recommendations
        const recContainer = document.getElementById("remediation-container");
        recContainer.innerHTML = "";
        
        const recs = [];
        if (length < 12) recs.push("Increase length to at least 12-16 characters.");
        if (isCommon) recs.push("Avoid blacklisted words like 'password' or 'admin'.");
        if (poolSize < 50) recs.push("Use a mix of uppercase, lowercase, numbers, and symbols.");
        if (sequential.length > 0) recs.push("Avoid standard sequential keyboard lines.");
        
        if (recs.length === 0 && length > 0) {
            recContainer.innerHTML = "<li>Password is cryptographically robust! Keep it up.</li>";
        } else {
            recs.forEach(rec => {
                recContainer.innerHTML += `<li>${rec}</li>`;
            });
        }
    });


    // ==========================================
    // MODULE 2: LOGIN LOCKOUT SIMULATOR
    // ==========================================
    const simUsernameInput = document.getElementById("sim-username");
    const simPasswordInput = document.getElementById("sim-password");
    const simRemainingEl = document.getElementById("sim-remaining-attempts");
    const simLoginBtn = document.getElementById("sim-login-btn");
    const lockoutOverlay = document.getElementById("lockout-overlay");
    const lockoutCountdownEl = document.getElementById("lockout-countdown");
    const simHistoryContainer = document.getElementById("sim-history-container");
    
    let attemptsCount = {};
    let lockoutState = {};
    let simLogs = [];

    function addSimLog(username, success, details) {
        const now = new Date();
        const timeStr = now.toTimeString().split(' ')[0];
        
        simLogs.push({ time: timeStr, username, success, details });
        
        // Redraw
        simHistoryContainer.innerHTML = "";
        simLogs.forEach(log => {
            const entry = document.createElement("div");
            entry.className = `log-entry ${log.success ? 'log-success' : 'log-error'}`;
            entry.innerHTML = `<span class="log-time">[${log.time}]</span> <span class="log-tag">[${log.success ? 'SUCCESS' : 'FAILURE'}]</span> User '${log.username}': ${log.details}`;
            simHistoryContainer.appendChild(entry);
        });
        simHistoryContainer.scrollTop = simHistoryContainer.scrollHeight;
    }

    function checkUserLockout(username) {
        if (!lockoutState[username]) return false;
        
        const elapsed = (Date.now() - lockoutState[username]) / 1000;
        const remaining = Math.ceil(15 - elapsed);
        
        if (remaining > 0) {
            return remaining;
        } else {
            delete lockoutState[username];
            attemptsCount[username] = 0;
            return false;
        }
    }

    function startLockoutTimer(username, remaining) {
        lockoutOverlay.classList.remove("hidden");
        lockoutCountdownEl.textContent = remaining;
        
        const interval = setInterval(() => {
            const rem = checkUserLockout(username);
            if (rem) {
                lockoutCountdownEl.textContent = rem;
            } else {
                clearInterval(interval);
                lockoutOverlay.classList.add("hidden");
                simRemainingEl.textContent = 3;
                simRemainingEl.className = "text-green";
                appendCentralLog("INFO", `User '${username}' lockout cooldown expired. Counter reset.`);
            }
        }, 1000);
    }

    simLoginBtn.addEventListener("click", () => {
        const username = simUsernameInput.value.trim().toLowerCase();
        const password = simPasswordInput.value;
        
        if (!username || !password) {
            alert("Please enter credentials to log in.");
            return;
        }

        // Check if user is locked
        const remainingLock = checkUserLockout(username);
        if (remainingLock) {
            startLockoutTimer(username, remainingLock);
            addSimLog(username, false, `Access BLOCKED. Cooldown remaining: ${remainingLock}s`);
            return;
        }

        // Validate
        if (!userDatabase[username]) {
            addSimLog(username, false, "Unknown user account.");
            appendCentralLog("WARNING", `Simulated authentication request failed for non-existent user '${username}'`);
            return;
        }

        const correctPassword = userDatabase[username];
        if (password === correctPassword) {
            attemptsCount[username] = 0;
            simRemainingEl.textContent = 3;
            simRemainingEl.className = "text-green";
            
            addSimLog(username, true, "Successfully authenticated.");
            appendCentralLog("SUCCESS", `User '${username}' successfully signed in to portal simulator.`);
        } else {
            const count = (attemptsCount[username] || 0) + 1;
            attemptsCount[username] = count;
            
            if (count >= 3) {
                lockoutState[username] = Date.now();
                simRemainingEl.textContent = 0;
                simRemainingEl.className = "text-red";
                
                addSimLog(username, false, "Account LOCKED. Cooldown timer started.");
                appendCentralLog("ALERT", `User account '${username}' LOCKED due to 3 consecutive failures.`);
                startLockoutTimer(username, 15);
            } else {
                const rem = 3 - count;
                simRemainingEl.textContent = rem;
                simRemainingEl.className = rem === 1 ? "text-red" : "text-amber";
                
                addSimLog(username, false, `Incorrect credentials. ${rem} attempts remaining.`);
                appendCentralLog("WARNING", `Incorrect login attempt for user '${username}' (${rem} attempts left)`);
            }
        }
    });

    document.getElementById("clear-sim-history").addEventListener("click", () => {
        simLogs = [];
        attemptsCount = {};
        lockoutState = {};
        simHistoryContainer.innerHTML = `
            <div class="empty-placeholder py-5">
                <i class="fa-solid fa-receipt text-muted"></i>
                <p>No login attempts recorded yet.</p>
            </div>
        `;
        simRemainingEl.textContent = 3;
        simRemainingEl.className = "text-green";
        appendCentralLog("INFO", "Lockout simulator state reset.");
    });


    // ==========================================
    // MODULE 3: SECURE PASSWORD GENERATOR
    // ==========================================
    const genLengthSlider = document.getElementById("gen-length");
    const genLengthVal = document.getElementById("gen-length-val");
    const genBtn = document.getElementById("generate-btn");
    const genField = document.getElementById("generated-password-field");
    const copyBtn = document.getElementById("copy-password-btn");
    const copyToast = document.getElementById("copy-toast");
    const genStrengthPanel = document.getElementById("generator-strength-panel");

    genLengthSlider.addEventListener("input", () => {
        genLengthVal.textContent = genLengthSlider.value;
    });

    function generateCSPRNGPassword(length, useLower, useUpper, useDigits, useSymbols) {
        const lowerPool = "abcdefghijklmnopqrstuvwxyz";
        const upperPool = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const digitPool = "0123456789";
        const symbolPool = "!@#$%^&*()-_=+[]{}|;:,.<>/?";
        
        let pool = "";
        const mandatory = [];
        
        if (useLower) {
            pool += lowerPool;
            mandatory.push(getRandomChar(lowerPool));
        }
        if (useUpper) {
            pool += upperPool;
            mandatory.push(getRandomChar(upperPool));
        }
        if (useDigits) {
            pool += digitPool;
            mandatory.push(getRandomChar(digitPool));
        }
        if (useSymbols) {
            pool += symbolPool;
            mandatory.push(getRandomChar(symbolPool));
        }
        
        if (pool === "") {
            throw new Error("Select at least one character set.");
        }
        if (length < mandatory.length) {
            throw new Error(`Length must be at least ${mandatory.length} to fit chosen types.`);
        }
        
        const result = [...mandatory];
        const remaining = length - mandatory.length;
        
        for (let i = 0; i < remaining; i++) {
            result.push(getRandomChar(pool));
        }
        
        // Shuffle
        for (let i = result.length - 1; i > 0; i--) {
            const j = getRandomInt(0, i);
            const temp = result[i];
            result[i] = result[j];
            result[j] = temp;
        }
        
        return result.join("");
    }

    function getRandomChar(str) {
        const idx = getRandomInt(0, str.length - 1);
        return str[idx];
    }

    function getRandomInt(min, max) {
        const range = max - min + 1;
        const array = new Uint32Array(1);
        window.crypto.getRandomValues(array);
        return min + (array[0] % range);
    }

    genBtn.addEventListener("click", () => {
        const length = parseInt(genLengthSlider.value);
        const useLower = document.getElementById("gen-lower").checked;
        const useUpper = document.getElementById("gen-upper").checked;
        const useDigits = document.getElementById("gen-digits").checked;
        const useSymbols = document.getElementById("gen-symbols").checked;
        
        try {
            const pwd = generateCSPRNGPassword(length, useLower, useUpper, useDigits, useSymbols);
            genField.value = pwd;
            
            // Audit strength
            const { entropy } = calculateEntropy(pwd);
            let rating = "Strong";
            let color = "text-green";
            if (entropy >= 80) {
                rating = "Excellent";
                color = "text-cyan";
            } else if (entropy < 60) {
                rating = "Moderate";
                color = "text-amber";
            }
            
            genStrengthPanel.style.display = "block";
            document.getElementById("gen-entropy-val").textContent = `${entropy.toFixed(2)} bits`;
            
            const ratingVal = document.getElementById("gen-rating-val");
            ratingVal.textContent = rating;
            ratingVal.className = `metric-val ${color}`;
            
            appendCentralLog("INFO", `Generated secure password of length ${length} (Entropy: ${entropy.toFixed(2)} bits)`);
        } catch (err) {
            alert(err.message);
        }
    });

    copyBtn.addEventListener("click", () => {
        const val = genField.value;
        if (val === "Click Generate above..." || !val) return;
        
        navigator.clipboard.writeText(val).then(() => {
            copyToast.classList.remove("hidden");
            setTimeout(() => {
                copyToast.classList.add("hidden");
            }, 2000);
        });
    });


    // ==========================================
    // MODULE 4 & 5: LOG ATTACK ANALYZER
    // ==========================================
    const csvInputArea = document.getElementById("csv-input-area");
    const loadSampleCsvBtn = document.getElementById("load-sample-csv-btn");
    const clearAnalyzerBtn = document.getElementById("clear-analyzer-btn");
    const analyzeCsvBtn = document.getElementById("analyze-csv-btn");
    
    const summaryCards = document.getElementById("analyzer-summary-cards");
    const alertsCard = document.getElementById("analyzer-alerts-card");
    const tablesRow = document.getElementById("analyzer-tables-row");
    const alertsContainer = document.getElementById("analyzer-alerts-container");
    
    const ipTableBody = document.querySelector("#ip-stats-table tbody");
    const userTableBody = document.querySelector("#user-stats-table tbody");

    const sampleCSVContent = `timestamp,username,ip_address,status,password_tried
2026-07-30 10:00:00,admin,192.168.1.50,FAILURE,password123
2026-07-30 10:00:05,admin,192.168.1.50,FAILURE,admin123
2026-07-30 10:00:10,admin,192.168.1.50,FAILURE,letmein
2026-07-30 10:00:15,admin,192.168.1.50,FAILURE,welcome
2026-07-30 10:00:20,admin,192.168.1.50,FAILURE,system
2026-07-30 10:00:25,admin,192.168.1.50,FAILURE,root
2026-07-30 10:01:00,alice,192.168.1.10,SUCCESS,alice_secure_pass_99
2026-07-30 10:02:00,bob,10.0.0.15,FAILURE,password
2026-07-30 10:02:10,bob,10.0.0.15,FAILURE,bob123
2026-07-30 10:02:20,bob,10.0.0.15,SUCCESS,bob_pass_2026!
2026-07-30 10:03:00,attacker,198.51.100.42,FAILURE,guess1
2026-07-30 10:03:02,attacker,198.51.100.42,FAILURE,guess2
2026-07-30 10:03:04,attacker,198.51.100.42,FAILURE,guess3
2026-07-30 10:03:06,attacker,198.51.100.42,FAILURE,guess4
2026-07-30 10:03:08,attacker,198.51.100.42,FAILURE,guess5
2026-07-30 10:03:10,attacker,198.51.100.42,FAILURE,guess6
2026-07-30 10:04:00,victim_user,192.168.1.100,FAILURE,qwerty
2026-07-30 10:04:05,victim_user,192.168.1.101,FAILURE,password
2026-07-30 10:04:10,victim_user,192.168.1.102,FAILURE,123456
2026-07-30 10:04:15,victim_user,192.168.1.103,FAILURE,welcome
2026-07-30 10:04:20,victim_user,192.168.1.104,FAILURE,letmein`;

    // ==========================================
    // MODULE 4: BRUTE FORCE ATTACK DETECTOR
    // ==========================================
    const bfCsvInput = document.getElementById("bf-csv-input");
    const loadBfCsvBtn = document.getElementById("load-bf-csv-btn");
    const clearBfBtn = document.getElementById("clear-bf-btn");
    const analyzeBfBtn = document.getElementById("analyze-bf-btn");
    
    const bfSummaryCards = document.getElementById("bf-summary-cards");
    const bfAlertsCard = document.getElementById("bf-alerts-card");
    const bfTableCard = document.getElementById("bf-table-card");
    const bfAlertsContainer = document.getElementById("bf-alerts-container");
    const bfStatsTableBody = document.querySelector("#bf-stats-table tbody");

    loadBfCsvBtn.addEventListener("click", () => {
        bfCsvInput.value = sampleCSVContent;
        appendCentralLog("INFO", "Sample CSV loaded into Brute Force Ingestion Panel.");
    });

    clearBfBtn.addEventListener("click", () => {
        bfCsvInput.value = "";
        bfSummaryCards.classList.add("hidden");
        bfAlertsCard.classList.add("hidden");
        bfTableCard.classList.add("hidden");
        bfAlertsContainer.innerHTML = "";
        bfStatsTableBody.innerHTML = "";
        appendCentralLog("INFO", "Brute force detector data reset.");
    });

    function parseCSV(text) {
        const lines = text.split("\n");
        if (lines.length === 0) return [];
        const headers = lines[0].split(",").map(h => h.trim());
        const data = [];
        
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            
            const cols = line.split(",").map(c => c.trim());
            const obj = {};
            headers.forEach((header, index) => {
                obj[header] = cols[index] || "";
            });
            data.push(obj);
        }
        return data;
    }

    analyzeBfBtn.addEventListener("click", () => {
        const rawCSV = bfCsvInput.value.trim();
        if (!rawCSV) {
            alert("Please paste or load CSV log data first.");
            return;
        }

        try {
            const logs = parseCSV(rawCSV);
            const ipStats = {};
            const alerts = [];
            let threatsCount = 0;

            logs.forEach(entry => {
                const ip = entry.ip_address;
                const username = (entry.username || "").toLowerCase();
                const status = (entry.status || "").toUpperCase();
                
                if (ip) {
                    if (!ipStats[ip]) {
                        ipStats[ip] = { attempts: 0, failures: 0, successes: 0, targets: new Set(), compromised: false };
                    }
                    const stat = ipStats[ip];
                    stat.attempts++;
                    stat.targets.add(username);
                    
                    if (status === "FAILURE") {
                        stat.failures++;
                    } else if (status === "SUCCESS") {
                        stat.successes++;
                        if (stat.failures >= 3) {
                            stat.compromised = true;
                        }
                    }
                }
            });

            // Analyze alerts
            Object.keys(ipStats).forEach(ip => {
                const stat = ipStats[ip];
                if (stat.failures >= 3) {
                    threatsCount++;
                    let msg = `<strong>IP Attack Warning:</strong> Source IP <code>${ip}</code> has ${stat.failures} failed attempts targeting (${[...stat.targets].join(', ')}).`;
                    if (stat.compromised) {
                        msg += ` <span class="text-red">CRITICAL: Success observed after failures. Potential Breach!</span>`;
                        alerts.unshift({ level: "CRITICAL", msg });
                    } else {
                        alerts.push({ level: "WARNING", msg });
                    }
                }
            });

            // Display
            bfSummaryCards.classList.remove("hidden");
            bfAlertsCard.classList.remove("hidden");
            bfTableCard.classList.remove("hidden");

            document.getElementById("bf-threats-count").textContent = threatsCount;
            document.getElementById("bf-total-lines").textContent = logs.length;

            bfAlertsContainer.innerHTML = "";
            if (alerts.length === 0) {
                bfAlertsContainer.innerHTML = `
                    <div class="empty-placeholder py-3">
                        <i class="fa-solid fa-check text-green"></i>
                        <p>No brute force signatures detected.</p>
                    </div>`;
            } else {
                alerts.forEach(item => {
                    const card = document.createElement("div");
                    card.className = `alert-card ${item.level === 'CRITICAL' ? '' : 'warning-style'}`;
                    card.innerHTML = `
                        <i class="fa-solid ${item.level === 'CRITICAL' ? 'fa-skull-crossbones text-red animate-pulse' : 'fa-triangle-exclamation text-amber'}"></i>
                        <div>${item.msg}</div>`;
                    bfAlertsContainer.appendChild(card);
                    appendCentralLog(item.level === 'CRITICAL' ? 'ALERT' : 'WARNING', `Brute Force: ${item.msg.replace(/<\/?[^>]+(>|$)/g, "")}`);
                });
            }

            bfStatsTableBody.innerHTML = "";
            Object.keys(ipStats).forEach(ip => {
                const stat = ipStats[ip];
                const isThreat = stat.failures >= 3;
                const statusStr = stat.compromised ? '<strong class="text-red">COMPROMISED</strong>' : (isThreat ? '<span class="text-amber">ATTACKER</span>' : '<span class="text-green">NORMAL</span>');
                
                const row = document.createElement("tr");
                row.innerHTML = `
                    <td>${ip}</td>
                    <td>${stat.attempts}</td>
                    <td>${stat.failures}</td>
                    <td>${stat.successes}</td>
                    <td>${statusStr}</td>`;
                bfStatsTableBody.appendChild(row);
            });

            appendCentralLog("INFO", `Brute force analysis complete. Inspected ${logs.length} entries.`);
        } catch (err) {
            appendCentralLog("ERROR", `Failed brute force scan: ${err.message}`);
            alert(err.message);
        }
    });

    // ==========================================
    // MODULE 5: PASSWORD GUESSING DETECTION
    // ==========================================
    const pgCsvInput = document.getElementById("pg-csv-input");
    const loadPgCsvBtn = document.getElementById("load-pg-csv-btn");
    const clearPgBtn = document.getElementById("clear-pg-btn");
    const analyzePgBtn = document.getElementById("analyze-pg-btn");
    
    const pgSummaryCards = document.getElementById("pg-summary-cards");
    const pgAlertsCard = document.getElementById("pg-alerts-card");
    const pgTableCard = document.getElementById("pg-table-card");
    const pgAlertsContainer = document.getElementById("pg-alerts-container");
    const pgStatsTableBody = document.querySelector("#pg-stats-table tbody");

    loadPgCsvBtn.addEventListener("click", () => {
        pgCsvInput.value = sampleCSVContent;
        appendCentralLog("INFO", "Sample CSV loaded into Guessing Ingestion Panel.");
    });

    clearPgBtn.addEventListener("click", () => {
        pgCsvInput.value = "";
        pgSummaryCards.classList.add("hidden");
        pgAlertsCard.classList.add("hidden");
        pgTableCard.classList.add("hidden");
        pgAlertsContainer.innerHTML = "";
        pgStatsTableBody.innerHTML = "";
        appendCentralLog("INFO", "Password guessing detector data reset.");
    });

    analyzePgBtn.addEventListener("click", () => {
        const rawCSV = pgCsvInput.value.trim();
        if (!rawCSV) {
            alert("Please paste or load CSV log data first.");
            return;
        }

        try {
            const logs = parseCSV(rawCSV);
            const userStats = {};
            const alerts = [];
            let targetCount = 0;

            logs.forEach(entry => {
                const username = (entry.username || "").toLowerCase().trim();
                const password = entry.password_tried;
                const status = (entry.status || "").toUpperCase();
                const ip = entry.ip_address;
                
                if (username) {
                    if (!userStats[username]) {
                        userStats[username] = { attempts: 0, failures: 0, successes: 0, uniquePasswords: new Set(), ips: new Set(), dictionaryUses: 0 };
                    }
                    const stat = userStats[username];
                    stat.attempts++;
                    stat.ips.add(ip);
                    
                    if (status === "FAILURE") {
                        stat.failures++;
                    } else if (status === "SUCCESS") {
                        stat.successes++;
                    }
                    
                    if (password) {
                        stat.uniquePasswords.add(password);
                        if (commonPasswords.has(password.toLowerCase())) {
                            stat.dictionaryUses++;
                        }
                    }
                }
            });

            // Analyze alerts
            Object.keys(userStats).forEach(user => {
                const stat = userStats[user];
                const uniqueCount = stat.uniquePasswords.size;
                if (uniqueCount >= 3) {
                    targetCount++;
                    let msg = `<strong>Guessing Target:</strong> Account <code>${user}</code> targeted with ${uniqueCount} unique passwords from ${stat.ips.size} IPs.`;
                    if (stat.dictionaryUses > 0) {
                        msg += ` <span class="text-amber">Signature: Dictionary Attack detected (${stat.dictionaryUses} blacklist matches).</span>`;
                    }
                    alerts.push({ level: "WARNING", msg });
                }
            });

            // Display
            pgSummaryCards.classList.remove("hidden");
            pgAlertsCard.classList.remove("hidden");
            pgTableCard.classList.remove("hidden");

            document.getElementById("pg-threats-count").textContent = targetCount;
            document.getElementById("pg-total-lines").textContent = logs.length;

            pgAlertsContainer.innerHTML = "";
            if (alerts.length === 0) {
                pgAlertsContainer.innerHTML = `
                    <div class="empty-placeholder py-3">
                        <i class="fa-solid fa-check text-green"></i>
                        <p>No credential guessing targeted signatures detected.</p>
                    </div>`;
            } else {
                alerts.forEach(item => {
                    const card = document.createElement("div");
                    card.className = "alert-card warning-style";
                    card.innerHTML = `
                        <i class="fa-solid fa-triangle-exclamation text-amber"></i>
                        <div>${item.msg}</div>`;
                    pgAlertsContainer.appendChild(card);
                    appendCentralLog("WARNING", `Password Guessing: ${item.msg.replace(/<\/?[^>]+(>|$)/g, "")}`);
                });
            }

            pgStatsTableBody.innerHTML = "";
            Object.keys(userStats).forEach(user => {
                const stat = userStats[user];
                const isTarget = stat.uniquePasswords.size >= 3;
                const statusStr = isTarget ? '<span class="text-amber">TARGETED</span>' : '<span class="text-green">SAFE</span>';
                
                const row = document.createElement("tr");
                row.innerHTML = `
                    <td>${user}</td>
                    <td>${stat.failures}</td>
                    <td>${stat.uniquePasswords.size}</td>
                    <td>${stat.ips.size}</td>
                    <td>${statusStr}</td>`;
                pgStatsTableBody.appendChild(row);
            });

            appendCentralLog("INFO", `Password guessing analysis complete. Inspected ${logs.length} entries.`);
        } catch (err) {
            appendCentralLog("ERROR", `Failed guessing scan: ${err.message}`);
            alert(err.message);
        }
    });

});

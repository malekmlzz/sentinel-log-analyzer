# sentinel-log-analyzer

# 🛡️ Sentinel Log Analyzer

Professional Python security log analyzer for detecting suspicious authentication activity, brute-force behavior, account targeting, and abnormal login patterns.

Sentinel Log Analyzer is a lightweight, privacy-first defensive security tool designed to analyze authentication logs and identify potentially suspicious behavior.

All analysis is performed locally. No log data, IP addresses, usernames, or other information are sent to external services.

---

## ✨ Features

- 🔍 Authentication log analysis
- 🚨 Brute-force detection
- 👤 Multiple-account targeting detection
- 🔐 Detection of successful login after repeated failures
- 📊 Risk scoring from 0 to 100
- ⚠️ Severity classification
- 🌐 IPv4 and IPv6 validation
- 📄 JSON report generation
- 📑 CSV report generation
- 🧩 Rule-based detection engine
- 🖥️ Command-line interface
- 🔒 Privacy-first local processing
- 📦 Zero external dependencies

---

## 🧠 Detection Engine

Sentinel analyzes authentication events using multiple security rules.

### 1. Repeated Authentication Failures

A source IP generating a high number of failed authentication attempts receives a higher risk score.

```text
Failed authentication attempts
              │
              ▼
       Threshold exceeded
              │
              ▼
       Suspicious activity
```

---

### 2. Multiple Username Targeting

Attackers may attempt to authenticate against multiple accounts from the same source.

For example:

```text
admin
root
test
administrator
user
```

Sentinel identifies this behavior and increases the associated risk score.

---

### 3. Successful Login After Multiple Failures

A successful authentication following several failed attempts can be an important security indicator.

Example:

```text
Failed login
     ↓
Failed login
     ↓
Failed login
     ↓
Successful login
```

This behavior receives additional risk points.

---

### 4. High-Volume Authentication Activity

A very high number of failed authentication attempts increases the overall risk score and may indicate automated authentication activity.

---

# 📊 Risk Scoring

Sentinel calculates a risk score between `0` and `100`.

| Score | Severity |
|------:|----------|
| 0–29 | LOW |
| 30–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

Example:

```text
[CRITICAL] 192.168.1.50 (Risk: 90/100)

    Failed attempts : 25
    Successful      : 1
    Unique users    : 7

    └─ Repeated authentication failures: 25
    └─ Multiple targeted accounts: 7
    └─ Successful authentication after failures
```

---

# 🚀 Installation

## Requirements

- Python 3.8+
- No external Python packages required

The project currently uses only Python's standard library.

Clone the repository:

```bash
git clone https://github.com/malekmlzz/sentinel-log-analyzer.git
```

Enter the project directory:

```bash
cd sentinel-log-analyzer
```

---

# 💻 Usage

Run the analyzer against a log file:

```bash
python sentinel_log_analyzer.py auth.log
```

Specify a custom detection threshold:

```bash
python sentinel_log_analyzer.py auth.log --threshold 3
```

The threshold represents the number of failed authentication attempts required before an IP is considered suspicious.

---

# 📄 JSON Reports

Generate a machine-readable JSON report:

```bash
python sentinel_log_analyzer.py auth.log --json report.json
```

Example:

```json
{
    "metadata": {
        "tool": "Sentinel Log Analyzer",
        "version": "1.0.0"
    },
    "statistics": {
        "security_events": 42,
        "unique_ips": 5,
        "failed_authentication": 38,
        "successful_authentication": 4
    },
    "findings": []
}
```

JSON reports can be useful for integrating the analyzer with other security tools and automation workflows.

---

# 📑 CSV Reports

Generate a CSV report:

```bash
python sentinel_log_analyzer.py auth.log --csv findings.csv
```

The resulting CSV file can be opened with:

- Microsoft Excel
- LibreOffice Calc
- Google Sheets
- Data-analysis tools
- Security-analysis workflows

---

# 🧪 Example Log

Create a file called:

```text
auth.log
```

Example content:

```text
Aug 25 10:10:01 server sshd[1001]: Failed password for admin from 192.168.1.50 port 2222 ssh2
Aug 25 10:10:03 server sshd[1002]: Failed password for root from 192.168.1.50 port 2223 ssh2
Aug 25 10:10:05 server sshd[1003]: Failed password for test from 192.168.1.50 port 2224 ssh2
Aug 25 10:10:07 server sshd[1004]: Failed password for user from 192.168.1.50 port 2225 ssh2
Aug 25 10:10:10 server sshd[1005]: Failed password for administrator from 192.168.1.50 port 2226 ssh2
```

Run:

```bash
python sentinel_log_analyzer.py auth.log
```

The analyzer should identify the source as suspicious because the same IP generated multiple failed authentication attempts against multiple usernames.

---

# 🏗️ Architecture

The project follows a security-analysis pipeline:

```text
                    ┌─────────────────┐
                    │    Log File     │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   Log Parser    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Event Extraction│
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Detection Rules │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   Risk Engine   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Security Report │
                    └─────────────────┘
```

---

# 🔐 Privacy & Security

Sentinel is designed around local processing.

The application does not:

- Upload log files
- Send IP addresses to external services
- Send usernames to external services
- Contact external APIs
- Execute analyzed files
- Store authentication credentials

All analysis takes place locally on the user's machine.

> **Important:** Log files may contain sensitive information. Never upload private production logs to a public GitHub repository.

---

# ⚠️ Limitations

Sentinel is a lightweight rule-based security analyzer.

It is not intended to replace professional:

- SIEM platforms
- EDR solutions
- IDS/IPS systems
- Threat intelligence platforms
- Incident-response platforms
- Enterprise security monitoring systems

Detection results should be considered security indicators that require additional investigation.

A suspicious IP address does not automatically prove that a system has been compromised.

---

# 🛠️ Future Development

Planned improvements include:

- [ ] Apache access-log support
- [ ] Nginx log support
- [ ] Windows Event Log support
- [ ] Configurable detection rules
- [ ] YAML configuration
- [ ] Automated unit tests
- [ ] HTML security reports
- [ ] Interactive dashboard
- [ ] Timeline visualization
- [ ] Statistical anomaly detection
- [ ] Geographic IP enrichment
- [ ] YARA integration
- [ ] Sigma rule support
- [ ] SIEM integration
- [ ] Docker support
- [ ] Scheduled log monitoring
- [ ] Real-time log analysis

---

# 🧪 Testing

Automated tests are planned for future versions.

The test suite will cover:

- IP extraction
- IP validation
- Log parsing
- Event classification
- Brute-force detection
- Multiple-account detection
- Risk scoring
- JSON report generation
- CSV report generation

Planned project structure:

```text
sentinel-log-analyzer/
│
├── sentinel_log_analyzer.py
├── README.md
├── LICENSE
├── requirements.txt
│
├── tests/
│   ├── test_parser.py
│   ├── test_detection.py
│   └── test_risk.py
│
└── examples/
    └── auth.log
```

---

# 📚 Security Concepts Demonstrated

This project demonstrates practical knowledge of:

- Security log analysis
- Authentication monitoring
- Brute-force detection
- IOC extraction
- Behavioral analysis
- Risk scoring
- Rule-based detection
- Incident-response concepts
- Defensive cybersecurity
- Python automation
- CLI application development
- JSON reporting
- CSV reporting
- Data parsing

---

# 🎯 Use Cases

Sentinel can be used for:

- Cybersecurity education
- SOC analyst training
- Security research
- Authentication-log investigation
- Incident-response practice
- Linux security monitoring
- Python security development
- Cybersecurity portfolios
- Defensive security automation

---

# 👨‍💻 Author

**Malek**

Python Developer | Cybersecurity Enthusiast | Security Research

GitHub:

https://github.com/malekmlzz

---

# ⚖️ Disclaimer

This project is developed for educational, defensive security, and authorized security-analysis purposes only.

Do not use this tool to analyze systems, networks, or data without proper authorization.

The results generated by Sentinel are security indicators and should be validated using additional investigation techniques.

---

# ⭐ Support

If you find this project useful, consider giving the repository a star ⭐ on GitHub.

Contributions, bug reports, feature requests, and security improvements are welcome.

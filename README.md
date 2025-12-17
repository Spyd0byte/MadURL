# MadURL – Advanced Terminal URL Analysis Tool

<p align="center">
  <img src="[https://via.placeholder.com/800x200/000000/FFFFFF?text=MadURL+Terminal+URL+Analyzer](https://raw.githubusercontent.com/Spyd0byte/MadURL/refs/heads/main/MadURL.png)" alt="MadURL Banner" />
</p>

> **MadURL** is a powerful, feature-rich terminal-based URL analysis tool with glitchy animations and Parrot OS–style aesthetics. Built for **cybersecurity researchers, penetration testers, and security enthusiasts**, it helps analyze suspicious URLs, expand shortened links, and generate detailed security reports.

---

## 🚀 Features

* 🔍 **Comprehensive URL Analysis**
  Parse and display all URL components in a clean, organized tree structure

* 🔄 **URL Expansion**
  Automatically detect and expand shortened URLs from known services

* 🛡️ **Security Analysis**
  Identify suspicious patterns and potential threats

* 📊 **VirusTotal Integration** *(API key required)*
  Check URLs against VirusTotal’s malware and threat intelligence database

* 🌐 **WHOIS Lookup**
  Retrieve domain registration and ownership information

* 📄 **PDF Reporting**
  Generate professional, shareable PDF reports of analysis results

* 🎨 **Terminal Aesthetics**
  Glitch-style animations with a Parrot OS–inspired color theme

* ⚡ **Fast & Lightweight**
  Minimal dependencies and optimized for terminal usage

---

## 🛠️ Installation

### Prerequisites

* Python **3.6+**
* `pip` (Python package manager)

### Install Dependencies

```bash
pip install requests python-whois reportlab
```

### Clone the Repository

```bash
git clone https://github.com/Spyd0Byte/MadURL.git
cd MadURL
```

---

## 📌 Usage

### 🔹 Basic URL Analysis

```bash
python madurl.py "https://example.com/path?query=param#fragment"
```

### 🔹 Expand Shortened URLs

```bash
python madurl.py "https://bit.ly/suspicious-link" --expand
```

### 🔹 VirusTotal Scan

```bash
# Get your free API key from https://www.virustotal.com
python madurl.py "https://example.com" --virustotal YOUR_API_KEY
```

### 🔹 WHOIS Lookup

```bash
python madurl.py "https://example.com" --whois
```

### 🔹 Generate PDF Report

```bash
python madurl.py "https://example.com" --pdf
```

#### Custom PDF Filename

```bash
python madurl.py "https://example.com" --pdf my_report.pdf
```

### 🔹 All Features Combined

```bash
python madurl.py "https://example.com" \
  --expand \
  --virustotal YOUR_API_KEY \
  --whois \
  --pdf report.pdf
```

---

## ⚙️ Command Line Options

| Option                               | Description                 |
| ------------------------------------ | --------------------------- |
| `url`                                | URL to analyze *(required)* |
| `-e`, `--expand`                     | Expand shortened URLs       |
| `-v API_KEY`, `--virustotal API_KEY` | Check URL with VirusTotal   |
| `-w`, `--whois`                      | Perform WHOIS lookup        |
| `-p [FILENAME]`, `--pdf [FILENAME]`  | Generate PDF report         |

---

## 🧠 Use Cases

* Malware & phishing link analysis
* SOC & blue-team investigations
* Cybersecurity learning & demos
* OSINT and threat intelligence research

---

## ⚠️ Disclaimer

MadURL is intended **for educational and defensive security purposes only**. The author is not responsible for misuse or illegal activity.

---

## 👨‍💻 Author

**Gaurav Pandey**
Cyber Security Researcher
GitHub: [Spyd0Byte](https://github.com/Spyd0Byte)

---

⭐ If you find this project useful, consider giving it a **star** on GitHub!

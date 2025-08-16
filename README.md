<p align="center">
  <img src="https://img.shields.io/badge/Scout%20Theme-olive%20green-6B8E23?style=for-the-badge" alt="Scout Theme" />
  <img src="https://img.shields.io/badge/Made%20in-Italy-008C45?style=for-the-badge" alt="Made in Italy" />
  <br>
  <img src="https://img.shields.io/github/stars/5KBb/BugBountyScout?style=for-the-badge" alt="GitHub Stars" />
  <img src="https://img.shields.io/github/issues/5KBb/BugBountyScout?style=for-the-badge" alt="Issues" />
  <img src="https://img.shields.io/github/license/5KBb/BugBountyScout?style=for-the-badge" alt="License" />
</p>

# 🏕️ BugBountyScout

> **BugBountyScout** is a Python tool for **bug bounty hunters** and **security researchers**.  
> It automates checks for **security headers**, **SSL/TLS misconfigurations**, **XSS**, and **SQLi**, producing a clear, actionable JSON report.  
> ⚜️ Proudly **Made in Italy** ⚜️  

---

## 🌍 Why “Scout”

Like a field scout, this project favors **practical reconnaissance** and **clear signals**.  
The color palette reflects natural tones (**olive green, light brown, cream**) for a distinctive identity.

---

## ✨ Features

- Security **header analysis** (missing/misconfigured headers)  
- **SSL/TLS** checks (weak suites, certificate details)  
- **XSS** probes (reflected/DOM hints)  
- **SQL injection** heuristics  
- **Threaded scans** for performance  
- **JSON report output** (timestamped)  
- Optional **encrypted reports** (using Fernet)  

---

## 📦 Installation

**Requirements**: Python 3.7+, pip, (optional) `cryptography` for encrypted reports.

```bash
git clone https://github.com/5KBb/BugBountyScout.git
cd BugBountyScout
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

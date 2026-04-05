# Krypt Security

Krypt is a high-performance VS Code extension designed for developers who prioritize security throughout their local development lifecycle. It performs a **dual-pass scan** across your workspace to identify both exposed secrets and critical source code vulnerabilities using a hybrid of local heuristics and advanced AI analysis.

---

## 🚀 Features

- **Secret Detection**: Rapidly identifies API keys, private tokens, high-entropy strings, and common authentication headers (Bearer, JWT, AWS, etc.) using fine-tuned local regex heuristics.
- **AI-Powered Analysis**: Delivers precise explanations and severity assessments for any detected risk via the **DeepSeek-v3.2** model (via OpenRouter).
- **OWASP Top 10 Scanning**: Performs a dedicated analysis for critical vulnerabilities:
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Broken Authentication
    - Sensitive Data Exposure
    - Missing Access Control
- **Output-Centric Workflow**: Results are neatly categorized and sorted by severity (CRITICAL, HIGH, MEDIUM, LOW) directly in the "Krypt Security" Output Channel.
- **Privacy-First**: Selectively ignores build artifacts (`.next`, `dist`, `out`), environment files (`.env*`), and non-source files to optimize scan time and minimize AI token usage.

---

## 🛠️ Getting Started

### 1. Installation
Currently, Krypt is available for local development and side-loading. To run the extension locally:
1. Clone the repository: `git clone https://github.com/GarzvR/krypt-extension`
2. Install dependencies: `npm install`
3. Press `F5` in VS Code to launch the Extension Development Host.

### 2. Configuration
Krypt requires an **OpenRouter API Key** to perform AI analysis.
1. Obtain an API key from [OpenRouter](https://openrouter.ai/).
2. In VS Code, navigate to **Settings** (`Cmd + ,`).
3. Search for **Krypt: Open Router Api Key** and paste your key.

---

## 🔍 How It Works

Krypt utilizes a sophisticated two-step process:
1. **Pass 1: Secret Identification**: Local Regex patterns sweep the workspace for secrets. It acts as a fast filter, ensuring only potential risks are analyzed further.
2. **Pass 2: Vulnerability Surface Scan**: Source files are batched and analyzed for OWASP-level security risks. Unlike simple linters, Krypt understands the context of your route handlers and logic using AI.

---

## 📋 Requirements
- VS Code version `^1.90.0`
- An active [OpenRouter](https://openrouter.ai/) account with credits for the `deepseek/deepseek-v3.2` model.

---

## 🛡️ Disclaimer
Krypt is a tool intended to assist with local security best practices. While highly accurate, it is not a replacement for professional penetration testing or comprehensive security audits. Always use secure vault solutions for production secrets.

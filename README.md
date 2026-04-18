# Krypt Security 🛡️

Krypt is a professional-grade VS Code security extension designed for developers who demand high-accuracy vulnerability detection. It leverages a sophisticated **Three-Pass AI Verification Architecture** to identify exposed secrets and OWASP vulnerabilities while aggressively minimizing false positives.

---

## 🚀 Key Features

- **Multi-Pass AI Verification**: Unlike single-pass scanners, Krypt uses a cascading verification logic (DeepSeek V3.2 + DeepSeek R1) to ensure every finding is legitimate.
- **Configurable AI Models**: Support for OpenRouter allows you to swap models (e.g., Claude 3.7, GPT-4o, or DeepSeek) for different phases of the scan.
- **Advanced Secret Detection**: Identify API keys, private tokens, and high-entropy strings using local heuristics before AI validation.
- **OWASP Top 10 Surface Analysis**: Deep contextual analysis for:
    - SQL & Command Injection
    - Cross-Site Scripting (XSS)
    - Broken Authentication & Authorization
    - Insecure Data Storage
- **Security Engineer Persona**: Findings include technical reasoning, realistic exploit scenarios, and required conditions—written by an AI persona tuned for precision, not paranoia.

---

## 🔍 The Multi-Pass Architecture

Krypt employs a state-of-the-art verification pipeline to ensure "No Noise" security reporting:

1.  **Pass 1: Initial Scan (Discovery)**
    *   Uses **DeepSeek V3.2** to sweep the workspace and identify potential risks.
2.  **Pass 2: Strict Auditor (Verification)**
    *   Re-evaluates findings with a strict "Security Reviewer" prompt. Items are classified as `CONFIRMED`, `FALSE_POSITIVE`, or `UNCERTAIN`.
3.  **Pass 3: Final Judge (Escalation)**
    *   **DeepSeek R1** (High-Reasoning) analyzes any `UNCERTAIN` findings with deep technical logic to provide a final binary verdict.

---

## 🛠️ Getting Started

### 1. Installation
1. Clone the repository: `git clone https://github.com/GarzvR/krypt-extension`
2. Install dependencies: `npm install`
3. Press `F5` to launch the extension.

### 2. Configuration
Krypt requires an **OpenRouter API Key**.
1. Obtain a key from [OpenRouter](https://openrouter.ai/).
2. In VS Code Settings (`Cmd + ,`), search for **Krypt**.
3. Configure your API key and preferred models:
    *   `krypt.scannerModel`: Initial discovery model.
    *   `krypt.verifierModel`: Second-pass verification model.
    *   `krypt.escalationModel`: Final escalation model (R1 recommended).

---

## 🧼 False Positive Control

Krypt includes built-in logic to handle "noisy" patterns that common scanners miss:
- **Firebase Intelligence**: Automatically recognizes that Firebase API keys in frontend code are public-by-design and downgrades/skips them accordingly.
- **Context Awareness**: Analyzes if code is actually reachable or just dead code/configuration.
- **Hardcoded Allowlist**: Common safe patterns and configuration files are pre-filtered to save tokens and time.

---

## 📋 Requirements
- VS Code version `^1.90.0`
- An active [OpenRouter](https://openrouter.ai/) account.

---

## 🛡️ Disclaimer
Krypt is a tool intended to assist with local security best practices. While highly accurate, it is not a replacement for professional penetration testing or comprehensive security audits. Always use secure vault solutions for production secrets.

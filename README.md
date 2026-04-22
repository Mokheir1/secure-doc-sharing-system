# 🛡️ Secure Document Sharing System
### CS 419 Final Project | [cite_start]Rutgers University [cite: 96, 111]
**Developed by:** Mohamed Kheir  
[cite_start]**Date:** April 21, 2026 [cite: 97]

## Project Overview
[cite_start]This is a high-integrity web platform designed for the secure storage and exchange of confidential documents[cite: 94, 107]. [cite_start]Built with a **Security by Design** philosophy, the system assumes a **Zero Trust** environment where all network traffic and user inputs are treated as potentially hostile [cite: 100, 110, 116-118, 179].

## 🚀 Key Security Features
* **Transport Layer Security (TLS):** Forced HTTPS protocol enforcement using self-signed RSA-4096 certificates to protect data-in-transit.
* [cite_start]**Symmetric Encryption:** Utilizes `cryptography.fernet` (AES-128 CBC) to ensure all documents are encrypted in-memory before being written to disk  [cite: 140, 143, 376-378].
* [cite_start]**Stateless Session Management:** Employs cryptographically secure 32-byte tokens with a 30-minute inactivity timeout, eliminating server-side session state  [cite: 111, 125, 355-357].
* [cite_start]**Role-Based Access Control (RBAC):** Granular permission tiers (Admin, Contributor, Viewer) enforced at the server level via custom decorators  [cite: 111, 132-138, 369-370].
* [cite_start]**Brute-Force Defense:** Implements IP-based rate limiting (10 attempts/min) and hard account lockouts after 5 failed authentication attempts  [cite: 88, 169, 400-402].

## 🛠️ Technical Enhancements (Post-Design Doc)
The following critical enhancements were added during development to reach enterprise-grade hardening:
1.  [cite_start]**Structured JSON Audit Logging:** Implemented an `audit_log` decorator that creates a structured, forensic-ready trail of all file interactions (Uploads, Downloads, Deletions) for non-repudiation  [cite: 85-87, 197-198, 311-314].
2.  **MIME-Type Whitelisting:** Hardened the file upload pipeline to explicitly reject executable payloads (e.g., `.sh`, `.py`) through active MIME-type sniffing.
3.  [cite_start]**Path Traversal Prevention:** Enforced strict filename sanitization using `secure_filename()` and absolute path validation to prevent unauthorized directory access  [cite: 44-46, 220-222].

## ⚙️ Installation & Setup

### 1. Initialize Environment
```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install flask bcrypt cryptography
```

### 2. Generate TLS Certificates
```powershell
python generate_certs.py
```

### 3. Run the Secure Server
```powershell
python app.py
```
Access the application at: **[https://127.0.0.1:5000](https://127.0.0.1:5000)**

## 📂 Project Structure
* `app.py`: Core Flask application and security logic.
* `data/`: Encrypted document storage and JSON metadata.
* `docs/`: Technical reports and security specifications.
* `logs/`: Structured JSON security logs for forensic analysis.
* `presentation/`: Final project slide deck.
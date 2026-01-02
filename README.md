# Advanced Encryption Tool 

A secure file encryption and decryption tool using AES-256-GCM with
password-based key derivation (PBKDF2-HMAC-SHA256).

Designed to ensure confidentiality, integrity, and authenticity of files.

---

##  Security Features

- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 key derivation
- High iteration count (600,000)
- Random salt and nonce generation
- Tamper detection
- Hidden password input

---

##  Requirements

Install the required dependency:

```bash
pip install cryptography
```

---

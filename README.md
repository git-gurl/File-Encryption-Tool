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


## How It Works

1. User provides a password
2. A cryptographic key is derived using PBKDF2
3. File is encrypted using AES-256-GCM
4. Salt and nonce are stored with the encrypted file
5. Authentication tag ensures tamper detection

---

## Encryption Format

[ Salt (16 bytes) ]
[ Nonce (12 bytes) ]
[ Ciphertext + Authentication Tag ]

---

## Usage

Run the program:

```bash
python encryption_tool.py
```

### Encrypt a File

- Select encryption mode
- Provide file path
- Enter password
- Encrypted file is saved with `.enc` extension

### Decrypt a File

- Select decryption mode
- Provide encrypted file path
- Enter correct password
- Original file is restored

## Supported Operations

| Operation | Description |
|---------|-------------|
| Encrypt | Securely encrypt any file |
| Decrypt | Safely decrypt encrypted files |
| Password Masking | Prevents password exposure |
| Integrity Check | Detects file tampering |

## Error Handling

- Incorrect password detection
- Corrupted or modified file detection
- Invalid file path handling
- Graceful termination on failure

## Security Notes

- Passwords are never stored
- Each encryption uses a unique salt and nonce
- AES-GCM provides built-in integrity verification

## Use Cases

- Secure file storage
- Cybersecurity labs
- Cryptography learning
- Data protection demonstrations

## Disclaimer

This tool is intended for educational and personal security use only.
Do not use for illegal or unauthorized activities.


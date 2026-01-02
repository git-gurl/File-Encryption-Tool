import os
import sys
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# =========================================================
# Configuration & Security Constants
# =========================================================

KEY_SIZE = 32          # 32 bytes = AES-256
NONCE_SIZE = 12        # Recommended size for GCM
SALT_SIZE = 16         # Salt for password-based key derivation
KDF_ITERATIONS = 600_000  # High iteration count for security


# =========================================================
# Key Derivation
# =========================================================

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a secure 32-byte key from a password using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# =========================================================
# Encryption
# =========================================================

def encrypt_file(input_path: str, output_path: str, password: str):
    """
    Encrypts a file using AES-256-GCM.
    Output format:
    [Salt (16 bytes)] + [Nonce (12 bytes)] + [Ciphertext + Auth Tag]
    """
    try:
        with open(input_path, "rb") as f:
            plaintext = f.read()

        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        with open(output_path, "wb") as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

        print(f"\n[SUCCESS] File encrypted successfully.")
        print(f"Saved as: {output_path}")

    except IOError as e:
        print(f"\n[ERROR] File I/O error: {e}")
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")


# =========================================================
# Decryption
# =========================================================

def decrypt_file(input_path: str, output_path: str, password: str):
    """
    Decrypts a file encrypted using AES-256-GCM.
    """
    try:
        with open(input_path, "rb") as f:
            data = f.read()

        if len(data) < SALT_SIZE + NONCE_SIZE:
            print("\n[ERROR] File is too small or corrupted.")
            return

        salt = data[:SALT_SIZE]
        nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        ciphertext = data[SALT_SIZE + NONCE_SIZE:]

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        with open(output_path, "wb") as f:
            f.write(plaintext)

        print(f"\n[SUCCESS] File decrypted successfully.")
        print(f"Saved as: {output_path}")

    except InvalidTag:
        print("\n[ERROR] Incorrect password or file has been tampered with.")
    except IOError as e:
        print(f"\n[ERROR] File I/O error: {e}")
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")


# =========================================================
# User Input Helper
# =========================================================

def get_valid_filepath(prompt_text, must_exist=True):
    """
    Gets a valid FILE path from the user.
    Prevents empty input, folders, and invalid paths.
    """
    while True:
        path = input(prompt_text).strip()

        # Remove quotes if drag & dropped
        if (path.startswith('"') and path.endswith('"')) or \
           (path.startswith("'") and path.endswith("'")):
            path = path[1:-1]

        if not path:
            print("[!] Path cannot be empty. Please try again.")
            continue

        if must_exist:
            if not os.path.exists(path):
                print("[!] Path does not exist. Please check and try again.")
                continue
            if not os.path.isfile(path):
                print("[!] This is a folder, not a file. Please select a file.")
                continue

        return path


# =========================================================
# Main Program
# =========================================================

def main():
    print("=" * 60)
    print("   SECURE FILE ENCRYPTION TOOL (AES-256-GCM)")
    print("=" * 60)
    print("Tip: You can drag & drop files into this window.\n")

    while True:
        print("\nChoose an option:")
        print("  1. Encrypt a file")
        print("  2. Decrypt a file")
        print("  3. Exit")

        choice = input("\nEnter your choice (1/2/3): ").strip()

        # ---------------- Encrypt ----------------
        if choice == "1":
            print("\n--- ENCRYPT FILE ---")

            in_file = get_valid_filepath(
                "Enter FULL path to the file you want to encrypt:\n> ",
                must_exist=True
            )

            print("\nOutput file:")
            print("• Press ENTER to save as the same name with .enc added")
            print("• Or type a full output file path")

            out_file = input("\nOutput path (default: <input>.enc):\n> ").strip()
            if not out_file:
                out_file = in_file + ".enc"

            print("\nPassword setup:")
            print("(Password input is hidden — nothing will appear as you type)")
            print("Tip: Passwords must match exactly.\n")

            pwd = getpass.getpass("Enter encryption password: ")
            confirm_pwd = getpass.getpass("Confirm password: ")

            if pwd != confirm_pwd:
                print("\n[ERROR] Passwords do not match. Please try again.")
                continue

            encrypt_file(in_file, out_file, pwd)

        # ---------------- Decrypt ----------------
        elif choice == "2":
            print("\n--- DECRYPT FILE ---")

            in_file = get_valid_filepath(
                "Enter FULL path to the encrypted (.enc) file:\n> ",
                must_exist=True
            )

            default_out = (
                in_file[:-4] if in_file.endswith(".enc")
                else in_file + ".dec"
            )

            print("\nOutput file:")
            print("• Press ENTER to restore original filename")
            print("• Or type a full output file path")

            out_file = input(f"\nOutput path (default: {default_out}):\n> ").strip()
            if not out_file:
                out_file = default_out

            print("\nPassword input is hidden — nothing will appear as you type.")
            pwd = getpass.getpass("Enter decryption password: ")

            decrypt_file(in_file, out_file, pwd)

        # ---------------- Exit ----------------
        elif choice == "3":
            print("\nGoodbye. Stay secure 🔐")
            sys.exit(0)

        else:
            print("\n[!] Invalid choice. Please enter 1, 2, or 3.")


# =========================================================
# Entry Point
# =========================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)

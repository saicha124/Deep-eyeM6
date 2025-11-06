"""
Shared Secret Management Utility
Handles encryption and decryption of sensitive data
"""

import os
from pathlib import Path
from cryptography.fernet import Fernet

CONFIG_DIR = Path('config')
CONFIG_DIR.mkdir(exist_ok=True)


def get_encryption_key():
    """Get or create encryption key for API key storage"""
    key_file = CONFIG_DIR / '.secret_key'
    if key_file.exists():
        return key_file.read_bytes()
    else:
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        os.chmod(key_file, 0o600)
        return key


cipher = Fernet(get_encryption_key())


def encrypt_value(value):
    """Encrypt sensitive data"""
    if not value:
        return ""
    return cipher.encrypt(value.encode()).decode()


def decrypt_value(encrypted_value):
    """Decrypt sensitive data"""
    if not encrypted_value:
        return ""
    try:
        return cipher.decrypt(encrypted_value.encode()).decode()
    except:
        return encrypted_value


def get_decrypted_env(key, default=""):
    """Get and decrypt environment variable"""
    encrypted = os.getenv(key, default)
    if not encrypted or encrypted == default:
        return encrypted
    return decrypt_value(encrypted)

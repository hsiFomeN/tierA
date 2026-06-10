import hashlib
import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_pem, public_pem

def encrypt_private_key(private_key_pem: str, password: str) -> str:
    key = hashlib.sha256(password.encode('utf-8')).digest()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    data = private_key_pem.encode('utf-8')
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    encrypted = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode('utf-8')

def decrypt_private_key(encrypted_b64: str, password: str) -> str:
    raw = base64.b64decode(encrypted_b64)
    if len(raw) < 32:
        raise ValueError("Слишком короткие данные ключа.")
    iv = raw[:16]
    encrypted = raw[16:]
    key = hashlib.sha256(password.encode('utf-8')).digest()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    pad_len = decrypted_padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Неверный пароль или повреждены данные.")
    if decrypted_padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Неверный пароль (ошибка padding).")
    return decrypted_padded[:-pad_len].decode('utf-8')

def encrypt_message_hybrid(plaintext: str, recipient_public_key_pem: str):
    """Возвращает (enc_key_b64, enc_msg_b64)"""
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    data = plaintext.encode('utf-8')
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    ciphertext = encryptor.update(data) + encryptor.finalize()
    encrypted_message = iv + ciphertext

    public_key = serialization.load_pem_public_key(
        recipient_public_key_pem.encode(), backend=default_backend()
    )
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode('utf-8'), base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message_hybrid(encrypted_key_b64: str, encrypted_message_b64: str, private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(), password=None, backend=default_backend()
    )
    encrypted_key = base64.b64decode(encrypted_key_b64)
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_message = base64.b64decode(encrypted_message_b64)
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = decrypted_padded[-1]
    return decrypted_padded[:-pad_len].decode('utf-8')
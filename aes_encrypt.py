from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os

def aes_encrypt(input_file_path, output_file_path):
    # Đọc dữ liệu file đầu vào
    with open(input_file_path, "rb") as f:
        plaintext = f.read()

    # Sinh key AES 256-bit và IV 16 bytes (CBC)
    key = get_random_bytes(32)
    iv = get_random_bytes(16)

    # Padding PKCS7
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)

    # Mã hóa AES-CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)

    # Tạo hash SHA-256 của dữ liệu gốc
    sha256_hash = hashlib.sha256(plaintext).hexdigest()

    # Lưu [IV + ciphertext] vào file nhị phân
    with open(output_file_path, "wb") as f:
        f.write(iv + ciphertext)

    return key, sha256_hash  # Trả về key và hash

# home/quan05/doan/aes_encrypt.py

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# THÊM THAM SỐ `key=None` VÀO HÀM
def aes_encrypt(input_file_path, output_file_path, key=None):
    """
    Mã hóa file bằng AES-GCM.
    Nếu key được cung cấp, sử dụng key đó.
    Nếu không, tạo một key ngẫu nhiên.
    """
    # Đọc dữ liệu file đầu vào
    with open(input_file_path, "rb") as f:
        plaintext = f.read()

    # Kiểm tra xem có cần tạo key mới không
    if key is None:
        key = get_random_bytes(32) # Tạo key 256-bit (32 bytes) ngẫu nhiên

    # Tạo cipher với mode GCM
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    
    # Mã hóa và tạo thẻ xác thực
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Lưu [nonce + tag + ciphertext] vào file
    with open(output_file_path, "wb") as f:
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    # Luôn trả về khóa đã được sử dụng (dù là ngẫu nhiên hay được cung cấp)
    return key
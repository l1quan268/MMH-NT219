from Crypto.Cipher import AES
import os

def aes_decrypt(ciphertext_path, key, output_path):
    try:
        with open(ciphertext_path, "rb") as f:
            # Đọc theo đúng thứ tự và kích thước đã lưu
            nonce = f.read(12)      # Thường là 12 hoặc 16 bytes
            tag = f.read(16)        # Luôn là 16 bytes
            ciphertext = f.read()   # Phần còn lại

        # Tạo lại cipher với key và nonce
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # Giải mã và xác thực. Nếu dữ liệu bị sửa, dòng này sẽ báo lỗi ValueError
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Lưu file đã giải mã
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
        
        print("Giải mã và xác thực thành công!")
        return True

    except (ValueError, KeyError) as e:
        print(f"Lỗi giải mã hoặc xác thực: Dữ liệu có thể đã bị thay đổi. Lỗi: {e}")
        return False
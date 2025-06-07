# home/quan05/doan/send_to_cloud.py

from pymongo import MongoClient
from bson.binary import Binary
from bson.objectid import ObjectId 
import datetime

def send_to_cloud(ciphertext_path, encrypted_key_path, access_policy, patient_name, doctor_id, mongo_uri, db_name, collection_name):
    """
    Gửi dữ liệu mã hóa và khóa đã mã hóa lên MongoDB.
    
    Args:
        ciphertext_path (str): Đường dẫn file chứa ciphertext.
        encrypted_key_path (str): Đường dẫn file chứa AES key đã mã hóa bằng CP-ABE.
        access_policy (str): Chuỗi chính sách truy cập.
        patient_name (str): Tên của bệnh nhân.
        mongo_uri (str): URI kết nối MongoDB.
        db_name (str): Tên database.
        collection_name (str): Tên collection.
    
    Returns:
        inserted_id (ObjectId): ID của document đã được thêm vào MongoDB.
    """
    client = MongoClient(mongo_uri)
    db = client[db_name]
    collection = db[collection_name]

    # Đọc nội dung file ciphertext
    with open(ciphertext_path, "rb") as f_cipher:
        ciphertext = f_cipher.read()

    # Đọc nội dung file AES key đã mã hóa
    with open(encrypted_key_path, "rb") as f_key:
        encrypted_key = f_key.read()

    # Tạo document để lưu vào MongoDB
    document = {
        "patient_name": patient_name,           # <-- Sử dụng tham số patient_name
        "access_policy": access_policy,         # <-- Sử dụng tham số access_policy
        "doctor_id": ObjectId(doctor_id),
        "ciphertext": Binary(ciphertext),
        "aes_key_cpabe": Binary(encrypted_key),
        "created_at": datetime.datetime.utcnow() 
    }

    # Lưu document vào MongoDB
    result = collection.insert_one(document)
    return result.inserted_id
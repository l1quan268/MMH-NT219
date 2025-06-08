# home/quan05/doan/send_to_cloud.py

from pymongo import MongoClient
from bson.binary import Binary
from bson.objectid import ObjectId
import datetime


def send_to_cloud(ciphertext_path, encrypted_key_path, access_policy, patient_name, patient_id, doctor_id, mongo_uri, db_name, collection_name):
    """
    Gửi dữ liệu mã hóa và khóa đã mã hóa lên MongoDB.
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

        "patient_id": ObjectId(patient_id), # Lưu ID của bệnh nhân để tham chiếu
        "patient_name": patient_name,           # Vẫn lưu tên để dễ đọc
        "access_policy": access_policy,
        "doctor_id": ObjectId(doctor_id),
        "ciphertext": Binary(ciphertext),
        "aes_key_cpabe": Binary(encrypted_key),
        "created_at": datetime.datetime.utcnow()
    }

    # Lưu document vào MongoDB
    result = collection.insert_one(document)
    return result.inserted_id
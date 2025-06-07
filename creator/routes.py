# home/quan05/doan/creator/routes.py

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from functools import wraps
# Bỏ import hashlib vì không dùng nữa
from aes_encrypt import aes_encrypt
from cpabe_encrypt import cpabe_encrypt
from send_to_cloud import send_to_cloud

creator_bp = Blueprint('creator', __name__, template_folder='../templates')

UPLOAD_FOLDER = "temp/"
OUTPUT_FOLDER = "output/"

# Decorator không đổi
def doctor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session['user']['role'] != 'doctor':
            flash("Bạn không có quyền truy cập trang này.", "danger")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

# Route data_creator không đổi
@creator_bp.route('/data_creator', methods=['GET'])
@doctor_required
def data_creator():
    session.pop('encrypted_files', None)
    return render_template('data_creator.html', step='prepare', active_tab='data_creator')

# === SỬA TRONG HÀM NÀY ===
@creator_bp.route('/encrypt', methods=['POST'])
@doctor_required
def encrypt():
    patient_name = request.form.get("patient_name")
    policy = request.form.get("policy_expression")
    medical_file = request.files.get("medical_file")
    pk_file = request.files.get("public_key_file")

    if not all([patient_name, policy, medical_file, pk_file]):
        flash("Vui lòng điền và chọn đầy đủ các tệp.", "warning")
        return redirect(url_for('.data_creator'))
    
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    input_path = os.path.join(UPLOAD_FOLDER, medical_file.filename)
    medical_file.save(input_path)
    
    public_key_path = os.path.join(UPLOAD_FOLDER, pk_file.filename)
    pk_file.save(public_key_path)

    output_ciphertext_path = os.path.join(OUTPUT_FOLDER, "ciphertext.bin")
    
    # THAY ĐỔI 1: Lời gọi aes_encrypt giờ chỉ trả về 1 giá trị là `aes_key`
    aes_key = aes_encrypt(input_path, output_ciphertext_path)
    
    output_key_path = os.path.join(OUTPUT_FOLDER, "aes_key_cpabe.ct")
    cpabe_encrypt(aes_key, policy, public_key_path, output_key_path)

    # THAY ĐỔI 2: Xóa 'hash' ra khỏi session
    session['encrypted_files'] = {
        'patient_name': patient_name,
        'policy': policy,
        'ciphertext_path': output_ciphertext_path,
        'key_path': output_key_path
    }

    flash("Mã hóa thành công! Vui lòng xác nhận để tải lên Cloud.", "success")
    return redirect(url_for('.confirm_upload'))

# Route confirm_upload không đổi
@creator_bp.route('/confirm_upload', methods=['GET'])
@doctor_required
def confirm_upload():
    if 'encrypted_files' not in session:
        flash("Không có dữ liệu để xác nhận. Vui lòng bắt đầu lại.", "warning")
        return redirect(url_for('.data_creator'))
    
    files_info = {
        'patient_name': session['encrypted_files']['patient_name'],
        'policy': session['encrypted_files']['policy'],
        'ciphertext_file': os.path.basename(session['encrypted_files']['ciphertext_path']),
        'key_file': os.path.basename(session['encrypted_files']['key_path'])
    }
    return render_template('data_creator.html', step='confirm', files=files_info, active_tab='data_creator')

# === SỬA TRONG HÀM NÀY ===
@creator_bp.route('/upload', methods=['POST'])
@doctor_required
def upload():
    if 'encrypted_files' not in session:
        flash("Phiên làm việc hết hạn. Vui lòng bắt đầu lại.", "danger")
        return redirect(url_for('.data_creator'))

    encrypted_data = session['encrypted_files']
    doctor_id = session['user']['id']
    mongo_uri = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
    db_name = "ehr_db"
    
    # THAY ĐỔI 3: Xóa `file_hash` khỏi lời gọi hàm
    inserted_id = send_to_cloud(
        ciphertext_path=encrypted_data['ciphertext_path'],
        encrypted_key_path=encrypted_data['key_path'],
        access_policy=encrypted_data['policy'],
        patient_name=encrypted_data['patient_name'],
        doctor_id=doctor_id, 
        mongo_uri=mongo_uri,
        db_name=db_name,
        collection_name="medical_records"
    )

    session.pop('encrypted_files', None)
    try:
        os.remove(encrypted_data['ciphertext_path'])
        os.remove(encrypted_data['key_path'])
    except OSError as e:
        print(f"Lỗi khi xóa file tạm: {e}")

    flash(f"Tải hồ sơ lên Cloud thành công! ID: {inserted_id}", "success")
    return redirect(url_for('.data_creator'))
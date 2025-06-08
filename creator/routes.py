# home/quan05/doan/creator/routes.py

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Thêm send_file và io
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_file
from functools import wraps
import io # Dùng để tạo file trong bộ nhớ

from aes_encrypt import aes_encrypt
from cpabe_encrypt import cpabe_encrypt
from send_to_cloud import send_to_cloud

creator_bp = Blueprint('creator', __name__, template_folder='../templates')

UPLOAD_FOLDER = "temp/"
OUTPUT_FOLDER = "output/"

def doctor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session['user']['role'] != 'doctor':
            flash("Bạn không có quyền truy cập trang này.", "danger")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@creator_bp.route('/data_creator', methods=['GET'])
@doctor_required
def data_creator():
    session.pop('upload_info', None) # Xóa session cũ nếu có
    return render_template('data_creator.html', step='prepare', active_tab='data_creator')

# =======================================================
# == ROUTE BỊ THIẾU ĐÃ ĐƯỢC THÊM VÀO ĐÂY ==
# =======================================================
@creator_bp.route('/generate-policy', methods=['POST'])
@doctor_required
def generate_policy():
    policies_data = request.form.getlist('policies')
    if not policies_data:
        flash("Lỗi: Không có thuộc tính nào được chọn.", "danger")
        return redirect(url_for('.data_creator'))

    groups = {}
    for item in policies_data:
        policy, group = item.split('|')
        if not groups.get(group):
            groups[group] = []
        groups[group].append(policy)

    if not groups.get('role'):
        flash("Lỗi: Bắt buộc phải chọn vai trò.", "danger")
        return redirect(url_for('.data_creator'))

    # ==========================================================
    # == QUAY LẠI LOGIC ĐƠN GIẢN, KHÔNG SẮP XẾP ==
    # ==========================================================
    policyParts = []
    
    # Lặp qua các nhóm theo thứ tự tự nhiên
    for group_name in groups:
        policies_in_group = groups[group_name]
        if len(policies_in_group) > 1:
            policyParts.append(f"({' or '.join(policies_in_group)})")
        else:
            policyParts.append(policies_in_group[0])

    final_policy = ' and '.join(policyParts)

    # ... (phần tạo và gửi file không đổi) ...
    mem_file = io.BytesIO()
    mem_file.write(final_policy.encode('utf-8'))
    mem_file.seek(0)

    return send_file(
        mem_file,
        mimetype='text/plain',
        as_attachment=True,
        download_name='access_policy.txt'
    )

# ROUTE /encrypt ĐÃ ĐƯỢC CẬP NHẬT ĐỂ NHẬN FILE CHÍNH SÁCH
@creator_bp.route('/encrypt', methods=['POST'])
@doctor_required
def encrypt():
    patient_name = request.form.get("patient_name")
    medical_file = request.files.get("medical_file")
    pk_file = request.files.get("public_key_file")
    policy_file = request.files.get("policy_file")

    if not all([patient_name, medical_file, pk_file, policy_file]):
        flash("Vui lòng điền và chọn đầy đủ 4 tệp được yêu cầu.", "warning")
        return redirect(url_for('.data_creator'))

    try:
        policy = policy_file.read().decode('utf-8').strip()
        if not policy: raise ValueError("File rỗng")
    except Exception as e:
        flash(f"Lỗi: File chính sách không hợp lệ. {e}", "danger")
        return redirect(url_for('.data_creator'))
    
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    input_path = os.path.join(UPLOAD_FOLDER, medical_file.filename)
    medical_file.save(input_path)
    
    public_key_path = os.path.join(UPLOAD_FOLDER, pk_file.filename)
    pk_file.save(public_key_path)

    output_ciphertext_path = os.path.join(OUTPUT_FOLDER, "ciphertext.bin")
    aes_key = aes_encrypt(input_path, output_ciphertext_path)
    
    output_key_path = os.path.join(OUTPUT_FOLDER, "aes_key_cpabe.ct")
    cpabe_encrypt(aes_key, policy, public_key_path, output_key_path)

    session['upload_info'] = {
        'patient_name': patient_name,
        'policy': policy,
        'doctor_id': session['user']['id']
    }

    flash("Mã hóa thành công! Các file đã được tạo trong 'output/'. Vui lòng chọn chúng ở Bước 2.", "success")
    return redirect(url_for('.confirm_upload'))


@creator_bp.route('/confirm_upload')
@doctor_required
def confirm_upload():
    if 'upload_info' not in session:
        return redirect(url_for('.data_creator'))
    
    info = session['upload_info']
    return render_template('data_creator.html', step='confirm', info=info, active_tab='data_creator')

@creator_bp.route('/upload', methods=['POST'])
@doctor_required
def upload():
    if 'upload_info' not in session:
        flash("Phiên làm việc hết hạn, vui lòng bắt đầu lại.", "danger")
        return redirect(url_for('.data_creator'))

    ciphertext_file = request.files.get("ciphertext_file_upload")
    key_file = request.files.get("key_file_upload")

    if not all([ciphertext_file, key_file]):
        flash("Vui lòng chọn đủ 2 file được yêu cầu để upload.", "danger")
        return redirect(url_for('.confirm_upload'))
    
    info = session['upload_info']

    temp_ciphertext_path = os.path.join(UPLOAD_FOLDER, ciphertext_file.filename)
    ciphertext_file.save(temp_ciphertext_path)
    temp_key_path = os.path.join(UPLOAD_FOLDER, key_file.filename)
    key_file.save(temp_key_path)

    mongo_uri = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
    db_name = "ehr_db"
    
    inserted_id = send_to_cloud(
        ciphertext_path=temp_ciphertext_path,
        encrypted_key_path=temp_key_path,
        access_policy=info['policy'],
        patient_name=info['patient_name'],
        doctor_id=info['doctor_id'], 
        mongo_uri=mongo_uri,
        db_name=db_name,
        collection_name="medical_records"
    )   

    session.pop('upload_info', None)
    flash(f"Tải hồ sơ lên Cloud thành công! ID: {inserted_id}", "success")
    return redirect(url_for('.data_creator'))
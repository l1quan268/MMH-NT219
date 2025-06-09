import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Blueprint, render_template, request, session, flash, redirect, url_for, send_file
from functools import wraps
from pymongo import MongoClient
from bson.objectid import ObjectId
import pickle
import io
import zipfile

from aes_encrypt import aes_encrypt
from cpabe_encrypt import cpabe_encrypt
from aes_decrypt import aes_decrypt
from cpabe_decrypt import cpabe_decrypt
from send_to_cloud import send_to_cloud

from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07

user_bp = Blueprint('user', __name__, template_folder='../templates')

UPLOAD_FOLDER = "temp/"
OUTPUT_FOLDER = "output/"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Vui lòng đăng nhập để truy cập trang này.", "warning")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@user_bp.route('/data_user', methods=['GET', 'POST'])
@login_required
def data_user():
    user = session['user']
    user_role = user['role'] # Lấy vai trò viết thường từ session, vd: 'doctor'
    results = []
    
    mongo_uri = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
    client = MongoClient(mongo_uri)
    db = client.ehr_db

    # Sửa điều kiện so sánh thành chữ thường
    if user_role == 'doctor':
        if request.method == 'POST':
            doctor_attributes = user.get('attributes', {})
            
            # Xây dựng chuỗi thuộc tính từ role viết thường, sau đó title() để thành chữ hoa
            search_conditions = [f"role:{user_role.title()}"]
            if 'department' in doctor_attributes:
                search_conditions.append(f"dept:{doctor_attributes['department']}")

            query = {
                '$and': [
                    {'access_policy': {'$regex': condition, '$options': 'i'}} for condition in search_conditions
                ]
            }
            results = list(db.medical_records.find(query, {'ciphertext': 0, 'aes_key_cpabe': 0}))
            flash(f"Tìm thấy {len(results)} hồ sơ phù hợp.", "info")
    # Sửa điều kiện so sánh thành chữ thường
    elif user_role == 'patient':
        patient_id_str = user['id']
        results = list(db.medical_records.find(
            {'patient_id': ObjectId(patient_id_str)}, 
            {'ciphertext': 0, 'aes_key_cpabe': 0}
        ))
        
    return render_template('data_user.html', results=results, active_tab='data_user')


# ... route download_record không đổi ...

@user_bp.route('/download-record', methods=['POST'])
@login_required
def download_record():
    doc_id = request.form.get('doc_id')
    if not doc_id:
        flash("Lỗi: Thiếu ID hồ sơ.", "danger")
        return redirect(url_for('.data_user'))

    mongo_uri = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
    client = MongoClient(mongo_uri)
    db = client.ehr_db
    record = db.medical_records.find_one({'_id': ObjectId(doc_id)})
    
    if not record:
        flash("Không tìm thấy hồ sơ.", "danger")
        return redirect(url_for('.data_user'))

    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr("ciphertext.bin", record['ciphertext'])
        zipf.writestr("aes_key_cpabe.ct", record['aes_key_cpabe'])
    mem_zip.seek(0)

    return send_file(mem_zip, mimetype='application/zip', as_attachment=True, download_name=f'record_{doc_id}.zip')

# ... route request_secret_key không đổi ...

@user_bp.route('/request-secret-key', methods=['POST'])
@login_required
def request_secret_key():
    attributes = request.form.getlist('attributes')
    if not attributes:
        flash("Vui lòng chọn thuộc tính để yêu cầu khóa.", "warning")
        return redirect(url_for('.data_user'))

    try:
        group = PairingGroup('SS512')
        cpabe = CPabe_BSW07(group)
        with open("public_key.pk", "rb") as f: pk = pickle.load(f)
        with open("master_key.mk", "rb") as f: mk = pickle.load(f)
        
        sk = cpabe.keygen(pk, mk, attributes)

        mem_file = io.BytesIO()
        pickle.dump(sk, mem_file)
        mem_file.seek(0)
        
        return send_file(mem_file, mimetype='application/octet-stream', as_attachment=True, download_name='secret_key.sk')
    except FileNotFoundError:
        flash("Lỗi hệ thống: Không tìm thấy Master Key hoặc Public Key để tạo khóa.", "danger")
        return redirect(url_for('.data_user'))
    except Exception as e:
        flash(f"Lỗi không xác định khi tạo khóa: {e}", "danger")
        return redirect(url_for('.data_user'))

# ... route decrypt_record không đổi ...

@user_bp.route('/decrypt-record', methods=['POST'])
@login_required
def decrypt_record():
    ciphertext_file = request.files.get('ciphertext_file')
    encrypted_key_file = request.files.get('encrypted_key_file')
    secret_key_file = request.files.get('secret_key_file')
    public_key_file = request.files.get('public_key_file')

    if not all([ciphertext_file, encrypted_key_file, secret_key_file, public_key_file]):
        flash("Vui lòng cung cấp đủ 4 file để giải mã.", "danger")
        return redirect(url_for('.data_user'))

    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(OUTPUT_FOLDER, exist_ok=True)

        ct_path = os.path.join(UPLOAD_FOLDER, "temp_ciphertext.bin")
        ek_path = os.path.join(UPLOAD_FOLDER, "temp_encrypted_key.ct")
        sk_path = os.path.join(UPLOAD_FOLDER, "temp_secret_key.sk")
        pk_path = os.path.join(UPLOAD_FOLDER, "temp_public_key.pk")
        ciphertext_file.save(ct_path)
        encrypted_key_file.save(ek_path)
        secret_key_file.save(sk_path)
        public_key_file.save(pk_path)

        aes_key = cpabe_decrypt(ek_path, sk_path, pk_path)
        if not aes_key:
            raise ValueError("Không thể giải mã khóa AES. Thuộc tính không khớp với chính sách hoặc khóa không hợp lệ.")

        decrypted_path = os.path.join(OUTPUT_FOLDER, "decrypted_record.txt")
        success = aes_decrypt(ct_path, aes_key, decrypted_path)
        if not success:
            raise ValueError("Giải mã AES thất bại. File có thể đã bị thay đổi hoặc khóa AES không đúng.")
            
        return send_file(decrypted_path, as_attachment=True, download_name="HOSODAGIAIMA.txt")

    except Exception as e:
        flash(f"Quá trình giải mã thất bại: {e}", "danger")
        return redirect(url_for('.data_user'))


@user_bp.route('/patient-upload', methods=['GET', 'POST'])
@login_required
def patient_upload():
    # Sửa điều kiện so sánh thành chữ thường
    if session['user']['role'] != 'patient':
        flash("Chức năng này chỉ dành cho bệnh nhân.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        policy = request.form.get("policy_expression")
        description = request.form.get("record_description")
        medical_file = request.files.get("medical_file")
        pk_file = request.files.get("public_key_file")
        
        if not all([policy, description, medical_file, pk_file]):
            flash("Vui lòng điền và chọn đầy đủ các tệp.", "warning")
            return redirect(url_for('.patient_upload'))

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(OUTPUT_FOLDER, exist_ok=True)

        input_path = os.path.join(UPLOAD_FOLDER, medical_file.filename)
        medical_file.save(input_path)
        public_key_path = os.path.join(UPLOAD_FOLDER, pk_file.filename)
        pk_file.save(public_key_path)

        output_ciphertext_path = os.path.join(OUTPUT_FOLDER, "patient_ciphertext.bin")
        aes_key = aes_encrypt(input_path, output_ciphertext_path)
        
        output_key_path = os.path.join(OUTPUT_FOLDER, "patient_aes_key_cpabe.ct")
        cpabe_encrypt(aes_key, policy, public_key_path, output_key_path)

        session['patient_upload_info'] = {
            'policy': policy,
            'description': description
        }
        
        flash("Mã hóa thành công! Các file đã được tạo trong 'output/'. Vui lòng chọn chúng ở Bước 2 để tải lên.", "success")
        return redirect(url_for('.patient_confirm_upload'))

    session.pop('patient_upload_info', None)
    return render_template('patient_upload.html', step='prepare', active_tab='patient_upload')


@user_bp.route('/patient-confirm-upload')
@login_required
def patient_confirm_upload():
    if 'patient_upload_info' not in session:
        return redirect(url_for('.patient_upload'))
    
    return render_template('patient_upload.html', step='confirm', active_tab='patient_upload')


@user_bp.route('/patient-do-upload', methods=['POST'])
@login_required
def patient_do_upload():
    if 'patient_upload_info' not in session:
        flash("Phiên làm việc hết hạn.", "danger")
        return redirect(url_for('.patient_upload'))

    ciphertext_file = request.files.get("ciphertext_file_upload")
    key_file = request.files.get("key_file_upload")

    if not all([ciphertext_file, key_file]):
        flash("Vui lòng chọn đủ 2 file.", "danger")
        return redirect(url_for('.patient_confirm_upload'))
    
    info = session['patient_upload_info']

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
        patient_name=session['user']['name'],
        patient_id=session['user']['id'],
        doctor_id=None,
        record_description=info['description'],
        # Sửa giá trị gửi đi thành chữ thường để nhất quán
        uploaded_by='patient',
        mongo_uri=mongo_uri,
        db_name=db_name,
        collection_name="medical_records"
    )
    
    session.pop('patient_upload_info', None)
    flash(f"Tải hồ sơ cá nhân thành công! ID: {inserted_id}", "success")
    return redirect(url_for('.data_user'))
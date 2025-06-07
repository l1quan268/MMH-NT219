# home/quan05/doan/user/routes.py

from flask import Blueprint, render_template, request, session, flash, redirect, url_for
from functools import wraps
from pymongo import MongoClient

user_bp = Blueprint('user', __name__, template_folder='../templates')

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
    user_role = session['user']['role']
    results = []
    
    mongo_uri = "mongodb+srv://tquan7245:abe123456@abe-cluster.f8itefc.mongodb.net/?retryWrites=true&w=majority&appName=abe-cluster"
    client = MongoClient(mongo_uri)
    db = client.ehr_db

    if request.method == 'POST' and user_role == 'doctor':
        results = list(db.medical_records.find({}, {'ciphertext': 0, 'aes_key_cpabe': 0}))
        flash(f"Tìm thấy {len(results)} hồ sơ.", "info")
    elif user_role == 'patient':
        user_name = session['user']['name']
        results = list(db.medical_records.find({'patient_name': user_name}, {'ciphertext': 0, 'aes_key_cpabe': 0}))
        
    return render_template('data_user.html', results=results, active_tab='data_user')

@user_bp.route('/decrypt_record', methods=['POST'])
@login_required
def decrypt_record():
    flash("Chức năng giải mã đang được phát triển!", "info")
    return redirect(url_for('.data_user'))
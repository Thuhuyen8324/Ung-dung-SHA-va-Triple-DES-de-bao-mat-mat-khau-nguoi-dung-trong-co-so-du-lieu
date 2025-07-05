from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from database import db
from models import User, LoginLog
from utils.security import generate_salt, process_password_for_storage, verify_password
from datetime import datetime 
from config import Config

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard')) 

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Kiểm tra tồn tại user
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html')

        # Kiểm tra mật khẩu khớp
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        # Kiểm tra độ mạnh của mật khẩu (tùy chỉnh theo yêu cầu)
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html')
        # Thêm các kiểm tra độ mạnh khác nếu cần: chữ hoa, chữ thường, số, ký tự đặc biệt

        # Xử lý mật khẩu an toàn
        salt = generate_salt()
        encrypted_password = process_password_for_storage(username, password, salt)

        new_user = User(
            username=username,
            salt=salt,
            encrypted_password=encrypted_password,
            fail_attempts=0,
            is_locked=False,
            # SỬ DỤNG UTC ĐỂ LƯU TRỮ TRONG DATABASE
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard')) 

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr 

        user = User.query.filter_by(username=username).first()

        if user:
            # Kiểm tra tài khoản bị khóa
            if user.is_locked:
                flash('Your account is locked due to too many failed attempts. Please contact an administrator.', 'danger')
                log_failed_login(user.id, username, ip_address, "Locked account login attempt")
                return render_template('login.html')

            # Kiểm tra mật khẩu
            if verify_password(username, password, user.salt, user.encrypted_password):
                login_user(user) # Đăng nhập người dùng bằng Flask-Login
                user.fail_attempts = 0 # Reset số lần thử sai
                # SỬ DỤNG UTC ĐỂ LƯU TRỮ TRONG DATABASE
                user.updated_at = datetime.utcnow()
                db.session.commit()
                # Ghi log đăng nhập thành công
                log_successful_login(user.id, username, ip_address)

                flash('Login successful!', 'success')
                if username == 'admin':
                    return redirect(url_for('admin.admin_dashboard'))
                return redirect(url_for('main.dashboard'))
            else:
                # Mật khẩu sai
                user.fail_attempts += 1
                if user.fail_attempts >= Config.MAX_FAILED_ATTEMPTS:
                    user.is_locked = True
                    flash(f'Too many failed login attempts. Your account has been locked. Please contact an administrator.', 'danger')
                    log_failed_login(user.id, username, ip_address, "Account locked due to too many failed attempts")
                else:
                    flash(f'Invalid username or password. You have {Config.MAX_FAILED_ATTEMPTS - user.fail_attempts} attempts left before your account is locked.', 'danger')
                log_failed_login(user.id, username, ip_address, "Invalid password")
                db.session.commit()
        else:
            # Username không tồn tại
            flash('Invalid username or password.', 'danger')
            log_failed_login(None, username, ip_address, "Non-existent username")
            db.session.commit()

    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        user = current_user 
        # Xác minh mật khẩu hiện tại
        if not verify_password(user.username, current_password, user.salt, user.encrypted_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html')

        # Kiểm tra mật khẩu mới khớp
        if new_password != confirm_new_password:
            flash('New passwords do not match.', 'danger')
            return render_template('change_password.html')

        # Kiểm tra độ mạnh của mật khẩu mới (tùy chỉnh theo yêu cầu)
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'danger')
            return render_template('change_password.html')

        # Cập nhật mật khẩu mới
        new_salt = generate_salt()
        user.salt = new_salt
        user.encrypted_password = process_password_for_storage(user.username, new_password, new_salt)
        # SỬ DỤNG UTC ĐỂ LƯU TRỮ TRONG DATABASE
        user.updated_at = datetime.utcnow()
        db.session.commit()

        flash('Your password has been changed successfully.', 'success')
        return redirect(url_for('main.dashboard'))
    return render_template('change_password.html')

def log_successful_login(user_id, username, ip_address):
    log = LoginLog(
        user_id=user_id,
        username=username,
        # SỬ DỤNG UTC ĐỂ LƯU TRỮ TRONG DATABASE
        login_time=datetime.utcnow(), 
        status='Success',
        ip_address=ip_address
    )
    db.session.add(log)
    db.session.commit() # Commit ngay sau khi thêm log

def log_failed_login(user_id, username, ip_address, reason):
    # Rút gọn chuỗi 'reason' nếu cần thiết để đảm bảo nó không vượt quá 50 ký tự
    status_message = f'Failed: {reason}'
    if len(status_message) > 50:
        status_message = status_message[:47] + '...'

    log = LoginLog(
        user_id=user_id, 
        username=username,
        # SỬ DỤNG UTC ĐỂ LƯU TRỮ TRONG DATABASE
        login_time=datetime.utcnow(),
        status=status_message,
        ip_address=ip_address
    )
    db.session.add(log)
    db.session.commit() 

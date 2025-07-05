from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from database import db
from models import User, LoginLog
from utils.security import generate_salt, process_password_for_storage, verify_password
from datetime import datetime, timedelta
from sqlalchemy import desc
from functools import wraps 

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
def admin_required(f):
    @wraps(f) 
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/')
@admin_required
def admin_dashboard():
    return render_template('admin/dashboard.html')

@admin_bp.route('/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/lock/<int:user_id>')
@admin_required
def lock_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash('Cannot lock the administrator account.', 'danger')
        return redirect(url_for('admin.manage_users'))

    user.is_locked = True
    user.fail_attempts = 0 # Reset attempts khi khóa
    user.updated_at = datetime.utcnow()
    db.session.commit()
    flash(f'User {user.username} has been locked.', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/unlock/<int:user_id>')
@admin_required
def unlock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_locked = False
    user.fail_attempts = 0 # Reset attempts khi mở khóa
    user.updated_at = datetime.utcnow()
    db.session.commit()
    flash(f'User {user.username} has been unlocked.', 'success')
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/reset_password/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        if new_password != confirm_new_password:
            flash('Passwords do not match.', 'danger')
            return render_template('admin/reset_password.html', user=user)

        if len(new_password) < 8: # Kiểm tra độ mạnh mật khẩu cơ bản
            flash('New password must be at least 8 characters long.', 'danger')
            return render_template('admin/reset_password.html', user=user)

        # Cập nhật mật khẩu mới cho người dùng
        new_salt = generate_salt()
        user.salt = new_salt
        user.encrypted_password = process_password_for_storage(user.username, new_password, new_salt)
        user.is_locked = False # Mở khóa nếu bị khóa
        user.fail_attempts = 0 # Reset fail attempts
        user.updated_at = datetime.utcnow()
        db.session.commit()

        flash(f'Password for user {user.username} has been reset successfully. Account unlocked.', 'success')
        return redirect(url_for('admin.manage_users'))

    return render_template('admin/reset_password.html', user=user)
@admin_bp.route('/login_logs')
@admin_required
def view_login_logs():
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    logs = LoginLog.query.filter(LoginLog.login_time >= seven_days_ago).order_by(desc(LoginLog.login_time)).all()
    return render_template('admin/login_logs.html', logs=logs)

# THÊM ROUTE XÓA TÀI KHOẢN TẠI ĐÂY
@admin_bp.route('/users/delete/<int:user_id>')
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # Ngăn không cho xóa tài khoản admin chính
    if user.username == 'admin':
        flash('Cannot delete the administrator account.', 'danger')
        return redirect(url_for('admin.manage_users'))

    try:
        LoginLog.query.filter_by(user_id=user_id).delete()
        
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback() 
        flash(f'Error deleting user {user.username}: {e}', 'danger')

    return redirect(url_for('admin.manage_users'))

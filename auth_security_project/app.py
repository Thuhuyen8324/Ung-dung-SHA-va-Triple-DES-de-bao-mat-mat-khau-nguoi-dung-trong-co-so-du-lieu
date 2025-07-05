from flask import Flask, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_required, current_user
from config import Config
from database import db
from models import User # Chỉ cần import User, LoginLog sẽ được thêm vào qua các routes
from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.main import main_bp
from datetime import timedelta
import pytz # ĐÃ THÊM DÒNG NÀY ĐỂ IMPORT PYTZ

# Khởi tạo ứng dụng Flask
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config) # Tải cấu hình từ class Config trong config.py

    # Khởi tạo SQLAlchemy và liên kết với ứng dụng Flask
    db.init_app(app)

    # Khởi tạo Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login' # Đặt view mặc định khi người dùng chưa đăng nhập

    # Callback function cho Flask-Login để tải người dùng từ ID
    @login_manager.user_loader
    def load_user(user_id):
        # Hàm này được Flask-Login sử dụng để tải người dùng dựa trên ID phiên
        return User.query.get(int(user_id))

    # CUNG CẤP PYTZ VÀ TIMEZONE CHO JINJA2 TEMPLATE
    app.jinja_env.globals.update(utc=pytz.utc, timezone=pytz.timezone) # ĐÃ THÊM DÒNG NÀY


    # Đăng ký các Blueprints (các module routes)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(main_bp)

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            if current_user.username == 'admin':
                return redirect(url_for('admin.admin_dashboard'))
            return redirect(url_for('main.dashboard'))
        # Nếu chưa đăng nhập, chuyển hướng đến trang login
        return redirect(url_for('auth.login'))

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('403.html'), 403

    return app

if __name__ == '__main__':
    app = create_app()

    with app.app_context():
        print("Database initialized (or skipped as tables exist).")

        from models import User
        from utils.security import generate_salt, process_password_for_storage
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_salt = generate_salt()
            admin_encrypted_password = process_password_for_storage('admin', 'admin@123', admin_salt) # Mật khẩu mặc định
            new_admin = User(
                username='admin',
                salt=admin_salt,
                encrypted_password=admin_encrypted_password,
                is_locked=False,
                fail_attempts=0
            )
            db.session.add(new_admin)
            db.session.commit()
            print("Default admin user 'admin' created with password 'admin@123'. PLEASE CHANGE THIS!")
        else:
            print("Admin user already exists.")


    app.run(debug=True, port=5000) # Chạy ứng dụng ở chế độ debug

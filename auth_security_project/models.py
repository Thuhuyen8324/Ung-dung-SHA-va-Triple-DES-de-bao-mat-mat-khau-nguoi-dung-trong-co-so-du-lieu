from datetime import datetime
from database import db 
from flask_login import UserMixin 
import pytz 

class User(db.Model, UserMixin):
    """
    Định nghĩa bảng 'users' trong cơ sở dữ liệu.
    Chứa thông tin người dùng và các thuộc tính bảo mật mật khẩu.
    """
    __tablename__ = 'users' 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.NVARCHAR(80), unique=True, nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    encrypted_password = db.Column(db.String(256), nullable=False)
    fail_attempts = db.Column(db.Integer, default=0) 
    is_locked = db.Column(db.Boolean, default=False) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow) 

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"<User {self.username}>"

class LoginLog(db.Model):

    __tablename__ = 'login_logs' 

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.NVARCHAR(80), nullable=False) 
    login_time = db.Column(db.DateTime, default=datetime.utcnow) 
    status = db.Column(db.NVARCHAR(500), nullable=False) 
    ip_address = db.Column(db.String(45), nullable=True) 

    def __repr__(self):
        return f"<LoginLog {self.username} - {self.status} at {self.login_time}>"
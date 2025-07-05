import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'một chuỗi bí mật khó đoán hơn nhiều cho session của bạn'

    SQLALCHEMY_DATABASE_URI = (
        f"mssql+pyodbc://THUHUYEN\\SQLEXPRESS/AuthDB"
        f"?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes;charset=utf8" 
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    TRIPLE_DES_KEY = b'THIS_IS_A_24_BYTE_KEY!!!' # Đây là 24 ký tự (chính xác)

    if len(TRIPLE_DES_KEY) != 24:
        raise ValueError("TRIPLE_DES_KEY must be exactly 24 bytes long.")

    TRIPLE_DES_IV = b'MyRandom' # Đây là 8 ký tự (chính xác)
    if len(TRIPLE_DES_IV) != 8:
        raise ValueError("TRIPLE_DES_IV must be exactly 8 bytes long.")

    MAX_FAILED_ATTEMPTS = 5

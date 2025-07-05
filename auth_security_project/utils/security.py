import hashlib
import os
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import base64
from config import Config 


TRIPLE_DES_KEY = Config.TRIPLE_DES_KEY
TRIPLE_DES_IV = Config.TRIPLE_DES_IV

def generate_salt(length=32):

    return os.urandom(length).hex() 

def hash_sha256(data: str) -> str:

    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def encrypt_3des(data_bytes: bytes) -> str:
    if len(TRIPLE_DES_KEY) != 24:
        raise ValueError("TRIPLE_DES_KEY must be exactly 24 bytes long in config.py")
    if len(TRIPLE_DES_IV) != 8:
        raise ValueError("TRIPLE_DES_IV must be exactly 8 bytes long in config.py")

    cipher = DES3.new(TRIPLE_DES_KEY, DES3.MODE_CBC, TRIPLE_DES_IV)
    padded_data = pad(data_bytes, DES3.block_size)
    encrypted_bytes = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_3des(encrypted_data_b64: str) -> bytes:
    
    if len(TRIPLE_DES_KEY) != 24:
        raise ValueError("TRIPLE_DES_KEY must be exactly 24 bytes long in config.py")
    if len(TRIPLE_DES_IV) != 8:
        raise ValueError("TRIPLE_DES_IV must be exactly 8 bytes long in config.py")

    encrypted_bytes = base64.b64decode(encrypted_data_b64)
    cipher = DES3.new(TRIPLE_DES_KEY, DES3.MODE_CBC, TRIPLE_DES_IV)
    decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
    # Loại bỏ padding sau khi giải mã
    return unpad(decrypted_padded_bytes, DES3.block_size)

def process_password_for_storage(username: str, password: str, salt: str) -> str:
   
    # 1. Băm password + salt
    hashed_password_salt = hash_sha256(password + salt)

    # 2. Băm username
    hashed_username = hash_sha256(username)

    combined_hash_string = hashed_password_salt + hashed_username
    final_hashed_result_hex = hash_sha256(combined_hash_string)

    final_hashed_result_bytes = bytes.fromhex(final_hashed_result_hex)
    encrypted_final_hash = encrypt_3des(final_hashed_result_bytes)

    return encrypted_final_hash

def verify_password(username: str, password_input: str, stored_salt: str, stored_encrypted_password: str) -> bool:
    # Xử lý mật khẩu nhập vào theo cùng quy trình đã lưu
    processed_input_password = process_password_for_storage(username, password_input, stored_salt)
    # So sánh kết quả đã xử lý với mật khẩu đã mã hóa được lưu trữ
    return processed_input_password == stored_encrypted_password

# --- Các hàm kiểm thử nhanh (không dùng trong ứng dụng chính) ---
if __name__ == '__main__':
    print("--- Testing Security Functions ---")

    salt = generate_salt()
    print(f"Generated Salt ({len(salt)} chars): {salt}")
    assert len(salt) == 64

    test_string = "Hello Security!"
    hashed_test = hash_sha256(test_string)
    print(f"SHA-256 of '{test_string}': {hashed_test} ({len(hashed_test)} chars)")
    assert len(hashed_test) == 64

    original_data = b"This is a test message for 3DES encryption. 1234567890ABCDEF"
    encrypted_data_b64 = encrypt_3des(original_data)
    print(f"Original Bytes ({len(original_data)}): {original_data}")
    print(f"Encrypted (Base64) ({len(encrypted_data_b64)} chars): {encrypted_data_b64}")

    decrypted_data = decrypt_3des(encrypted_data_b64)
    print(f"Decrypted Bytes ({len(decrypted_data)}): {decrypted_data}")
    assert original_data == decrypted_data
    print("3DES Encryption/Decryption test passed!")

    test_username = "testuser"
    test_password = "SecurePassword123!"
    test_salt = generate_salt()

    stored_encrypted_pwd = process_password_for_storage(test_username, test_password, test_salt)
    print(f"\nProcessed Password (stored): {stored_encrypted_pwd}")

    is_correct = verify_password(test_username, test_password, test_salt, stored_encrypted_pwd)
    print(f"Verification with correct password: {is_correct}")
    assert is_correct == True

    is_incorrect = verify_password(test_username, "WrongPassword", test_salt, stored_encrypted_pwd)
    print(f"Verification with incorrect password: {is_incorrect}")
    assert is_incorrect == False
    print("Password processing and verification test passed!")

    print("\n--- All security functions tested successfully! ---")
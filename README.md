<h2 align="center">📸 Kết quả hiển thị</h2>
<h2 align=""center">🛡️ ỨNG DỤNG BẢO MẬT MẬT KHẨU NGƯỜI DÙNG BẰNG SHA-256 VÀ TRIPLE DES TRONG FLASK</h2>
<h2>✨ Giới thiệu</h2>
Trong kỷ nguyên số hóa hiện nay, việc bảo vệ dữ liệu cá nhân, đặc biệt là thông tin đăng nhập như mật khẩu, đã trở thành ưu tiên hàng đầu. Các cuộc tấn công mạng nhằm vào mật khẩu đang ngày càng tinh vi, đặt ra thách thức lớn cho các hệ thống phần mềm. Dự án này tập trung vào việc xây dựng một hệ thống xác thực người dùng an toàn, sử dụng các thuật toán mật mã mạnh mẽ là SHA-256 để băm mật khẩu và Triple DES (3DES) để mã hóa lớp cuối cùng, đảm bảo mật khẩu không bao giờ được lưu trữ dưới dạng văn bản thuần trong cơ sở dữ liệu.

Hệ thống được phát triển trên nền tảng Python và Flask Framework, kết nối với MS SQL Server. Ngoài việc áp dụng các thuật toán mật mã, dự án còn tích hợp các tính năng bảo mật thiết yếu như sử dụng Salt ngẫu nhiên cho mỗi mật khẩu, kết hợp tên đăng nhập vào quá trình băm, và cơ chế tự động khóa tài khoản khi có nhiều lần đăng nhập thất bại.

Mục tiêu của dự án là không chỉ cung cấp một giải pháp thực tiễn cho vấn đề bảo mật mật khẩu mà còn là cơ hội để tìm hiểu sâu hơn về cơ chế hoạt động, ưu nhược điểm và cách thức triển khai của các thuật toán mật mã quan trọng, góp phần nâng cao nhận thức và kỹ năng trong lĩnh vực an toàn thông tin.
<h2>🏛️ Kiến trúc Hệ thống và Công nghệ Sử dụng</h2>
Hệ thống được thiết kế theo kiến trúc phân tầng (Multi-tier Architecture), bao gồm các thành phần chính sau:<br>
<strong>1. Tầng Giao diện Người dùng (Frontend):</strong><br>

- <strong>HTML/CSS/JavaScript:</strong> Được sử dụng để xây dựng giao diện web động và thân thiện với người dùng.<br>

<strong>2. Tầng Ứng dụng (Backend - Logic):</strong><br>

- <strong>Python:</strong> Ngôn ngữ lập trình chính của ứng dụng.<br>
- <strong>Flask Framework:</strong> Micro-framework web để xây dựng các API và xử lý logic nghiệp vụ.<br>
- <strong>Flask-Login:</strong> Extension của Flask để quản lý phiên đăng nhập và xác thực người dùng.<br>
- <strong>Flask-SQLAlchemy:</strong> Extension của Flask để tích hợp SQLAlchemy (Object Relational Mapper - ORM), giúp tương tác với cơ sở dữ liệu.<br>
- <strong>PyCryptodome:</strong> Thư viện mật mã chuyên dụng cung cấp các cài đặt cho Triple DES.<br>
- <strong>hashlib (Built-in Python):</strong> Thư viện chuẩn của Python để thực hiện các phép băm SHA-256.<br>

<strong>3. Tầng Cơ sở Dữ liệu (Database):</strong><br>

<strong>Microsoft SQL Server:</strong> Hệ quản trị cơ sở dữ liệu quan hệ được sử dụng để lưu trữ thông tin người dùng và nhật ký hoạt động.<br>
<h2>⚙️ Trình bày Kỹ thuật Chi tiết</h2>
<strong>📂 1. Cấu trúc Thư mục Dự án</strong><br>
Cấu trúc thư mục của dự án được tổ chức một cách rõ ràng để dễ quản lý và mở rộng:
<pre>
Project/
├── __pycache__/                  (Các file cache của Python)
├── routes/                       (Module định tuyến và xử lý yêu cầu HTTP)
│   ├── __pycache__/
│   ├── __init__.py               (Khởi tạo package routes)
│   ├── admin.py                  (Định nghĩa các route và logic cho trang quản trị)
│   ├── auth.py                   (Định nghĩa các route và logic cho xác thực: đăng ký, đăng nhập)
│   └── main.py                   (Định nghĩa các route và logic chung của ứng dụng)
├── templates/                    (Chứa các file HTML giao diện người dùng)
│   ├── admin/                    (Các template dành cho trang quản trị)
│   │   ├── dashboard.html        (Trang tổng quan quản trị)
│   │   ├── login_logs.html       (Trang hiển thị lịch sử đăng nhập)
│   │   ├── reset_password.html   (Trang đặt lại mật khẩu cho tài khoản bị khóa/quên)
│   │   └── users.html            (Trang quản lý danh sách người dùng)
│   ├── 404.html                  (Trang báo lỗi không tìm thấy tài nguyên)
│   ├── change_password.html      (Trang đổi mật khẩu của người dùng)
│   ├── dashboard.html            (Trang tổng quan sau khi người dùng đăng nhập)
│   ├── layout.html               (Template bố cục chung của trang web, chứa header, footer, navigation)
│   ├── login.html                (Trang đăng nhập)
│   └── register.html             (Trang đăng ký tài khoản)
└── utils/                        (Chứa các module tiện ích, thư viện dùng chung)
    ├── __pycache__/
    ├── security.py                 (Chứa các hàm xử lý bảo mật: băm SHA, mã hóa/giải mã Triple DES, sinh Salt)
    ├── app.py                      (File cấu hình và khởi tạo ứng dụng chính)
    ├── config.py                   (Chứa các biến cấu hình hệ thống: chuỗi kết nối DB, khóa bí mật)
    ├── database.py                 (Module quản lý kết nối và thao tác với cơ sở dữ liệu)
    └── models.py                   (Định nghĩa các mô hình dữ liệu, tương ứng với bảng trong DB)
</pre>


<strong>2. 🔑 2. Quản lý Cấu hình (config.py) </strong><br>
File config.py chứa các biến môi trường và cấu hình quan trọng cho ứng dụng:<br>

- <strong>SECRET_KEY:</strong> Khóa bí mật dùng để bảo vệ session của Flask.<br>
- <strong>SQLALCHEMY_DATABASE_URI:</strong> Chuỗi kết nối đến MS SQL Server, sử dụng pyodbc và xác thực Windows (trusted_connection=yes).<br>
- <strong>TRIPLE_DES_KEY:</strong> Khóa 24 byte cho thuật toán Triple DES.<br>
- <strong>Flask-SQLAlchemy:</strong> Extension của Flask để tích hợp SQLAlchemy (Object Relational Mapper - ORM), giúp tương tác với cơ sở dữ liệu.<br>
- <strong>TRIPLE_DES_IV:</strong> Vector Khởi tạo 8 byte cho Triple DES (lưu ý: trong môi trường thực tế, IV cần được tạo ngẫu nhiên cho mỗi lần mã hóa).<br>
- <strong>MAX_FAILED_ATTEMPTS:</strong> Số lần đăng nhập sai tối đa trước khi tài khoản bị khóa.<br>

<strong>📊 3. Định nghĩa Mô hình Dữ liệu (models.py)</strong></br>
File models.py định nghĩa cấu trúc của các bảng trong cơ sở dữ liệu thông qua Flask-SQLAlchemy.</br>

- <strong>User Model:</strong> Ánh xạ tới bảng users, chứa các trường như id, username, salt, encrypted_password, fail_attempts, is_locked, created_at, updated_at.<br>
- salt (String(64)): Lưu salt ngẫu nhiên cho mật khẩu.<br>
- encrypted_password (String(256)): Lưu mật khẩu sau khi băm và mã hóa.<br>
- fail_attempts (Integer): Đếm số lần đăng nhập sai.<br>
- is_locked (Boolean): Trạng thái khóa tài khoản.<br>
- UserMixin: Cung cấp các thuộc tính cần thiết cho Flask-Login.<br>
- <strong>LoginLog Model:</strong> Ánh xạ tới bảng login_logs, ghi lại các sự kiện đăng nhập với các trường id, user_id, username, login_time, status, ip_address<br>
 <strong>🚀 Mô hình CSDL</strong>
 <td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/giaodienAdmin.jpg" alt="màn hình điền thông tin" width="100%"><br>
    </td>
<strong>🔐 4. Các Hàm Bảo mật và Xử lý Mật khẩu (utils/security.py)</strong></br>
File này chứa các hàm cốt lõi để bảo vệ mật khẩu, đảm bảo dữ liệu được xử lý an toàn trước khi lưu trữ.</br>


- generate_salt(length=32): Tạo một chuỗi salt ngẫu nhiên 32 byte (chuyển thành 64 ký tự hex) bằng os.urandom().<br>
- hash_sha256(data: str): Băm dữ liệu đầu vào bằng SHA-256, trả về chuỗi hex 64 ký tự.<br>
- encrypt_3des(data_bytes: bytes): Mã hóa chuỗi byte bằng Triple DES ở chế độ CBC, sử dụng TRIPLE_DES_KEY và TRIPLE_DES_IV. Dữ liệu được pad trước khi mã hóa và kết quả được base64.b64encode để lưu trữ.<br>
- decrypt_3des(encrypted_data_b64: str): Giải mã chuỗi Base64 đã mã hóa bằng 3DES, sau đó unpad để khôi phục dữ liệu gốc.<br>
- process_password_for_storage(username: str, password: str, salt: str): Quy trình chính để chuẩn bị mật khẩu lưu trữ:<br>
hash_sha256(password + salt)

1. hash_sha256(username)

2. Nối hai kết quả và băm lại bằng hash_sha256.

3. Mã hóa kết quả băm cuối cùng bằng encrypt_3des.
- verify_password(username: str, password_input: str, stored_salt: str, stored_encrypted_password: str): Xác minh mật khẩu bằng cách chạy mật khẩu nhập vào qua cùng quy trình process_password_for_storage và so sánh kết quả với mật khẩu đã lưu.
<strong>➡️ 5. Luồng Đăng nhập và Xác thực (routes/auth.py)</strong></br>
Module auth.py xử lý các yêu cầu đăng ký và đăng nhập người dùng.</br>

- Khi đăng ký, mật khẩu người dùng được xử lý bởi process_password_for_storage trước khi lưu.<br>
- Khi đăng nhập, mật khẩu nhập vào được xác minh bằng verify_password.<br>
- Hệ thống kiểm soát số lần đăng nhập thất bại. Nếu vượt quá MAX_FAILED_ATTEMPTS, tài khoản sẽ bị khóa.<br>
- Mọi nỗ lực đăng nhập (thành công hay thất bại) đều được ghi lại vào bảng login_logs.<br>
    </td>
<table align="center">
  <td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/dk.jpg" alt="màn hình điền thông tin" width="100%"><br>
      <strong>Màn hình giao diện Đăng ký</strong>
    </td>
    <td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/login.jpg" alt="Kết quả tính toán" width="100%"><br>
      <strong>Màn hình giao diện Đăng nhập</strong>
    </td>
  </tr>
</table>

  <tr>
    <td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/giaodienAdmin.jpg" alt="màn hình điền thông tin" width="100%"><br>
      <strong>Màn hình giao diện Admin</strong>
    </td>
    <td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/giaodienND.jpg" alt="Kết quả tính toán" width="100%"><br>
      <strong>Màn hình giao diện người dùng</strong>
    </td>
  </tr>
   <td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/Adminql.jpg" alt="màn hình điền thông tin" width="100%"><br>
      <strong>Màn hình Quản lý của Admin</strong>
    </td>
    <td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/LoginLogs.jpg" alt="Kết quả tính toán" width="100%"><br>
      <strong>Màn hình giao diện Login Logs</strong>
    </td>
    </tr>
  <td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/thaypass.jpg" alt="màn hình điền thông tin" width="100%"><br>
      <strong>Màn hình thay đổi Mật khẩu</strong>
    </td>
  


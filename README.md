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

<strong> 🔑 2. Quản lý Cấu hình (config.py) </strong>
File config.py chứa các biến môi trường và cấu hình quan trọng cho ứng dụng:<br>
<strong> SECRET_KEY:</strong> Khóa bí mật dùng để bảo vệ session của Flask..<br>
<strong> SQLALCHEMY_DATABASE_URI:</strong> Chuỗi kết nối đến MS SQL Server, sử dụng pyodbc và xác thực Windows (trusted_connection=yes).<br>
<strong>TRIPLE_DES_KEY:</strong> Khóa 24 byte cho thuật toán Triple DES.<br>
<strong>TRIPLE_DES_IV:</strong> Vector Khởi tạo 8 byte cho Triple DES (lưu ý: trong môi trường thực tế, IV cần được tạo ngẫu nhiên cho mỗi lần mã hóa).<br>
<strong>MAX_FAILED_ATTEMPTS:</strong> Số lần đăng nhập sai tối đa trước khi tài khoản bị khóa.<br>

<strong>📊 3. Định nghĩa Mô hình Dữ liệu (models.py)</strong>
File models.py định nghĩa cấu trúc của các bảng trong cơ sở dữ liệu thông qua Flask-SQLAlchemy.
<strong>User Model:</strong> Ánh xạ tới bảng users, chứa các trường như id, username, salt, encrypted_password, fail_attempts, is_locked, created_at, updated_at.<br>
  
  &nbsp;&nbsp;&bull;salt (String(64)): Lưu salt ngẫu nhiên cho mật khẩu.<br>
  &nbsp;&nbsp;&bull;encrypted_password (String(256)): Lưu mật khẩu sau khi băm và mã hóa.<br>
  &nbsp;&nbsp;&bull; fail_attempts (Integer): Đếm số lần đăng nhập sai.<br>
  &nbsp;&nbsp;&bull;is_locked (Boolean): Trạng thái khóa tài khoản.<br>
  &nbsp;&nbsp;&bull;UserMixin: Cung cấp các thuộc tính cần thiết cho Flask-Login.<br>
  
  <strong>LoginLog <strong>Model:</strong> Ánh xạ tới bảng login_logs, ghi lại các sự kiện đăng nhập với các trường id, user_id, username, login_time, status, ip_address<br>
<table align="center">
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
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/dk.jpg" alt="màn hình điền thông tin" width="100%"><br>
      <strong>Màn hình giao diện Đăng ký</strong>
    </td>
    <td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/login.jpg" alt="Kết quả tính toán" width="100%"><br>
      <strong>Màn hình giao diện Đăng nhập</strong>
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
</table>

  


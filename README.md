<h2 align="center">🛡️ ỨNG DỤNG SHA-256 VÀ TRIPLE DES ĐỂ BẢO VỆ MẬT KHẨU NGƯỜI DÙNG TRONG CƠ SỞ DỮ LIỆU</h2>
<h2>✨ Giới thiệu</h2>
Trong bối cảnh an ninh mạng ngày càng phức tạp, việc bảo vệ mật khẩu người dùng trong cơ sở dữ liệu là một trong những thách thức hàng đầu đối với mọi hệ thống thông tin. Dự án này tập trung vào việc triển khai một giải pháp bảo mật mật khẩu toàn diện, sử dụng kết hợp hai thuật toán mật mã kinh điển và mạnh mẽ:

SHA-256 (Secure Hash Algorithm 256-bit): Để thực hiện chức năng băm mật khẩu, chuyển đổi mật khẩu thành một chuỗi băm cố định, không thể đảo ngược.

Triple DES (3DES - Triple Data Encryption Standard): Để mã hóa lớp cuối cùng của chuỗi băm, bổ sung một lớp bảo vệ khác cho dữ liệu mật khẩu trước khi lưu trữ.

Mục tiêu chính của dự án là đảm bảo rằng mật khẩu người dùng không bao giờ được lưu trữ dưới dạng văn bản thuần, ngay cả khi cơ sở dữ liệu bị xâm nhập. Hệ thống được phát triển trên nền tảng Python và Flask Framework, kết nối với Microsoft SQL Server. Bên cạnh việc tích hợp sâu các thuật toán SHA-256 và Triple DES, dự án còn kết hợp các biện pháp bảo mật thực tiễn khác như sử dụng Salt ngẫu nhiên cho mỗi mật khẩu, kết hợp tên đăng nhập vào quá trình băm để tăng cường tính duy nhất, và triển khai cơ chế tự động khóa tài khoản khi có nhiều lần đăng nhập thất bại, nhằm chống lại các cuộc tấn công vét cạn và tấn công từ điển.

Dự án này không chỉ là một ứng dụng thực tế mà còn là nghiên cứu chuyên sâu về cách các thuật toán mật mã cơ bản hoạt động, ưu nhược điểm của chúng trong bối cảnh bảo mật mật khẩu hiện đại, và phương pháp triển khai chúng một cách an toàn trong một ứng dụng web.
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


<strong>🔑 2. Quản lý Cấu hình (config.py) </strong><br>
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
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/csdl.jpg" alt="csdl" width="100%"><br>
    </td>
<strong>🔐 4. Các Hàm Bảo mật và Xử lý Mật khẩu (utils/security.py)</strong></br>
File này chứa các hàm cốt lõi để bảo vệ mật khẩu, đảm bảo dữ liệu được xử lý an toàn trước khi lưu trữ.</br>


- generate_salt(length=32): Tạo một chuỗi salt ngẫu nhiên 32 byte (chuyển thành 64 ký tự hex) bằng os.urandom().<br>
- hash_sha256(data: str): Băm dữ liệu đầu vào bằng SHA-256, trả về chuỗi hex 64 ký tự.<br>
- encrypt_3des(data_bytes: bytes): Mã hóa chuỗi byte bằng Triple DES ở chế độ CBC, sử dụng TRIPLE_DES_KEY và TRIPLE_DES_IV. Dữ liệu được pad trước khi mã hóa và kết quả được base64.b64encode để lưu trữ.<br>
- decrypt_3des(encrypted_data_b64: str): Giải mã chuỗi Base64 đã mã hóa bằng 3DES, sau đó unpad để khôi phục dữ liệu gốc.<br>
- process_password_for_storage(username: str, password: str, salt: str): Quy trình chính để chuẩn bị mật khẩu lưu trữ:<br>
hash_sha256(password + salt)

<strong>quy trình chính để chuẩn bị mật khẩu trước khi lưu trữ trong cơ sở dữ liệu, kết hợp SHA-256 và Triple DES:</strong><br>

1.<strong> Băm mật khẩu và Salt:</strong> Mật khẩu người dùng được băm cùng với một giá trị salt ngẫu nhiên bằng SHA-256. Điều này giúp ngăn chặn tấn công bảng cầu vồng và đảm bảo cùng một mật khẩu sẽ tạo ra các giá trị băm khác nhau nếu salt khác nhau.<br>

2. <strong>Băm tên người dùng:</strong> Tên đăng nhập cũng được băm bằng SHA-256 để thêm một yếu tố duy nhất khác vào chuỗi bảo mật.

3. <strong>Kết hợp và Băm lại:</strong> Hai kết quả băm từ bước 1 và 2 được nối lại và băm thêm một lần nữa bằng SHA-256. Bước này tăng cường độ phức tạp và làm chậm quá trình băm, tuy nhiên không hiệu quả bằng các hàm băm mật khẩu chuyên dụng (ví dụ: Argon2, bcrypt).

4. <strong>Mã hóa bằng Triple DES:</strong> Chuỗi băm cuối cùng (là kết quả của bước 3) được chuyển đổi thành chuỗi byte và sau đó được mã hóa bằng thuật toán Triple DES. Đây là lớp bảo vệ thứ hai, đảm bảo rằng ngay cả khi kẻ tấn công có được chuỗi băm, họ vẫn cần phá vỡ lớp mã hóa 3DES để có được thông tin băm. Kết quả được base64 mã hóa để lưu trữ dạng chuỗi.

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

<strong>📊 6. Quản lý Tài khoản (User Dashboard & Admin Dashboard)</strong><br>
- <strong>User Dashboard </strong>(routes/main.py): Giao diện cho người dùng thông thường sau khi đăng nhập.</br>
- <strong>Admin Dashboard </strong>(routes/admin.py): Cung cấp các chức năng quản trị viên như quản lý người dùng (xem, khóa/mở khóa), và xem nhật ký đăng nhập.</br>
<h4 align="center"> <strong>Màn hình giao diện Admin</strong></h4>
<td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/giaodienAdmin.jpg" alt="màn hình điền thông tin" width="100%"><br>

<table align="center">
 <td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/Adminql.jpg" alt="màn hình điền thông tin" width="100%"><br>
      <strong>Màn hình Quản lý của Admin</strong>
    </td>
    <td align="center">
      <img src="https://github.com/Thuhuyen8324/Ung-dung-SHA-va-Triple-DES-de-bao-mat-mat-khau-nguoi-dung-trong-co-so-du-lieu/blob/main/Anh/LoginLogs.jpg" alt="Kết quả tính toán" width="100%"><br>
      <strong>Màn hình giao diện Login Logs</strong>
    </td>
  </tr>
</table>
<h2>🚀 Cài đặt và Chạy Dự án</h2>
<strong>1. Khởi tạo Cơ sở Dữ liệu và Tạo tài khoản Admin mặc định:</strong>
Chạy app.py. Lần đầu chạy, nó sẽ tự động kiểm tra và tạo tài khoản admin mặc định với mật khẩu admin@123 nếu chưa tồn tại.
  <code> python app.py</code><br>
<strong>2.Truy cập Ứng dụng:</strong>
Mở trình duyệt web của bạn và truy cập:<code> http://127.0.0.1:5000/</code>

<strong>Tài khoản Admin mặc định:</strong>
- Username: <code>admin</code>
- Password: <code>admin@123</code>
<strong> LƯU Ý QUAN TRỌNG:</strong> Hãy thay đổi mật khẩu mặc định ngay lập tức sau khi đăng nhập lần đầu!
<h2 align="center">📧 Liên hệ</h2>
<h4 align="center">Nếu có bất kỳ câu hỏi hoặc góp ý nào về dự án, vui lòng liên hệ:</h4>
<table align="center">
  <tbody>
    <tr>
      <td>Nguyễn Thu Huyền</td>
      <td>nguyenthuhuyen8324@gmail.com</td>
    </tr>
    <tr>
      <td>Nguyễn Thu Anh</td>
      <td>nguyenthuanh061@gmail.com</td>
    </tr>
  </tbody>
</table>
    
  


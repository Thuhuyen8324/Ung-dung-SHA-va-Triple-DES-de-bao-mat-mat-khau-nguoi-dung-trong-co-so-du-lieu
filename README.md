<h2 align="center">📸 Kết quả hiển thị</h2>
<h2 align=""center">ĐỀ TÀI: Ứng dụng SHA và Triple DES để bảo vệ mật khẩu người dùng trong cơ sở dữ liệu </h2>
<h2>Giới thiệu</h2>
Trong kỷ nguyên số hóa hiện nay, việc bảo vệ dữ liệu cá nhân, đặc biệt là thông tin đăng nhập như mật khẩu, đã trở thành ưu tiên hàng đầu. Các cuộc tấn công mạng nhằm vào mật khẩu đang ngày càng tinh vi, đặt ra thách thức lớn cho các hệ thống phần mềm. Dự án này tập trung vào việc xây dựng một hệ thống xác thực người dùng an toàn, sử dụng các thuật toán mật mã mạnh mẽ là SHA-256 để băm mật khẩu và Triple DES (3DES) để mã hóa lớp cuối cùng, đảm bảo mật khẩu không bao giờ được lưu trữ dưới dạng văn bản thuần trong cơ sở dữ liệu.

Hệ thống được phát triển trên nền tảng Python và Flask Framework, kết nối với MS SQL Server. Ngoài việc áp dụng các thuật toán mật mã, dự án còn tích hợp các tính năng bảo mật thiết yếu như sử dụng Salt ngẫu nhiên cho mỗi mật khẩu, kết hợp tên đăng nhập vào quá trình băm, và cơ chế tự động khóa tài khoản khi có nhiều lần đăng nhập thất bại.

Mục tiêu của dự án là không chỉ cung cấp một giải pháp thực tiễn cho vấn đề bảo mật mật khẩu mà còn là cơ hội để tìm hiểu sâu hơn về cơ chế hoạt động, ưu nhược điểm và cách thức triển khai của các thuật toán mật mã quan trọng, góp phần nâng cao nhận thức và kỹ năng trong lĩnh vực an toàn thông tin.
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

  


document.getElementById("submitButton").addEventListener("click", function () {
  const form = document.getElementById("addServerForm");
  const responseMessage = document.getElementById("responseMessage");

  const ipAddress = document.getElementById("IPaddress").value.trim();
  const username = document.getElementById("username").value.trim();
  const port = document.getElementById("port").value.trim();
  const password = document.getElementById("password").value.trim();

  // Biểu thức chính quy kiểm tra địa chỉ IP
  const ipPattern =
    /^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$/;

  if (!ipPattern.test(ipAddress)) {
    responseMessage.innerHTML = `<p style="color: red;">Địa chỉ IP không hợp lệ! Vui lòng nhập theo định dạng 123.123.123.123</p>`;
    return;
  }

  if (!username) {
    responseMessage.innerHTML = `<p style="color: red;">Vui lòng nhập username!</p>`;
    return;
  }
  if (!port) {
    responseMessage.innerHTML = `<p style="color: red;">Vui lòng nhập cổng kết nối!</p>`;
    return;
  }
  if (!password) {
    responseMessage.innerHTML = `<p style="color: red;">Vui lòng nhập password!</p>`;
    return;
  }

  // Gửi dữ liệu qua AJAX nếu tất cả các trường hợp lệ
  const formData = new FormData(form);

  fetch("/home/addserver", {
    method: "POST",
    body: formData,
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.status === "success") {
        responseMessage.innerHTML = `<p style="color: green;">${data.message}</p>`;
        form.reset();
      } else {
        responseMessage.innerHTML = `<p style="color: red;">${data.message}</p>`;
      }
    })
    .catch((error) => {
      console.error("Error:", error);
      responseMessage.innerHTML = `<p style="color: red;">Đã xảy ra lỗi khi thêm server!</p>`;
    });
});

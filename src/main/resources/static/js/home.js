document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".delete-button").forEach((button) => {
    button.addEventListener("click", async function (e) {
      e.stopPropagation();
      const host = this.getAttribute("data-host");
      if (confirm(`Bạn có chắc chắn muốn xóa máy chủ ${host} không?`)) {
        const response = await fetch("/delete-server", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ host: host }),
        });
        if (response.ok) {
          this.closest(".server").remove();
        } else {
          alert("Xóa thất bại!");
        }
      }
    });
  });
});

document.querySelectorAll(".server").forEach((serverDiv) => {
  serverDiv.addEventListener("click", function (e) {
    if (!e.target.closest(".delete-button")) {
      const host = this.getAttribute("data-host");
      if (host) {
        // Encode giá trị host để tránh lỗi URL
        const encodedHost = encodeURIComponent(host);
        window.location.href = `/server?host=${encodedHost}`;
      } else {
        console.error("Giá trị host không tồn tại!");
      }
    }
  });
});
      // Search: tìm theo nickname hoặc host
const search = document.getElementById("search");
search.addEventListener("input", () => {
  const q = search.value.trim().toLowerCase();
  document.querySelectorAll(".server").forEach((el) => {
    const host = (el.dataset.host || "").toLowerCase();
    const nick = (el.dataset.nickname || "").toLowerCase();
    const label = nick || host;
    // hiển thị nếu query nằm trong nickname hoặc host
    el.style.display = nick.includes(q) || host.includes(q) ? "" : "none";
  });
});

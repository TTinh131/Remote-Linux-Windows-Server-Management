document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".delete-btn").forEach((button) => {
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
          window.location.href = "/home";
        }
      }
    });
  });

  document.querySelector(".update-btn").addEventListener("click", function (e) {
    e.preventDefault();
    const host = this.getAttribute("data-host");
    window.location.href = `/server/update?host=${encodeURIComponent(host)}`;
  });
});

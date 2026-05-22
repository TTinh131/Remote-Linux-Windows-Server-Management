function toggleControlNav(e) {
    e.stopPropagation();
    const nav = document.getElementById("controlNav");
    const toggleBtn = document.querySelector(".control-toggle");

    nav.classList.toggle("active");
    toggleBtn.classList.toggle("active");

    nav.classList.contains("active")
      ? document.addEventListener("click", closeControlNav)
      : document.removeEventListener("click", closeControlNav);
  }

  function closeControlNav(e) {
    if (!e.target.closest(".control-navbar")) {
      toggleControlNav(e);
    }
  }
//xử lí cho nav-server
document.addEventListener('DOMContentLoaded', function () {
    const host = document.getElementById("controlNav").dataset.host;
    document.getElementById('restart').addEventListener('click', function () {
      controllbtn('restart');
    });

    document.getElementById('shutdown').addEventListener('click', function () {
      controllbtn('shutdown');
    });

    function controllbtn(action) {
      fetch(`/controll-btn/${action}?host=${encodeURIComponent(host)}`, {
        method: 'POST'
      })
      .then(res => res.text())
      .then(msg => alert(msg))
      .catch(err => alert('Lỗi: ' + err));
    }
  });

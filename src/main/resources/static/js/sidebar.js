document.addEventListener("DOMContentLoaded", function() {
  collapseSidebar(); 
});

function expandSidebar() {
  document.body.classList.remove("sidebar-collapsed");
}

function collapseSidebar() {
  document.body.classList.add("sidebar-collapsed");
}

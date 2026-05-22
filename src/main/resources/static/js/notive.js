let notifications = document.querySelector('.notifications');

function createToast(type, icon, title, text){
    let newToast = document.createElement('div');
    newToast.innerHTML = `
        <div class="toast ${type}">
            <div class="progress"></div>
            <i class="${icon}"></i>
            <div class="content">
                <div class="title">${title}</div>
                <span>${text}</span>
            </div>
            <i class="fa-solid fa-xmark" onclick="(this.parentElement).remove()"></i>
        </div>`;
    notifications.appendChild(newToast);
    newToast.timeOut = setTimeout(() => newToast.remove(), 5000);
}

// Lắng nghe SSE
const evtSource = new EventSource('/ssh-logs');
evtSource.onmessage = function(event) {
    const msg = event.data;
    if (msg.startsWith("Connected successfully to host:")) {
        createToast(
            'success',
            'fa-solid fa-circle-check',
            'Success',
            msg
        );
    } else if (msg.startsWith("Connect failed for host")) {
        createToast(
            'error',
            'fa-solid fa-circle-exclamation',
            'Error',
            msg
        );
    } else {
        console.log("Unknown message:", msg);
    }
};
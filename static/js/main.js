document.addEventListener("DOMContentLoaded", function() {
    setTimeout(function() {
        let alerts = document.querySelectorAll(".alert");
        alerts.forEach(function(alert) {
            alert.style.transition = "opacity 0.5s ease-out";
            alert.style.opacity = "0";
            setTimeout(() => alert.remove(), 500); // Remove after fade-out
        });
    }, 5000); // 5 seconds delay before removing
});

function setupPasswordToggle(toggleSelector, inputSelector) {
    const toggle = document.querySelector(toggleSelector);
    const input = document.querySelector(inputSelector);

    if (toggle && input) {
        toggle.addEventListener('click', () => {
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);
            
            // If icon is inside the toggle
            if (toggle.firstElementChild) {
                toggle.firstElementChild.classList.toggle('fa-eye-slash');
            } else {
                toggle.classList.toggle('fa-eye-slash');
            }
        });
    }
}

// Works for both login and signup
setupPasswordToggle('#togglePassword', '#password');
setupPasswordToggle('#toggleConfirmPassword', '#confirmpassword');


    // Remove flash messages after 5 seconds
    setTimeout(function () {
        document.querySelectorAll('.flash-message').forEach(function (msg) {
            msg.style.opacity = '0';
            setTimeout(() => msg.remove(), 500); // Wait for fade-out
        });
    }, 5000);

    
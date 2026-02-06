// static/js/auth.js

document.addEventListener('DOMContentLoaded', function() {
    // Login formasi
    const loginForm = document.getElementById('login-form');
    const loginMessage = document.getElementById('login-message');
    
    // Ro'yxatdan o'tish formasi
    const registerForm = document.getElementById('register-form');
    const registerMessage = document.getElementById('register-message');
    
    // Login formasini yuborish
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            // Formani tekshirish
            if (!username || !password) {
                showMessage(loginMessage, 'Foydalanuvchi nomi va parolni kiriting', 'error');
                return;
            }
            
            // So'rovni yuborish
            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    password: password
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Muvaffaqiyatli kirish
                    showMessage(loginMessage, data.message, 'success');
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 1000);
                } else {
                    // Xatolik
                    showMessage(loginMessage, data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error during login:', error);
                showMessage(loginMessage, 'Tizimga kirishda xatolik yuz berdi', 'error');
            });
        });
    }
    
    // Ro'yxatdan o'tish formasini yuborish
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('reg-username').value;
            const email = document.getElementById('reg-email').value;
            const password = document.getElementById('reg-password').value;
            const confirmPassword = document.getElementById('reg-confirm-password').value;
            
            // Formani tekshirish
            if (!username || !email || !password) {
                showMessage(registerMessage, 'Barcha maydonlarni to\'ldiring', 'error');
                return;
            }
            
            // Parolni tasdiqlash
            if (password !== confirmPassword) {
                showMessage(registerMessage, 'Parollar mos kelmaydi', 'error');
                return;
            }
            
            // Email formatini tekshirish
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                showMessage(registerMessage, 'Noto\'g\'ri email format', 'error');
                return;
            }
            
            // So'rovni yuborish
            fetch('/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username,
                    email: email,
                    password: password
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Muvaffaqiyatli ro'yxatdan o'tish
                    showMessage(registerMessage, data.message, 'success');
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 1000);
                } else {
                    // Xatolik
                    showMessage(registerMessage, data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error during registration:', error);
                showMessage(registerMessage, 'Ro\'yxatdan o\'tishda xatolik yuz berdi', 'error');
            });
        });
    }
    
    // Xabarni ko'rsatish
    function showMessage(element, message, type) {
        element.textContent = message;
        element.className = 'auth-message ' + type;
    }
});
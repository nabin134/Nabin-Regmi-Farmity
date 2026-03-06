// API Base URL
const API_BASE_URL = '/api/auth';

// Helper to get CSRF token
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Main initialization
document.addEventListener('DOMContentLoaded', function() {
    // Role selection cards
    const roleCards = document.querySelectorAll('.role-card');
    roleCards.forEach(card => {
        card.addEventListener('click', function() {
            const role = this.getAttribute('data-role');
            window.location.href = `/register/?role=${role}`;
        });
    });

    // Login Form - Skip if login.html has its own handler
    // The login.html template has its own login handler with OTP support
    // So we skip the main.js handler for login page
    if (!window.location.pathname.includes('/login/')) {
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', handleLogin);
        }
    }

    // Register Form
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }

    // Password Toggle
    const togglePassword = document.getElementById('togglePassword');
    if (togglePassword) {
        togglePassword.addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            const icon = this.querySelector('i');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                if (icon) {
                    icon.classList.remove('fa-eye');
                    icon.classList.add('fa-eye-slash');
                } else {
                    this.textContent = '🙈';
                }
            } else {
                passwordInput.type = 'password';
                if (icon) {
                    icon.classList.remove('fa-eye-slash');
                    icon.classList.add('fa-eye');
                } else {
                    this.textContent = '👁️';
                }
            }
        });
    }

    // Password confirmation validation
    const confirmPassword = document.getElementById('confirmPassword');
    const password = document.getElementById('password');
    if (confirmPassword && password) {
        confirmPassword.addEventListener('input', function() {
            if (this.value !== password.value) {
                this.setCustomValidity('Passwords do not match');
            } else {
                this.setCustomValidity('');
            }
        });
    }
});

function showTempMessage(messageDiv, text, type, ms = 3000) {
    if (!messageDiv) return;
    messageDiv.textContent = text || '';
    messageDiv.className = 'message ' + (type || '');
    if (text) {
        messageDiv.className = 'message ' + (type || '');
        // Ensure it behaves like a popoff/toast (auto-hide)
        clearTimeout(messageDiv._hideTimer);
        messageDiv._hideTimer = setTimeout(() => {
            messageDiv.textContent = '';
            messageDiv.className = 'message';
        }, ms);
    }
}

// Logout Function
function logout() {
    localStorage.removeItem('user');
    localStorage.removeItem('isLoggedIn');
    window.location.href = '/'; // Redirect to landing page
}

// Update Header based on Auth Status
function updateAuthHeader() {
    const authButtons = document.getElementById('authButtons');
    if (!authButtons) return;

    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
    const user = JSON.parse(localStorage.getItem('user') || '{}');

    if (isLoggedIn) {
        authButtons.innerHTML = `
            <div class="profile-menu">
                <button class="profile-icon-btn" id="profileDropdownBtn">
                    <i class="fas fa-user"></i>
                </button>
                <div class="dropdown-menu" id="profileDropdown">
                    <div style="padding: 0.8rem 1.5rem; border-bottom: 1px solid #eee;">
                        <strong style="display: block; color: var(--sea-green);">${user.full_name || 'User'}</strong>
                        <span style="font-size: 0.8rem; color: #666;">${user.role || 'Member'}</span>
                    </div>
                    <a href="/dashboard/" class="dropdown-item">
            <i class="fas fa-th-large"></i> Dashboard
          </a>
          <a href="/profile/" class="dropdown-item">
            <i class="fas fa-user-circle"></i> Profile Details
          </a>
          <a href="/kyc/" class="dropdown-item">
            <i class="fas fa-file-alt"></i> Update KYC
          </a>
          <a href="/settings/" class="dropdown-item">
            <i class="fas fa-cog"></i> Settings
          </a>
                    <div class="dropdown-divider"></div>
                    <a href="#" class="dropdown-item" onclick="logout(); return false;" style="color: var(--paarl);">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </a>
                </div>
            </div>
        `;

        // Add event listener for dropdown
        const dropdownBtn = document.getElementById('profileDropdownBtn');
        const dropdownMenu = document.getElementById('profileDropdown');

        if (dropdownBtn && dropdownMenu) {
            dropdownBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                dropdownMenu.classList.toggle('show');
            });

            // Close dropdown when clicking outside
            document.addEventListener('click', function(e) {
                if (!dropdownBtn.contains(e.target) && !dropdownMenu.contains(e.target)) {
                    dropdownMenu.classList.remove('show');
                }
            });
        }
    } else {
        // Ensure default buttons are there if not logged in
        authButtons.innerHTML = `
            <a href="/login/" class="nav-link">Login</a>
            <a href="/role-selection/" class="btn-signup">Sign Up</a>
        `;
    }
}

// Initialize header on load
document.addEventListener('DOMContentLoaded', updateAuthHeader);

// Handle Login
async function handleLogin(e) {
    e.preventDefault();
    
    const form = e.target;
    const emailInput = form.elements.email || form.querySelector('#email');
    const passwordInput = form.elements.password || form.querySelector('#password');
    
    if (!emailInput || !passwordInput) return;
    
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const messageDiv = document.getElementById('message');
    
    if (messageDiv) {
        showTempMessage(messageDiv, '', '');
    }

    try {
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton ? submitButton.textContent : '';
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = 'Signing In...';
        }

        const csrftoken = getCookie('csrftoken');
        const response = await fetch(`${API_BASE_URL}/login/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken,
            },
            body: JSON.stringify({ email, password })
        });

        if (submitButton) {
            submitButton.disabled = false;
            submitButton.textContent = originalButtonText;
        }

        const data = await response.json();

        if (response.ok) {
            if (data.user) {
                localStorage.setItem('user', JSON.stringify(data.user));
                localStorage.setItem('isLoggedIn', 'true');
                
                if (messageDiv) {
                    showTempMessage(messageDiv, 'Login successful! Redirecting...', 'success', 3000);
                }
                
                // Redirect immediately to prevent any issues
                if (data.redirect_url) {
                    // Ensure URL starts with / if it's a relative path
                    let redirectUrl = data.redirect_url;
                    if (!redirectUrl.startsWith('http') && !redirectUrl.startsWith('/')) {
                        redirectUrl = '/' + redirectUrl;
                    }
                    // Remove trailing slash if present (except for root)
                    if (redirectUrl !== '/' && redirectUrl.endsWith('/')) {
                        redirectUrl = redirectUrl.slice(0, -1);
                    }
                    window.location.href = redirectUrl;
                } else {
                    // Fallback to dashboard which will redirect based on role
                    window.location.href = '/dashboard/';
                }
            }
        } else {
            const errorMsg = data.error || data.message || 'Login failed.';
            if (messageDiv) {
                showTempMessage(messageDiv, errorMsg, 'error', 3000);
            } else {
                alert(errorMsg);
            }
        }
    } catch (error) {
        console.error('Login error:', error);
        if (messageDiv) {
            showTempMessage(messageDiv, 'Network error. Please check your connection.', 'error', 3000);
        }
    }
}

// Handle Register
async function handleRegister(e) {
    e.preventDefault();
    
    const form = e.target;
    const emailInput = form.elements.email || form.querySelector('#email');
    const passwordInput = form.elements.password || form.querySelector('#password');
    const confirmPasswordInput = form.elements.confirmPassword || form.querySelector('#confirmPassword');
    const roleSelect = form.elements.userRole || form.querySelector('#userRole');
    const roleHidden = form.querySelector('#role');
    
    if (!emailInput || !passwordInput || !confirmPasswordInput) return;
    
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    
    let role = 'buyer';
    // Priority: hidden input (pre-selected) > select dropdown
    if (roleHidden && roleHidden.value) role = roleHidden.value;
    else if (roleSelect && roleSelect.value) role = roleSelect.value;
    
    const messageDiv = document.getElementById('message');
    if (messageDiv) {
        showTempMessage(messageDiv, '', '');
    }

    if (password !== confirmPassword) {
        if (messageDiv) {
            showTempMessage(messageDiv, 'Passwords do not match!', 'error', 3000);
        }
        return;
    }

    try {
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton ? submitButton.textContent : '';
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = 'Creating Account...';
        }

        const fullNameInput = form.elements.fullName || form.querySelector('#fullName');
        const phoneInput = form.elements.phone || form.querySelector('#phone');
        const locationInput = form.elements.location || form.querySelector('#location');

        const requestData = {
            email,
            password,
            role,
            fullName: fullNameInput ? fullNameInput.value.trim() : '',
            phone: phoneInput ? phoneInput.value.trim() : '',
            location: locationInput ? locationInput.value.trim() : ''
        };
        
        const csrftoken = getCookie('csrftoken');
        const response = await fetch(`${API_BASE_URL}/signup/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrftoken,
            },
            body: JSON.stringify(requestData)
        });

        if (submitButton) {
            submitButton.disabled = false;
            submitButton.textContent = originalButtonText;
        }

        const data = await response.json();

        if (response.ok) {
            // Clear any existing user data (don't auto-login)
            localStorage.removeItem('user');
            localStorage.removeItem('isLoggedIn');

            if (messageDiv) {
                showTempMessage(messageDiv, data.message || 'Account created successfully! Redirecting...', 'success', 3000);
            }
            
            // Redirect (backend decides next step: email verification page)
            setTimeout(() => {
                window.location.href = (data && data.redirect_url) ? data.redirect_url : '/login/?registered=true';
            }, 1500);
        } else {
            let errorMsg = data.error || 'Registration failed.';
            if (data.details) {
                if (data.details.email && Array.isArray(data.details.email)) {
                    errorMsg = data.details.email[0];
                } else if (typeof data.details.email === 'string') {
                    errorMsg = data.details.email;
                } else if (data.details.email) {
                    errorMsg = data.details.email;
                } else if (data.details.phone && Array.isArray(data.details.phone)) {
                    errorMsg = data.details.phone[0];
                } else if (data.details.fullName && Array.isArray(data.details.fullName)) {
                    errorMsg = data.details.fullName[0];
                } else if (data.details.location && Array.isArray(data.details.location)) {
                    errorMsg = data.details.location[0];
                } else if (data.details.password && Array.isArray(data.details.password)) {
                    errorMsg = data.details.password[0];
                } else if (data.details.confirmPassword && Array.isArray(data.details.confirmPassword)) {
                    errorMsg = data.details.confirmPassword[0];
                } else {
                    const firstKey = Object.keys(data.details)[0];
                    const firstVal = firstKey ? data.details[firstKey] : null;
                    if (firstVal && Array.isArray(firstVal)) errorMsg = firstVal[0];
                    else if (firstVal && typeof firstVal === 'string') errorMsg = firstVal;
                    else errorMsg = JSON.stringify(data.details);
                }
            }
            if (messageDiv) {
                showTempMessage(messageDiv, errorMsg, 'error', 3000);
            }
        }
    } catch (error) {
        console.error('Registration error:', error);
        if (messageDiv) {
            showTempMessage(messageDiv, 'Network error. Please check your connection.', 'error', 3000);
        }
    }
}

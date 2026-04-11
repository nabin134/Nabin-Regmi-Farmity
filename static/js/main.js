/* Dark mode: keep html + body in sync with localStorage (whole-site theme). */
(function () {
    function applyFarmityDarkMode() {
        try {
            var on = localStorage.getItem('darkMode') === 'true';
            document.documentElement.classList.toggle('dark-mode', on);
            if (document.body) document.body.classList.toggle('dark-mode', on);
        } catch (e) {}
    }
    applyFarmityDarkMode();
    document.addEventListener('DOMContentLoaded', applyFarmityDarkMode);
})();

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

    // Register Form — register.html binds its own submit handler (fetch + verify-email redirect).
    // Attaching handleRegister here too caused duplicate POSTs (success then duplicate-email error).
    const registerPath = (window.location.pathname || '/').replace(/\/+$/, '') || '/';
    const onRegisterPage = registerPath === '/register';
    if (!onRegisterPage) {
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', handleRegister);
        }
    }

    // Password visibility toggles (login: #togglePassword only; register: #togglePassword + #toggleConfirmPassword)
    function wirePasswordToggle(toggleEl, inputId) {
        if (!toggleEl) return;
        toggleEl.addEventListener('click', function () {
            const passwordInput = document.getElementById(inputId);
            if (!passwordInput) return;
            const icon = this.querySelector('i');
            const show = passwordInput.type === 'password';
            passwordInput.type = show ? 'text' : 'password';
            this.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
            this.setAttribute('title', show ? 'Hide password' : 'Show password');
            if (icon) {
                icon.classList.toggle('fa-eye', !show);
                icon.classList.toggle('fa-eye-slash', show);
            } else {
                this.textContent = show ? '🙈' : '👁️';
            }
        });
    }
    // login.html wires its own password toggle (and adds aria state). Avoid double-binding.
    if (!window.location.pathname.includes('/login/')) {
        wirePasswordToggle(document.getElementById('togglePassword'), 'password');
    }
    wirePasswordToggle(document.getElementById('toggleConfirmPassword'), 'confirmPassword');

    // Login page: clear inline errors when user edits a field
    if (window.location.pathname.includes('/login/')) {
        var loginForm = document.getElementById('loginForm');
        if (loginForm) {
            ['#email', '#password', '#otp'].forEach(function (sel) {
                var el = loginForm.querySelector(sel);
                if (!el) return;
                el.addEventListener('input', function () {
                    clearLoginFieldErrors();
                });
            });
        }
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

// Preserve current page context for POST->redirect flows (admin CRUD/list/detail pages).
document.addEventListener('DOMContentLoaded', function () {
    function ensureHidden(form, name) {
        var input = form.querySelector('input[name="' + name + '"]');
        if (!input) {
            input = document.createElement('input');
            input.type = 'hidden';
            input.name = name;
            form.appendChild(input);
        }
        return input;
    }

    function stampReturnState(form) {
        try {
            ensureHidden(form, '_return_path').value = window.location.pathname || '/';
            var search = window.location.search || '';
            ensureHidden(form, '_return_query').value = search.startsWith('?') ? search.substring(1) : search;
            ensureHidden(form, '_return_scroll').value = String(Math.max(0, Math.round(window.scrollY || 0)));
        } catch (e) {
            // Ignore state-stamp failures; form submission should continue.
        }
    }

    document.querySelectorAll('form').forEach(function (form) {
        var method = (form.getAttribute('method') || 'get').toLowerCase();
        if (method !== 'post') return;
        form.addEventListener('submit', function () { stampReturnState(form); }, true);
    });

    // Restore scroll from query parameter after redirect, then clean URL.
    try {
        var url = new URL(window.location.href);
        var scrollVal = url.searchParams.get('_scroll');
        if (scrollVal !== null && scrollVal !== '') {
            var y = parseInt(scrollVal, 10);
            if (!isNaN(y) && y >= 0) {
                window.requestAnimationFrame(function () {
                    window.scrollTo(0, y);
                });
            }
            url.searchParams.delete('_scroll');
            window.history.replaceState({}, '', url.pathname + (url.search ? url.search : '') + url.hash);
        }
    } catch (e) {
        // Ignore restore failures safely.
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

function ensureLogoutModal() {
    if (document.getElementById('farmityLogoutModalOverlay')) return;

    const style = document.createElement('style');
    style.id = 'farmityLogoutModalStyles';
    style.textContent = `
        :root{
            --logout-modal-bg: rgba(15, 23, 42, 0.55);
            --logout-card: #ffffff;
            --logout-text: #0f172a;
            --logout-muted: #475569;
            --logout-border: rgba(15, 23, 42, 0.10);
            --logout-shadow: 0 25px 60px rgba(2, 6, 23, 0.25);
            --logout-primary: #15803d;
            --logout-primary-dark: #166534;
            --logout-danger: #dc2626;
            --logout-danger-dark: #b91c1c;
        }
        #farmityLogoutModalOverlay{
            position: fixed;
            inset: 0;
            background: var(--logout-modal-bg);
            display: none;
            align-items: center;
            justify-content: center;
            padding: 18px;
            z-index: 9999;
            backdrop-filter: blur(6px);
        }
        #farmityLogoutModalOverlay.show{ display:flex; }
        .farmity-logout-card{
            width: 100%;
            max-width: 460px;
            background: var(--logout-card);
            border: 1px solid var(--logout-border);
            border-radius: 16px;
            box-shadow: var(--logout-shadow);
            overflow: hidden;
            transform: translateY(8px);
            opacity: 0;
            transition: transform 160ms ease, opacity 160ms ease;
            font-family: 'Segoe UI', system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
        }
        #farmityLogoutModalOverlay.show .farmity-logout-card{
            transform: translateY(0);
            opacity: 1;
        }
        .farmity-logout-head{
            display:flex;
            gap: 12px;
            align-items: center;
            padding: 18px 18px 12px;
        }
        .farmity-logout-icon{
            width: 44px;
            height: 44px;
            border-radius: 12px;
            display:flex;
            align-items:center;
            justify-content:center;
            background: rgba(220, 38, 38, 0.10);
            color: var(--logout-danger);
            flex: 0 0 44px;
        }
        .farmity-logout-title{
            margin: 0;
            font-size: 1.05rem;
            font-weight: 800;
            letter-spacing: -0.01em;
            color: var(--logout-text);
        }
        .farmity-logout-body{
            padding: 0 18px 16px;
        }
        .farmity-logout-desc{
            margin: 0;
            color: var(--logout-muted);
            line-height: 1.55;
            font-size: 0.92rem;
        }
        .farmity-logout-actions{
            display:flex;
            gap: 10px;
            justify-content: flex-end;
            padding: 14px 18px 18px;
            background: rgba(2, 6, 23, 0.02);
            border-top: 1px solid rgba(15, 23, 42, 0.06);
        }
        .farmity-logout-btn{
            appearance: none;
            border: 1px solid rgba(15, 23, 42, 0.12);
            background: #fff;
            color: var(--logout-text);
            border-radius: 999px;
            padding: 10px 14px;
            font-weight: 800;
            font-size: 0.92rem;
            cursor: pointer;
            transition: transform 120ms ease, box-shadow 120ms ease, background 120ms ease, border-color 120ms ease;
            user-select: none;
        }
        .farmity-logout-btn:active{ transform: translateY(1px); }
        .farmity-logout-btn.cancel:hover{
            background: rgba(2, 6, 23, 0.04);
        }
        .farmity-logout-btn.confirm{
            border-color: rgba(220, 38, 38, 0.25);
            background: linear-gradient(135deg, var(--logout-danger) 0%, var(--logout-danger-dark) 100%);
            color: #fff;
            box-shadow: 0 10px 22px rgba(220, 38, 38, 0.25);
        }
        .farmity-logout-btn.confirm:hover{
            box-shadow: 0 12px 26px rgba(220, 38, 38, 0.30);
        }
        @media (max-width: 420px){
            .farmity-logout-actions{ flex-direction: column-reverse; }
            .farmity-logout-btn{ width: 100%; justify-content: center; }
        }
    `;
    document.head.appendChild(style);

    const overlay = document.createElement('div');
    overlay.id = 'farmityLogoutModalOverlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-hidden', 'true');
    overlay.innerHTML = `
        <div class="farmity-logout-card" role="document" tabindex="-1">
            <div class="farmity-logout-head">
                <div class="farmity-logout-icon" aria-hidden="true">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
                        <path d="M12 9v4" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>
                        <path d="M12 17h.01" stroke="currentColor" stroke-width="3.2" stroke-linecap="round"/>
                        <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/>
                    </svg>
                </div>
                <div>
                    <h3 class="farmity-logout-title">Are you sure you want to log out?</h3>
                </div>
            </div>
            <div class="farmity-logout-body">
                <p class="farmity-logout-desc">You will need to sign in again to access your dashboard, admin tools, and account features.</p>
            </div>
            <div class="farmity-logout-actions">
                <button type="button" class="farmity-logout-btn cancel" data-action="cancel">Cancel</button>
                <button type="button" class="farmity-logout-btn confirm" data-action="confirm">Confirm Logout</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
}

function showLogoutConfirmation() {
    ensureLogoutModal();
    const overlay = document.getElementById('farmityLogoutModalOverlay');
    const card = overlay ? overlay.querySelector('.farmity-logout-card') : null;
    const btnConfirm = overlay ? overlay.querySelector('[data-action="confirm"]') : null;
    const btnCancel = overlay ? overlay.querySelector('[data-action="cancel"]') : null;

    if (!overlay || !card || !btnConfirm || !btnCancel) {
        return Promise.resolve(window.confirm('Are you sure you want to log out?'));
    }

    return new Promise((resolve) => {
        let done = false;
        const finish = (val) => {
            if (done) return;
            done = true;
            overlay.classList.remove('show');
            overlay.setAttribute('aria-hidden', 'true');
            document.removeEventListener('keydown', onKeyDown, true);
            overlay.removeEventListener('click', onOverlayClick, true);
            btnConfirm.removeEventListener('click', onConfirm, true);
            btnCancel.removeEventListener('click', onCancel, true);
            resolve(val);
        };

        const onConfirm = (e) => { e.preventDefault(); finish(true); };
        const onCancel = (e) => { e.preventDefault(); finish(false); };
        const onOverlayClick = (e) => {
            // Click outside the card = cancel
            if (e.target === overlay) finish(false);
        };
        const onKeyDown = (e) => {
            if (e.key === 'Escape') finish(false);
            if (e.key === 'Enter') finish(true);
        };

        overlay.addEventListener('click', onOverlayClick, true);
        btnConfirm.addEventListener('click', onConfirm, true);
        btnCancel.addEventListener('click', onCancel, true);
        document.addEventListener('keydown', onKeyDown, true);

        overlay.classList.add('show');
        overlay.setAttribute('aria-hidden', 'false');
        setTimeout(() => card.focus(), 0);
    });
}

function showGenericConfirmationFromForm(form) {
    const message = (form.getAttribute('data-farmity-confirm-message') || '').trim() || 'Are you sure you want to proceed?';
    const type = (form.getAttribute('data-farmity-confirm-type') || '').trim() || 'warning';
    const title = (form.getAttribute('data-farmity-confirm-title') || '').trim() || 'Please Confirm';
    const confirmText = (form.getAttribute('data-farmity-confirm-button') || '').trim() || 'Yes, Continue';
    const cancelText = (form.getAttribute('data-farmity-cancel-button') || '').trim() || 'Cancel';

    if (typeof showConfirmation === 'function') {
        return showConfirmation({
            title: title,
            message: message,
            type: type,
            confirmText: confirmText,
            cancelText: cancelText
        });
    }
    return Promise.resolve(window.confirm(message));
}

// Logout Function
async function logout() {
    const ok = await showLogoutConfirmation();
    if (!ok) return;
    localStorage.removeItem('user');
    localStorage.removeItem('isLoggedIn');
    // Use backend logout so Django session is cleared too.
    window.location.href = '/logout/';
}

// Global logout safeguard: works for user + admin logout links/forms.
document.addEventListener('click', async function(e) {
    const link = e.target && e.target.closest ? e.target.closest('a') : null;
    if (!link) return;
    const href = (link.getAttribute('href') || '').trim();
    if (!href) return;

    // Match Django logout URL regardless of absolute/relative form.
    const isLogoutLink = href === '/logout/' || href === 'logout/' || href.endsWith('/logout/');
    if (!isLogoutLink) return;

    e.preventDefault();
    e.stopPropagation();

    const ok = await showLogoutConfirmation();
    if (!ok) return;
    localStorage.removeItem('user');
    localStorage.removeItem('isLoggedIn');
    window.location.href = href;
}, true);

document.addEventListener('submit', async function(e) {
    const form = e.target;
    if (!form || !form.getAttribute) return;

    // Confirm non-AJAX forms that opt in via data attributes.
    const useFormConfirm = form.getAttribute('data-farmity-confirm') === '1';
    const isAjaxForm = form.getAttribute('data-farmity-ajax') === '1';
    if (useFormConfirm && !isAjaxForm) {
        e.preventDefault();
        e.stopPropagation();
        const ok = await showGenericConfirmationFromForm(form);
        if (!ok) return;
        form.submit();
        return;
    }

    const action = (form.getAttribute('action') || '').trim();
    if (!action) return;
    const isLogoutForm = action === '/logout/' || action === 'logout/' || action.endsWith('/logout/');
    if (!isLogoutForm) return;

    e.preventDefault();
    e.stopPropagation();

    const ok = await showLogoutConfirmation();
    if (!ok) return;
    localStorage.removeItem('user');
    localStorage.removeItem('isLoggedIn');
    form.submit();
}, true);

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

// ----- Signup page: inline field errors (below each input) -----
function firstSignupErrorDetail(val) {
    if (val == null || val === '') return '';
    if (typeof val === 'string') return val;
    if (Array.isArray(val)) {
        const first = val[0];
        if (first && typeof first === 'object') {
            if (typeof first.string === 'string') return first.string;
            if (typeof first.message === 'string') return first.message;
        }
        return String(first);
    }
    if (typeof val === 'object' && val.string) return val.string;
    return String(val);
}

function clearSignupFieldErrors(form) {
    if (!form) return;
    form.querySelectorAll('.register-field-error').forEach(function (el) {
        el.textContent = '';
        el.classList.remove('show');
    });
    form.querySelectorAll('.field-invalid').forEach(function (el) {
        el.classList.remove('field-invalid');
    });
    var phoneWrap = form.querySelector('.phone-wrapper');
    if (phoneWrap) phoneWrap.classList.remove('has-field-error');
    var termsWrap = form.querySelector('#termsCheckboxWrapper');
    if (termsWrap) termsWrap.classList.remove('field-invalid-terms');
    var genderGrp = form.querySelector('#genderGroup');
    if (genderGrp) genderGrp.classList.remove('field-invalid-gender');
    const msg = document.getElementById('message');
    if (msg) {
        msg.textContent = '';
        msg.className = 'message';
    }
}

function setSignupFieldError(form, apiKey, message) {
    if (!form || !message) return;
    var idSuffix = 'general';
    if (apiKey && apiKey !== 'non_field_errors') {
        idSuffix = apiKey === 'role' ? 'role' : apiKey;
    }
    var errEl = form.querySelector('#registerFieldError-' + idSuffix) || form.querySelector('#registerFieldError-general');
    if (errEl) {
        errEl.textContent = message;
        errEl.classList.add('show');
    }
    if (apiKey === 'non_field_errors' || !apiKey) return;
    var inputSel = {
        fullName: '#fullName',
        email: '#email',
        phone: '#phone',
        location: '#location',
        role: '#userRole',
        password: '#password',
        confirmPassword: '#confirmPassword',
    };
    if (apiKey === 'terms') {
        var tw = form.querySelector('#termsCheckboxWrapper');
        if (tw) tw.classList.add('field-invalid-terms');
        return;
    }
    if (apiKey === 'gender') {
        var gg = form.querySelector('#genderGroup');
        if (gg) gg.classList.add('field-invalid-gender');
        return;
    }
    var sel = inputSel[apiKey];
    if (sel) {
        var inp = form.querySelector(sel);
        if (inp) inp.classList.add('field-invalid');
    }
    if (apiKey === 'phone') {
        var pw = form.querySelector('.phone-wrapper');
        if (pw) pw.classList.add('has-field-error');
    }
}

function applySignupApiErrors(form, details) {
    if (!details || typeof details !== 'object') return;
    const known = ['fullName', 'email', 'phone', 'location', 'gender', 'role', 'password', 'confirmPassword', 'terms', 'non_field_errors'];
    Object.keys(details).forEach(function (key) {
        const msg = firstSignupErrorDetail(details[key]);
        if (!msg) return;
        if (known.indexOf(key) !== -1) {
            setSignupFieldError(form, key === 'role' ? 'role' : key, msg);
        } else {
            setSignupFieldError(form, 'non_field_errors', msg);
        }
    });
}

/** Login page (`login.html`): inline errors below fields, same pattern as signup. */
function clearLoginFieldErrors() {
    var form = document.getElementById('loginForm');
    if (!form) return;
    form.querySelectorAll('.login-field-error').forEach(function (el) {
        el.textContent = '';
        el.classList.remove('show');
    });
    form.querySelectorAll('#loginStep .form-control.field-invalid, #otpStep .form-control.field-invalid').forEach(function (el) {
        el.classList.remove('field-invalid');
    });
}

function setLoginFieldError(field, message) {
    var form = document.getElementById('loginForm');
    if (!form || !message) return;
    var fid = field && field !== 'general' ? field : 'general';
    var errEl = form.querySelector('#loginFieldError-' + fid) || form.querySelector('#loginFieldError-general');
    if (errEl) {
        errEl.textContent = message;
        errEl.classList.add('show');
    }
    if (field === 'email') {
        var em = form.querySelector('#email');
        if (em) em.classList.add('field-invalid');
    } else if (field === 'password') {
        var pw = form.querySelector('#password');
        if (pw) pw.classList.add('field-invalid');
    } else if (field === 'otp') {
        var ot = form.querySelector('#otp');
        if (ot) ot.classList.add('field-invalid');
    }
}

/** Signup page only: top banner for success / general errors (all driven by frontend). Stays visible at least 5s when timed. */
function showRegisterBanner(text, type, ms) {
    const el = document.getElementById('message');
    if (!el) return;
    clearTimeout(el._registerBannerTimer);
    if (!text) {
        el.textContent = '';
        el.className = 'message';
        return;
    }
    el.textContent = text;
    el.className = 'message ' + (type === 'success' ? 'success' : 'error');
    const hideMs = ms == null ? 5000 : Math.max(5000, ms);
    el._registerBannerTimer = setTimeout(function () {
        el.textContent = '';
        el.className = 'message';
    }, hideMs);
}

function cleanRegisterUrlQuery(paramName) {
    try {
        const u = new URL(window.location.href);
        u.searchParams.delete(paramName);
        const qs = u.searchParams.toString();
        window.history.replaceState({}, '', u.pathname + (qs ? '?' + qs : '') + u.hash);
    } catch (e) { /* ignore */ }
}

function initRegisterPageMessages() {
    const params = new URLSearchParams(window.location.search || '');
    const err = params.get('error');
    if (err === 'email_exists') {
        showRegisterBanner(
            'This email is already registered. Please sign in instead, or use a different email to create a new account.',
            'error',
            5000
        );
        cleanRegisterUrlQuery('error');
    }
}

/** Client-side checks aligned with SignupSerializer (length, phone digits, password rules). */
function validateSignupFormFrontend(form) {
    const emailInput = form.querySelector('#email');
    const fullNameInput = form.querySelector('#fullName');
    const locationInput = form.querySelector('#location');
    const phoneInput = form.querySelector('#phone');
    const passwordInput = form.querySelector('#password');
    const confirmPasswordInput = form.querySelector('#confirmPassword');
    const roleSelect = form.querySelector('#userRole');
    const roleHidden = form.querySelector('#role');
    const termsInput = form.querySelector('#terms');

    const email = emailInput ? emailInput.value.trim() : '';
    const fullName = fullNameInput ? fullNameInput.value.trim() : '';
    const location = locationInput ? locationInput.value.trim() : '';
    const phoneRaw = phoneInput ? phoneInput.value.trim() : '';
    const digits = phoneRaw.replace(/\D/g, '');
    const password = passwordInput ? passwordInput.value : '';
    const confirmPassword = confirmPasswordInput ? confirmPasswordInput.value : '';

    let role = '';
    if (roleHidden && roleHidden.value) role = String(roleHidden.value).trim();
    else if (roleSelect && roleSelect.value) role = String(roleSelect.value).trim();
    if (role === 'None' || role === 'null' || role === 'undefined') role = '';

    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

    var genderEl = form.querySelector('input[name="gender"]:checked');
    /* Role may be pre-selected from the role page; if nothing else was filled in, one clear message is enough. */
    var hasAnyUserInput = !!(
        email ||
        fullName ||
        location ||
        digits.length ||
        genderEl ||
        password ||
        confirmPassword ||
        (termsInput && termsInput.checked)
    );
    if (!hasAnyUserInput) {
        setSignupFieldError(
            form,
            'non_field_errors',
            'Please fill out all required fields before continuing.'
        );
        return false;
    }

    let ok = true;

    if (!email) {
        setSignupFieldError(form, 'email', 'Email address is required.');
        ok = false;
    } else if (!emailOk) {
        setSignupFieldError(form, 'email', 'Enter a valid email address.');
        ok = false;
    }

    if (!role) {
        setSignupFieldError(form, 'role', 'Please select your role.');
        ok = false;
    }
    if (!fullName) {
        setSignupFieldError(form, 'fullName', 'Full name is required.');
        ok = false;
    } else if (fullName.length < 2) {
        setSignupFieldError(form, 'fullName', 'Full name must be at least 2 characters.');
        ok = false;
    }
    if (!location) {
        setSignupFieldError(form, 'location', 'Location is required.');
        ok = false;
    } else if (location.length < 2) {
        setSignupFieldError(form, 'location', 'Location must be at least 2 characters.');
        ok = false;
    }

    if (!genderEl) {
        setSignupFieldError(form, 'gender', 'Gender is required.');
        ok = false;
    }

    if (!digits.length) {
        setSignupFieldError(form, 'phone', 'Phone number is required.');
        ok = false;
    } else if (digits.length !== 10) {
        setSignupFieldError(form, 'phone', 'Phone number must be exactly 10 digits.');
        ok = false;
    }

    if (!password) {
        setSignupFieldError(form, 'password', 'Password is required.');
        ok = false;
    } else if (password.length < 8) {
        setSignupFieldError(form, 'password', 'Password must be at least 8 characters long.');
        ok = false;
    } else if (!/[A-Z]/.test(password)) {
        setSignupFieldError(form, 'password', 'Password must contain at least 1 uppercase letter.');
        ok = false;
    } else if (!/[a-z]/.test(password)) {
        setSignupFieldError(form, 'password', 'Password must contain at least 1 lowercase letter.');
        ok = false;
    } else if (!/\d/.test(password)) {
        setSignupFieldError(form, 'password', 'Password must contain at least 1 number.');
        ok = false;
    } else if (!/[^A-Za-z0-9]/.test(password)) {
        setSignupFieldError(form, 'password', 'Password must contain at least 1 special character.');
        ok = false;
    }

    if (!confirmPassword) {
        setSignupFieldError(form, 'confirmPassword', 'Confirm password is required.');
        ok = false;
    } else if (password !== confirmPassword) {
        setSignupFieldError(form, 'confirmPassword', 'Passwords do not match.');
        if (passwordInput) passwordInput.classList.add('field-invalid');
        if (confirmPasswordInput) confirmPasswordInput.classList.add('field-invalid');
        ok = false;
    }

    if (!termsInput || !termsInput.checked) {
        setSignupFieldError(form, 'terms', 'You must agree to the Terms of Service and Privacy Policy.');
        ok = false;
    }

    return ok;
}

document.addEventListener('DOMContentLoaded', function () {
    var reg = document.getElementById('registerForm');
    if (!reg) return;
    initRegisterPageMessages();
    function clearSignupFieldForInput(inp) {
        var id = inp.id;
        var name = inp.name || '';
        var suffix = null;
        if (id === 'fullName' || name === 'fullName') suffix = 'fullName';
        else if (id === 'email' || name === 'email') suffix = 'email';
        else if (id === 'phone' || name === 'phone') suffix = 'phone';
        else if (id === 'location' || name === 'location') suffix = 'location';
        else if (id === 'userRole' || name === 'userRole') suffix = 'role';
        else if (id === 'password' || name === 'password') suffix = 'password';
        else if (id === 'confirmPassword' || name === 'confirmPassword') suffix = 'confirmPassword';
        else if (id === 'terms' || name === 'terms') suffix = 'terms';
        else if (name === 'gender') suffix = 'gender';
        else if (id === 'countryCode' || name === 'countryCode') suffix = 'phone';
        if (suffix) {
            var err = reg.querySelector('#registerFieldError-' + suffix);
            if (err) {
                err.textContent = '';
                err.classList.remove('show');
            }
        }
        inp.classList.remove('field-invalid');
        if (suffix === 'phone') {
            var pw = reg.querySelector('.phone-wrapper');
            if (pw) pw.classList.remove('has-field-error');
        }
        if (suffix === 'terms') {
            var tw = reg.querySelector('#termsCheckboxWrapper');
            if (tw) tw.classList.remove('field-invalid-terms');
        }
        if (suffix === 'gender') {
            var ggrp = reg.querySelector('#genderGroup');
            if (ggrp) ggrp.classList.remove('field-invalid-gender');
        }
        var g = reg.querySelector('#registerFieldError-general');
        if (g) {
            g.textContent = '';
            g.classList.remove('show');
        }
    }
    reg.querySelectorAll('input, select').forEach(function (inp) {
        ['input', 'change'].forEach(function (ev) {
            inp.addEventListener(ev, function () {
                clearSignupFieldForInput(inp);
            });
        });
    });
    reg.querySelectorAll('input[name="gender"]').forEach(function (radio) {
        radio.addEventListener('change', function () {
            var err = reg.querySelector('#registerFieldError-gender');
            if (err) {
                err.textContent = '';
                err.classList.remove('show');
            }
            var ggrp = reg.querySelector('#genderGroup');
            if (ggrp) ggrp.classList.remove('field-invalid-gender');
            var gen = reg.querySelector('#registerFieldError-general');
            if (gen) {
                gen.textContent = '';
                gen.classList.remove('show');
            }
        });
    });
    var termsCb = reg.querySelector('#terms');
    if (termsCb) {
        termsCb.addEventListener('change', function () {
            var err = reg.querySelector('#registerFieldError-terms');
            if (err) {
                err.textContent = '';
                err.classList.remove('show');
            }
            var tw = reg.querySelector('#termsCheckboxWrapper');
            if (tw) tw.classList.remove('field-invalid-terms');
        });
    }
});

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
    
    clearSignupFieldErrors(form);

    if (!validateSignupFormFrontend(form)) {
        return;
    }

    // Enforce allowed domains (backend also enforces).
    const emailParts = (email || '').toLowerCase().split('@');
    const domain = emailParts.length === 2 ? emailParts[1] : '';
    if (domain !== 'gmail.com' && domain !== 'yahoo.com') {
        setSignupFieldError(form, 'email', 'Only Gmail.com or Yahoo.com email addresses are allowed.');
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

        var genderRadio = form.querySelector('input[name="gender"]:checked');
        const requestData = {
            email,
            password,
            confirmPassword,
            role,
            fullName: fullNameInput ? fullNameInput.value.trim() : '',
            phone: phoneInput ? phoneInput.value.trim() : '',
            location: locationInput ? locationInput.value.trim() : '',
            gender: genderRadio ? genderRadio.value : '',
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

        let data = {};
        try {
            data = await response.json();
        } catch (parseErr) {
            data = {};
        }

        if (response.ok) {
            // Clear any existing user data (don't auto-login)
            localStorage.removeItem('user');
            localStorage.removeItem('isLoggedIn');

            showRegisterBanner(
                data.message || 'Account created successfully! Redirecting…',
                'success',
                5000
            );

            // Redirect after banner has time to show (at least 5s)
            setTimeout(() => {
                window.location.href = (data && data.redirect_url) ? data.redirect_url : '/login/?registered=true';
            }, 5200);
        } else {
            if (data.details) {
                applySignupApiErrors(form, data.details);
            }
            var detailMsg = data.detail != null ? firstSignupErrorDetail(data.detail) : '';
            if (detailMsg && !form.querySelector('.register-field-error.show')) {
                setSignupFieldError(form, 'non_field_errors', detailMsg);
            } else if (!form.querySelector('.register-field-error.show') && data.error) {
                setSignupFieldError(form, 'non_field_errors', data.error);
            }
        }
    } catch (error) {
        console.error('Registration error:', error);
        setSignupFieldError(form, 'non_field_errors', 'Network error. Please check your connection.');
    }
}

// ======================
// REUSABLE VALIDATION UTILITIES
// ======================

/**
 * Universal Field Validation Utility
 * Provides consistent validation across all forms in the system
 */
window.FormValidator = {
    // Email validation regex
    emailRegex: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    
    // Phone validation regex (10 digits)
    phoneRegex: /^\d{10}$/,
    
    // Password requirements
    passwordRequirements: {
        minLength: 8,
        requireUppercase: true,
        requireLowercase: true,
        requireNumber: true,
        requireSpecial: true
    },

    /**
     * Show inline field error
     * @param {HTMLElement} field - The input field
     * @param {string} message - Error message to display
     */
    showFieldError: function(field, message) {
        if (!field) return;
        
        // Remove existing error
        this.hideFieldError(field);
        
        // Add error styling
        field.classList.add('field-invalid');
        
        const wrapper = field.closest('.input-wrapper');
        const mountParent = wrapper ? wrapper.parentNode : field.parentNode;
        const insertAfter = wrapper || field;
        let key = (field.id || field.name || '').trim();
        if (!key) {
            if (!field.dataset.farmityErrorKey) {
                field.dataset.farmityErrorKey = 'farmity-fe-' + String(Math.random()).slice(2);
            }
            key = field.dataset.farmityErrorKey;
        }

        // Old behavior appended inside .input-wrapper; global CSS uses flex row, so errors appeared beside the input.
        if (wrapper) {
            wrapper.querySelectorAll(':scope > .field-error').forEach(function (el) {
                el.remove();
            });
        }

        let errorElement = mountParent.querySelector('.field-error[data-farmity-for="' + key.replace(/"/g, '\\"') + '"]');
        if (!errorElement) {
            errorElement = document.createElement('div');
            errorElement.className = 'field-error';
            errorElement.setAttribute('data-farmity-for', key);
            errorElement.style.cssText = 'color: #dc3545; font-size: 0.85rem; margin-top: 0.5rem; font-weight: 500; display: block; width: 100%; box-sizing: border-box;';
            insertAfter.insertAdjacentElement('afterend', errorElement);
        }
        
        errorElement.textContent = message;
        errorElement.style.display = 'block';
        
        // Focus the field
        field.focus();
    },

    /**
     * Hide field error
     * @param {HTMLElement} field - The input field
     */
    hideFieldError: function(field) {
        if (!field) return;
        
        field.classList.remove('field-invalid');
        
        let key = (field.id || field.name || '').trim();
        if (!key && field.dataset.farmityErrorKey) {
            key = field.dataset.farmityErrorKey;
        }
        const wrapper = field.closest('.input-wrapper');
        const mountParent = wrapper ? wrapper.parentNode : field.parentNode;
        let errorElement = key && mountParent
            ? mountParent.querySelector('.field-error[data-farmity-for="' + key.replace(/"/g, '\\"') + '"]')
            : null;
        if (!errorElement && wrapper) {
            errorElement = wrapper.querySelector(':scope > .field-error');
        }
        if (!errorElement) {
            errorElement = field.parentNode.querySelector('.field-error');
        }
        if (errorElement) {
            errorElement.style.display = 'none';
        }
    },

    /**
     * Validate email field
     * @param {HTMLElement} field - Email input field
     * @param {boolean} required - Whether field is required
     * @returns {boolean} - True if valid
     */
    validateEmail: function(field, required = true) {
        const value = field.value.trim();
        
        if (required && !value) {
            this.showFieldError(field, 'Email is required.');
            return false;
        }
        
        if (value && !this.emailRegex.test(value)) {
            this.showFieldError(field, 'Please enter a valid email address (e.g., user@example.com).');
            return false;
        }
        
        this.hideFieldError(field);
        return true;
    },

    /**
     * Validate required field
     * @param {HTMLElement} field - Input field
     * @param {string} fieldName - Name of the field for error message
     * @returns {boolean} - True if valid
     */
    validateRequired: function(field, fieldName) {
        const value = field.value.trim();
        
        if (!value) {
            this.showFieldError(field, `${fieldName} is required.`);
            return false;
        }
        
        this.hideFieldError(field);
        return true;
    },

    /**
     * Validate password strength
     * @param {HTMLElement} field - Password input field
     * @param {HTMLElement} confirmField - Confirm password field (optional)
     * @returns {boolean} - True if valid
     */
    validatePassword: function(field, confirmField = null) {
        const password = field.value;
        
        if (!password) {
            this.showFieldError(field, 'Password is required.');
            return false;
        }
        
        if (password.length < this.passwordRequirements.minLength) {
            this.showFieldError(field, `Password must be at least ${this.passwordRequirements.minLength} characters long.`);
            return false;
        }
        
        if (this.passwordRequirements.requireUppercase && !/[A-Z]/.test(password)) {
            this.showFieldError(field, 'Password must contain at least 1 uppercase letter.');
            return false;
        }
        
        if (this.passwordRequirements.requireLowercase && !/[a-z]/.test(password)) {
            this.showFieldError(field, 'Password must contain at least 1 lowercase letter.');
            return false;
        }
        
        if (this.passwordRequirements.requireNumber && !/\d/.test(password)) {
            this.showFieldError(field, 'Password must contain at least 1 number.');
            return false;
        }
        
        if (this.passwordRequirements.requireSpecial && !/[^A-Za-z0-9]/.test(password)) {
            this.showFieldError(field, 'Password must contain at least 1 special character.');
            return false;
        }
        
        // Check password confirmation
        if (confirmField && confirmField.value) {
            if (password !== confirmField.value) {
                this.showFieldError(confirmField, 'Passwords do not match.');
                return false;
            } else {
                this.hideFieldError(confirmField);
            }
        }
        
        this.hideFieldError(field);
        return true;
    },

    /**
     * Validate phone number (10 digits)
     * @param {HTMLElement} field - Phone input field
     * @param {boolean} required - Whether field is required
     * @returns {boolean} - True if valid
     */
    validatePhone: function(field, required = true) {
        const value = field.value.replace(/\D/g, ''); // Remove non-digits
        
        if (required && !value) {
            this.showFieldError(field, 'Phone number is required.');
            return false;
        }
        
        if (value && value.length !== 10) {
            this.showFieldError(field, 'Phone number must be exactly 10 digits.');
            return false;
        }
        
        this.hideFieldError(field);
        return true;
    },

    /**
     * Add real-time validation to field
     * @param {HTMLElement} field - Input field
     * @param {string} type - Validation type (email, required, password, phone)
     * @param {Object} options - Additional options
     */
    addRealtimeValidation: function(field, type, options = {}) {
        if (!field) return;
        
        const validator = this;
        
        // Clear error on input
        field.addEventListener('input', function() {
            switch (type) {
                case 'email':
                    validator.validateEmail(field, options.required);
                    break;
                case 'required':
                    validator.validateRequired(field, options.fieldName || 'Field');
                    break;
                case 'password':
                    validator.validatePassword(field, options.confirmField);
                    break;
                case 'phone':
                    validator.validatePhone(field, options.required);
                    break;
            }
        });
        
        // Clear error on focus
        field.addEventListener('focus', function() {
            validator.hideFieldError(field);
        });
    },

    /**
     * Validate entire form
     * @param {HTMLElement} form - Form element
     * @param {Object} rules - Validation rules
     * @returns {boolean} - True if form is valid
     */
    validateForm: function(form, rules) {
        if (!form || !rules) return true;
        
        let isValid = true;
        
        Object.keys(rules).forEach(function(fieldName) {
            const field = form.querySelector(`[name="${fieldName}"], #${fieldName}`);
            const rule = rules[fieldName];
            
            if (!field) return;
            
            switch (rule.type) {
                case 'email':
                    if (!this.validateEmail(field, rule.required)) isValid = false;
                    break;
                case 'required':
                    if (!this.validateRequired(field, rule.fieldName || fieldName)) isValid = false;
                    break;
                case 'password':
                    const confirmField = rule.confirmField ? form.querySelector(`[name="${rule.confirmField}"], #${rule.confirmField}`) : null;
                    if (!this.validatePassword(field, confirmField)) isValid = false;
                    break;
                case 'phone':
                    if (!this.validatePhone(field, rule.required)) isValid = false;
                    break;
            }
        }.bind(this));
        
        return isValid;
    }
};

function farmityShouldSkipGlobalFieldValidation(field) {
    if (!field || !field.closest) return false;
    /* Login/register ship their own inline errors; binding both yields duplicate messages. */
    try {
        var path = (window.location.pathname || '').replace(/\/+$/, '') || '/';
        if (path.endsWith('/login')) {
            return true;
        }
    } catch (e) { /* ignore */ }
    return !!(field.closest('#loginForm') || field.closest('#registerForm'));
}

// Auto-initialize common validation patterns
document.addEventListener('DOMContentLoaded', function() {
    // Add email validation to all email fields
    document.querySelectorAll('input[type="email"]').forEach(function(field) {
        if (farmityShouldSkipGlobalFieldValidation(field)) return;
        window.FormValidator.addRealtimeValidation(field, 'email', { required: field.hasAttribute('required') });
    });
    
    // Add required validation to all required fields
    document.querySelectorAll('input[required], select[required], textarea[required]').forEach(function(field) {
        if (farmityShouldSkipGlobalFieldValidation(field)) return;
        if (field.type !== 'email') {
            window.FormValidator.addRealtimeValidation(field, 'required', { 
                fieldName: field.getAttribute('data-field-name') || field.name || 'Field' 
            });
        }
    });
    
    // Add password validation to password fields
    document.querySelectorAll('input[type="password"]').forEach(function(field) {
        if (farmityShouldSkipGlobalFieldValidation(field)) return;
        const confirmField = field.form.querySelector('input[type="password"][name*="confirm"], input[type="password"][id*="confirm"]');
        window.FormValidator.addRealtimeValidation(field, 'password', { confirmField: confirmField });
    });
    
    // Add phone validation to phone fields
    document.querySelectorAll('input[type="tel"], input[name*="phone"], input[id*="phone"]').forEach(function(field) {
        if (farmityShouldSkipGlobalFieldValidation(field)) return;
        window.FormValidator.addRealtimeValidation(field, 'phone', { required: field.hasAttribute('required') });
    });
});

// ======================
// UNIVERSAL SUCCESS MESSAGE UTILITIES
// ======================

/**
 * Universal Success Message Utility
 * Provides consistent success message display across all forms in the system
 */
window.SuccessMessage = {
    /**
     * Show success message using the admin messaging system
     * @param {string} message - Success message to display
     * @param {number} duration - Auto-dismiss duration in milliseconds (default: 5000)
     */
    show: function(message, duration = 5000) {
        console.log('Showing success message:', message);
        
        // Try multiple selectors to find the container
        let messagesContainer = document.querySelector('.dashboard-content') ||
                              document.querySelector('main') ||
                              document.querySelector('body') ||
                              document.querySelector('.content-wrapper');
        
        if (!messagesContainer) {
            console.warn('Could not find messages container');
            // Fallback to alert if no container found
            alert(message);
            return;
        }
        
        // Check if messages wrapper already exists
        let messagesWrapper = messagesContainer.querySelector('.admin-messages-wrap');
        if (!messagesWrapper) {
            // Insert messages wrapper at the top of the container
            const existingMessages = messagesContainer.querySelector('.admin-messages');
            if (existingMessages) {
                messagesWrapper = existingMessages;
            } else {
                messagesWrapper = document.createElement('div');
                messagesWrapper.className = 'admin-messages-wrap messages-auto-dismiss';
                messagesWrapper.setAttribute('data-dismiss-ms', duration.toString());
                messagesWrapper.setAttribute('aria-live', 'polite');
                
                const innerWrapper = document.createElement('div');
                innerWrapper.className = 'admin-messages-inner';
                messagesWrapper.appendChild(innerWrapper);
                
                messagesContainer.insertBefore(messagesWrapper, messagesContainer.firstChild);
            }
        }
        
        // Create success message element
        const messageHtml = `
            <div class="admin-messages-wrap messages-auto-dismiss" data-dismiss-ms="${duration}" aria-live="polite">
                <div class="admin-messages-inner">
                    <div class="message-alert msg-success" role="status">
                        <span class="msg-icon" aria-hidden="true">
                            <i class="fas fa-check-circle"></i>
                        </span>
                        <span class="msg-text">${this.escapeHtml(message)}</span>
                        <button type="button" class="msg-close" aria-label="Dismiss message" onclick="this.closest('.admin-messages-wrap').remove()">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        // Insert the message
        messagesContainer.insertAdjacentHTML('afterbegin', messageHtml);
        
        // Auto-dismiss after duration
        setTimeout(function() {
            const msgElement = messagesContainer.querySelector('.admin-messages-wrap.messages-auto-dismiss');
            if (msgElement) {
                msgElement.classList.add('messages-hidden');
                setTimeout(function() {
                    msgElement.remove();
                }, 300);
            }
        }, duration);
    },

    /**
     * Show success message for form actions
     * @param {string} action - The action performed (e.g., 'KYC Verified', 'User Deleted')
     * @param {string} target - The target of the action (e.g., user email, KYC ID)
     */
    showActionSuccess: function(action, target) {
        const message = target ? `${action} successfully for: ${target}` : `${action} successful`;
        this.show(message);
    },

    /**
     * Show success message for CRUD operations
     * @param {string} operation - Operation type (Create, Update, Delete)
     * @param {string} itemType - Type of item (User, KYC Request, etc.)
     * @param {string} identifier - Item identifier (name, email, ID)
     */
    showCrudSuccess: function(operation, itemType, identifier) {
        const message = `${itemType} ${operation}d successfully${identifier ? `: ${identifier}` : ''}`;
        this.show(message);
    },

    /**
     * Escape HTML to prevent XSS
     * @param {string} text - Text to escape
     * @returns {string} - Escaped text
     */
    escapeHtml: function(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    /**
     * Show success message and optionally redirect
     * @param {string} message - Success message
     * @param {string} redirectUrl - URL to redirect to (optional)
     * @param {number} delay - Redirect delay in milliseconds (default: 2000)
     */
    showWithRedirect: function(message, redirectUrl, delay = 2000) {
        this.show(message);
        
        if (redirectUrl) {
            setTimeout(function() {
                window.location.href = redirectUrl;
            }, delay);
        }
    }
};

// Auto-initialize success messages for common actions
document.addEventListener('DOMContentLoaded', function() {
    // Check for URL parameters that indicate success
    const urlParams = new URLSearchParams(window.location.search);
    const successParam = urlParams.get('success');
    const actionParam = urlParams.get('action');
    const targetParam = urlParams.get('target');
    
    if (successParam === 'true' && actionParam) {
        if (targetParam) {
            SuccessMessage.showActionSuccess(actionParam.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()), targetParam);
        } else {
            SuccessMessage.show(`${actionParam.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())} successful`);
        }
        
        // Clean up URL parameters
        const cleanUrl = window.location.pathname;
        window.history.replaceState({}, document.title, cleanUrl);
    }
});

// API Base URL
const API_BASE_URL = '/api/auth';

// Role Selection
document.addEventListener('DOMContentLoaded', function() {
    // Role selection cards
    const roleCards = document.querySelectorAll('.role-card');
    roleCards.forEach(card => {
        card.addEventListener('click', function() {
            const role = this.getAttribute('data-role');
            window.location.href = `/register/?role=${role}`;
        });
    });

    // Login Form
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
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
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                this.textContent = '🙈';
            } else {
                passwordInput.type = 'password';
                this.textContent = '👁️';
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

// Handle Login
async function handleLogin(e) {
    e.preventDefault();
    
    const form = e.target;
    const emailInput = form.elements.email || form.querySelector('#email');
    const passwordInput = form.elements.password || form.querySelector('#password');
    
    if (!emailInput || !passwordInput) {
        console.error('Login form fields not found');
        alert('Form error: Please refresh the page and try again.');
        return;
    }
    
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const messageDiv = document.getElementById('message');
    
    // Clear previous messages
    if (messageDiv) {
        messageDiv.textContent = '';
        messageDiv.className = 'message';
    }

    // Validate email
    if (!email || !email.includes('@')) {
        if (messageDiv) {
            messageDiv.textContent = 'Please enter a valid email address';
            messageDiv.className = 'message error';
        } else {
            alert('Please enter a valid email address');
        }
        return;
    }

    // Validate password
    if (!password || password.length < 1) {
        if (messageDiv) {
            messageDiv.textContent = 'Please enter your password';
            messageDiv.className = 'message error';
        } else {
            alert('Please enter your password');
        }
        return;
    }

    try {
        // Show loading state
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton ? submitButton.textContent : '';
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = 'Signing In...';
        }

        console.log('Sending login request:', { email, passwordLength: password.length });

        const response = await fetch('/api/auth/login/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email: email,
                password: password
            })
        });

        console.log('Login response status:', response.status);
        console.log('Login response ok:', response.ok);

        // Restore button state
        if (submitButton) {
            submitButton.disabled = false;
            submitButton.textContent = originalButtonText;
        }

        let data;
        try {
            data = await response.json();
            console.log('Login response data:', data);
        } catch (jsonError) {
            console.error('JSON parse error:', jsonError);
            if (messageDiv) {
                messageDiv.textContent = 'Server returned invalid response. Please try again.';
                messageDiv.className = 'message error';
            } else {
                alert('Server returned invalid response. Please try again.');
            }
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.textContent = originalButtonText;
            }
            return;
        }

        if (response.ok) {
            console.log('Login successful:', data);
            // Success
            if (data.user) {
                // Store user data in localStorage
                localStorage.setItem('user', JSON.stringify(data.user));
                localStorage.setItem('isLoggedIn', 'true');
                
                if (messageDiv) {
                    messageDiv.textContent = data.message + ' - Welcome, ' + data.user.email + '!';
                    messageDiv.className = 'message success';
                }
                
                // Redirect to dashboard after 1.5 seconds
                setTimeout(() => {
                    window.location.href = '/dashboard/';
                }, 1500);
            } else {
                if (messageDiv) {
                    messageDiv.textContent = data.message || 'Login successful!';
                    messageDiv.className = 'message success';
                }
                setTimeout(() => {
                    window.location.href = '/dashboard/';
                }, 1500);
            }
        } else {
            // Error
            console.error('Login failed:', data);
            let errorMsg = data.error || 'Login failed. Please try again.';
            
            if (data.details) {
                const errorDetails = [];
                for (const [field, errors] of Object.entries(data.details)) {
                    if (Array.isArray(errors)) {
                        errorDetails.push(`${field}: ${errors.join(', ')}`);
                    } else {
                        errorDetails.push(`${field}: ${errors}`);
                    }
                }
                if (errorDetails.length > 0) {
                    errorMsg = errorDetails.join('\n');
                }
            }
            
            if (messageDiv) {
                messageDiv.textContent = errorMsg;
                messageDiv.className = 'message error';
            } else {
                alert(errorMsg);
            }
        }
    } catch (error) {
        console.error('Login error:', error);
        const errorMsg = 'Network error. Please check your connection and try again.';
        if (messageDiv) {
            messageDiv.textContent = errorMsg;
            messageDiv.className = 'message error';
        } else {
            alert(errorMsg);
        }
        
        // Restore button state
        const submitButton = form.querySelector('button[type="submit"]');
        if (submitButton) {
            submitButton.disabled = false;
            submitButton.textContent = 'Sign In';
        }
    }
}

// Handle Register
async function handleRegister(e) {
    e.preventDefault();
    
    console.log('Registration form submitted');
    
    const form = e.target;
    
    // Get form values - use form.elements for reliable access
    const emailInput = form.elements.email || form.querySelector('#email');
    const passwordInput = form.elements.password || form.querySelector('#password');
    const confirmPasswordInput = form.elements.confirmPassword || form.querySelector('#confirmPassword');
    const roleSelect = form.elements.userRole || form.querySelector('#userRole');
    const roleHidden = form.querySelector('#role');
    
    if (!emailInput || !passwordInput || !confirmPasswordInput) {
        console.error('Form fields not found');
        alert('Form error: Please refresh the page and try again.');
        return;
    }
    
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;
    
    // Get role - check select dropdown first, then hidden field, then default
    let role = 'buyer';
    if (roleSelect && roleSelect.value) {
        role = roleSelect.value;
    } else if (roleHidden && roleHidden.value) {
        role = roleHidden.value;
    }
    
    // Ensure role is valid
    const allowedRoles = ['buyer', 'farmer', 'agricultural_expert', 'vendor'];
    if (!allowedRoles.includes(role)) {
        role = 'buyer';
    }
    
    console.log('Registration form data:', { email, role, passwordLength: password.length, hasConfirmPassword: !!confirmPassword });
    
    const messageDiv = document.getElementById('message');
    
    // Clear previous messages
    if (messageDiv) {
        messageDiv.textContent = '';
        messageDiv.className = 'message';
    }
    
    // Validate passwords match
    if (password !== confirmPassword) {
        if (messageDiv) {
            messageDiv.textContent = 'Passwords do not match!';
            messageDiv.className = 'message error';
        } else {
            alert('Passwords do not match!');
        }
        return;
    }

    // Validate password length
    if (password.length < 8) {
        if (messageDiv) {
            messageDiv.textContent = 'Password must be at least 8 characters long!';
            messageDiv.className = 'message error';
        } else {
            alert('Password must be at least 8 characters long!');
        }
        return;
    }

    // Check terms
    const termsCheckbox = form.elements.terms || form.querySelector('#terms');
    if (!termsCheckbox || !termsCheckbox.checked) {
        if (messageDiv) {
            messageDiv.textContent = 'Please agree to the Terms of Service and Privacy Policy';
            messageDiv.className = 'message error';
        } else {
            alert('Please agree to the Terms of Service and Privacy Policy');
        }
        return;
    }

    // Validate email
    if (!email || !email.includes('@')) {
        if (messageDiv) {
            messageDiv.textContent = 'Please enter a valid email address';
            messageDiv.className = 'message error';
        } else {
            alert('Please enter a valid email address');
        }
        return;
    }

    try {
        // Show loading state
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton ? submitButton.textContent : '';
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = 'Creating Account...';
        }

        // Ensure role is set
        if (!role || role === '') {
            role = 'buyer';
        }
        
        // Prepare request data
        const requestData = {
            email: email,
            password: password,
            role: role
        };
        
        console.log('Sending registration request:', { email, role, passwordLength: password.length });
        
        const response = await fetch('/api/auth/signup/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestData)
        });

        console.log('Response status:', response.status);
        console.log('Response ok:', response.ok);
        console.log('Response headers:', Object.fromEntries(response.headers.entries()));

        // Restore button state
        if (submitButton) {
            submitButton.disabled = false;
            submitButton.textContent = originalButtonText;
        }

        let data;
        try {
            data = await response.json();
            console.log('Response data:', data);
        } catch (jsonError) {
            console.error('JSON parse error:', jsonError);
            if (messageDiv) {
                messageDiv.textContent = 'Server returned invalid response. Please try again.';
                messageDiv.className = 'message error';
            } else {
                alert('Server returned invalid response. Please try again.');
            }
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.textContent = originalButtonText;
            }
            return;
        }

        if (response.ok) {
            console.log('Registration successful:', data);
            // Success - show message and redirect to login page
            if (messageDiv) {
                messageDiv.textContent = data.message || 'Account created successfully! Redirecting to login...';
                messageDiv.className = 'message success';
            }
            
            // Redirect to login page with success parameter after 2 seconds
            setTimeout(() => {
                window.location.href = '/login/?registered=true';
            }, 2000);
        } else {
            // Error - handle different error formats
            console.error('Registration failed - Full response:', data);
            console.error('Response status code:', response.status);
            
            let errorMsg = 'Registration failed. Please try again.';
            
            // Try to extract meaningful error message
            if (data.error) {
                errorMsg = data.error;
            }
            
            if (data.details) {
                const errorDetails = [];
                for (const [field, errors] of Object.entries(data.details)) {
                    if (Array.isArray(errors)) {
                        // Join array of error messages
                        const fieldErrors = errors.map(err => {
                            if (typeof err === 'string') {
                                return err;
                            } else if (typeof err === 'object' && err.message) {
                                return err.message;
                            }
                            return String(err);
                        }).join(', ');
                        errorDetails.push(`${field.charAt(0).toUpperCase() + field.slice(1)}: ${fieldErrors}`);
                    } else if (typeof errors === 'object' && errors !== null) {
                        // Handle nested errors
                        for (const [key, value] of Object.entries(errors)) {
                            if (Array.isArray(value)) {
                                errorDetails.push(`${field} ${key}: ${value.join(', ')}`);
                            } else {
                                errorDetails.push(`${field} ${key}: ${value}`);
                            }
                        }
                    } else if (errors) {
                        errorDetails.push(`${field.charAt(0).toUpperCase() + field.slice(1)}: ${errors}`);
                    }
                }
                if (errorDetails.length > 0) {
                    errorMsg = errorDetails.join('\n');
                }
            }
            
            // Handle specific error cases
            if (data.details && data.details.email) {
                const emailErrors = Array.isArray(data.details.email) ? data.details.email : [data.details.email];
                const emailErrorStr = emailErrors.map(e => String(e)).join(' ');
                if (emailErrorStr.includes('already exists') || emailErrorStr.includes('unique') || emailErrorStr.includes('already registered')) {
                    errorMsg = 'This email is already registered. Please use a different email or try logging in.';
                }
            }
            
            // Handle role errors specifically
            if (data.details && data.details.role) {
                const roleErrors = Array.isArray(data.details.role) ? data.details.role : [data.details.role];
                errorMsg = `Role error: ${roleErrors.join(', ')}`;
            }
            
            console.error('Final error message to display:', errorMsg);
            
            // Display error message
            if (messageDiv) {
                messageDiv.textContent = errorMsg;
                messageDiv.className = 'message error';
                messageDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            } else {
                alert('Registration Failed\n\n' + errorMsg + '\n\nCheck browser console (F12) for more details.');
            }
        }
    } catch (error) {
        console.error('Registration error:', error);
        const errorMsg = 'Network error. Please check your connection and try again.';
        if (messageDiv) {
            messageDiv.textContent = errorMsg;
            messageDiv.className = 'message error';
        } else {
            alert(errorMsg);
        }
        
        // Restore button state
        const submitButton = form.querySelector('button[type="submit"]');
        if (submitButton) {
            submitButton.disabled = false;
            submitButton.textContent = 'Create Account';
        }
    }
}

// Check if user is logged in
function checkAuth() {
    const isLoggedIn = localStorage.getItem('isLoggedIn');
    if (isLoggedIn === 'true') {
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        return user;
    }
    return null;
}

// Logout function
function handleLogout() {
    localStorage.removeItem('user');
    localStorage.removeItem('isLoggedIn');
    window.location.href = '/';
}

// Make logout available globally
window.handleLogout = handleLogout;


/**
 * Enhanced Form Validation System
 * Handles all form validation, error display, and user interactions
 */

class FormValidator {
    constructor(formId, options = {}) {
        this.form = document.getElementById(formId);
        this.options = {
            showRealTimeValidation: true,
            debounceMs: 300,
            ...options
        };
        this.validators = {};
        this.debounceTimers = {};
        
        if (this.form) {
            this.init();
        }
    }

    init() {
        // Setup form submission
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        
        // Setup real-time validation
        if (this.options.showRealTimeValidation) {
            this.setupRealTimeValidation();
        }
        
        // Clear errors on input
        this.form.addEventListener('input', (e) => this.clearFieldError(e.target.name));
        this.form.addEventListener('focus', (e) => this.clearFieldError(e.target.name));
    }

    setupRealTimeValidation() {
        const inputs = this.form.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            if (input.name) {
                input.addEventListener('input', (e) => this.validateField(e.target));
                input.addEventListener('blur', (e) => this.validateField(e.target));
            }
        });
    }

    addValidator(fieldName, validator) {
        this.validators[fieldName] = validator;
    }

    validateField(field) {
        if (!field || !field.name) return true;
        
        const fieldName = field.name;
        const value = field.value.trim();
        const validator = this.validators[fieldName];
        
        if (!validator) return true;
        
        // Debounce validation
        if (this.debounceTimers[fieldName]) {
            clearTimeout(this.debounceTimers[fieldName]);
        }
        
        this.debounceTimers[fieldName] = setTimeout(() => {
            const result = validator(value, field);
            this.setFieldValidation(fieldName, result);
        }, this.options.debounceMs);
        
        return true;
    }

    setFieldValidation(fieldName, result) {
        const field = this.form.querySelector(`[name="${fieldName}"]`);
        if (!field) return;
        
        const wrapper = field.closest('.input-wrapper') || field.closest('.form-group');
        
        if (result.valid) {
            this.clearFieldError(fieldName);
            this.setFieldSuccess(fieldName, result.message);
        } else {
            this.setFieldError(fieldName, result.message);
        }
    }

    setFieldError(fieldName, message) {
        const field = this.form.querySelector(`[name="${fieldName}"]`);
        const errorElement = document.getElementById(`${this.form.id}FieldError-${fieldName}`);
        
        if (field) {
            field.classList.add('field-invalid');
            field.classList.remove('field-valid');
            
            const wrapper = field.closest('.input-wrapper');
            if (wrapper) {
                wrapper.classList.add('has-error');
                wrapper.classList.remove('has-success');
            }
        }
        
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.classList.add('show');
        }
    }

    setFieldSuccess(fieldName, message) {
        const field = this.form.querySelector(`[name="${fieldName}"]`);
        const successElement = document.getElementById(`${this.form.id}FieldSuccess-${fieldName}`);
        
        if (field) {
            field.classList.add('field-valid');
            field.classList.remove('field-invalid');
            
            const wrapper = field.closest('.input-wrapper');
            if (wrapper) {
                wrapper.classList.add('has-success');
                wrapper.classList.remove('has-error');
            }
        }
        
        if (successElement) {
            successElement.textContent = message;
            successElement.classList.add('show');
        }
    }

    clearFieldError(fieldName) {
        const field = this.form.querySelector(`[name="${fieldName}"]`);
        const errorElement = document.getElementById(`${this.form.id}FieldError-${fieldName}`);
        const successElement = document.getElementById(`${this.form.id}FieldSuccess-${fieldName}`);
        
        if (field) {
            field.classList.remove('field-invalid', 'field-valid');
            
            const wrapper = field.closest('.input-wrapper');
            if (wrapper) {
                wrapper.classList.remove('has-error', 'has-success');
            }
        }
        
        if (errorElement) {
            errorElement.classList.remove('show');
        }
        
        if (successElement) {
            successElement.classList.remove('show');
        }
    }

    clearAllErrors() {
        const fields = this.form.querySelectorAll('input, select, textarea');
        fields.forEach(field => {
            if (field.name) {
                this.clearFieldError(field.name);
            }
        });
    }

    validateAll() {
        let isValid = true;
        const fields = this.form.querySelectorAll('input, select, textarea');
        
        fields.forEach(field => {
            if (field.name && field.type !== 'hidden') {
                const result = this.validateField(field);
                if (!result.valid) {
                    isValid = false;
                }
            }
        });
        
        return isValid;
    }

    handleSubmit(e) {
        e.preventDefault();
        
        if (!this.validateAll()) {
            this.showFormError('Please fix the errors below before submitting.');
            return false;
        }
        
        // Call custom submit handler if provided
        if (this.options.onSubmit) {
            this.options.onSubmit(e, this);
        } else {
            // Default form submission
            this.submitForm();
        }
        
        return false;
    }

    submitForm() {
        const submitBtn = this.form.querySelector('button[type="submit"], input[type="submit"]');
        const originalText = submitBtn ? submitBtn.textContent : '';
        
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        }
        
        // Submit form
        this.form.submit();
    }

    showFormError(message) {
        const errorElement = document.getElementById(`${this.form.id}Error-general`);
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.classList.add('show');
        }
    }

    reset() {
        this.form.reset();
        this.clearAllErrors();
    }
}

// Common validation functions
const Validators = {
    required: (message = 'This field is required.') => (value) => ({
        valid: value.trim().length > 0,
        message: message
    }),
    
    email: (message = 'Please enter a valid email address.') => (value) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return {
            valid: emailRegex.test(value),
            message: message
        };
    },
    
    minLength: (min, message) => (value) => ({
        valid: value.length >= min,
        message: message || `Must be at least ${min} characters.`
    }),
    
    maxLength: (max, message) => (value) => ({
        valid: value.length <= max,
        message: message || `Must be no more than ${max} characters.`
    }),
    
    password: (message = 'Password must be at least 8 characters with letters, numbers, and special characters.') => (value) => {
        const hasLetter = /[a-zA-Z]/.test(value);
        const hasNumber = /\d/.test(value);
        const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(value);
        return {
            valid: value.length >= 8 && hasLetter && hasNumber,
            message: message
        };
    },
    
    passwordMatch: (compareField, message = 'Passwords do not match.') => (value) => ({
        valid: value === document.getElementById(compareField)?.value,
        message: message
    }),
    
    phone: (message = 'Please enter a valid phone number.') => (value) => {
        const phoneRegex = /^[\d\s\-\+\(\)]+$/;
        return {
            valid: phoneRegex.test(value) && value.replace(/\D/g, '').length >= 10,
            message: message
        };
    },
    
    numeric: (message = 'Please enter a valid number.') => (value) => {
        const num = parseFloat(value);
        return {
            valid: !isNaN(num) && num >= 0,
            message: message
        };
    }
};

// Toast notification system
class ToastManager {
    constructor() {
        this.container = null;
        this.init();
    }

    init() {
        this.container = document.createElement('div');
        this.container.className = 'toast-container';
        document.body.appendChild(this.container);
    }

    show(message, type = 'info', duration = 5000) {
        if (!this.container) this.init();
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = this.getIcon(type);
        toast.innerHTML = `
            <i class="fas ${icon}"></i>
            <span>${message}</span>
        `;
        
        this.container.appendChild(toast);
        
        // Auto remove
        setTimeout(() => {
            toast.classList.add('hiding');
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, duration);
    }

    getIcon(type) {
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        return icons[type] || icons.info;
    }

    success(message, duration) {
        this.show(message, 'success', duration);
    }

    error(message, duration) {
        this.show(message, 'error', duration);
    }

    warning(message, duration) {
        this.show(message, 'warning', duration);
    }

    info(message, duration) {
        this.show(message, 'info', duration);
    }
}

// Confirmation dialog system
class ConfirmationDialog {
    constructor() {
        this.modal = null;
    }

    show(options) {
        const {
            title = 'Confirm Action',
            message = 'Are you sure you want to perform this action?',
            type = 'warning',
            confirmText = 'Confirm',
            cancelText = 'Cancel',
            onConfirm = null,
            onCancel = null
        } = options;

        this.createModal(options);
        
        return new Promise((resolve) => {
            const confirmBtn = this.modal.querySelector('.btn-confirm');
            const cancelBtn = this.modal.querySelector('.btn-cancel');
            
            const handleConfirm = () => {
                this.hide();
                if (onConfirm) onConfirm();
                resolve(true);
            };
            
            const handleCancel = () => {
                this.hide();
                if (onCancel) onCancel();
                resolve(false);
            };
            
            confirmBtn.addEventListener('click', handleConfirm);
            cancelBtn.addEventListener('click', handleCancel);
            
            // Close on backdrop click
            this.modal.addEventListener('click', (e) => {
                if (e.target === this.modal) {
                    handleCancel();
                }
            });
            
            // Close on Escape key
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    handleCancel();
                }
            });
        });
    }

    createModal(options) {
        this.modal = document.createElement('div');
        this.modal.className = 'confirmation-modal';
        
        const iconClass = options.type === 'danger' ? 'danger' : 'warning';
        const icon = options.type === 'danger' ? 'fa-exclamation-triangle' : 'fa-question-circle';
        
        this.modal.innerHTML = `
            <div class="confirmation-content">
                <div class="confirmation-header">
                    <div class="confirmation-icon ${iconClass}">
                        <i class="fas ${icon}"></i>
                    </div>
                    <div>
                        <div class="confirmation-title">${options.title}</div>
                    </div>
                </div>
                <div class="confirmation-message">${options.message}</div>
                <div class="confirmation-buttons">
                    <button type="button" class="btn btn-secondary btn-cancel">${options.cancelText}</button>
                    <button type="button" class="btn btn-primary btn-confirm">${options.confirmText}</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(this.modal);
    }

    hide() {
        if (this.modal && this.modal.parentNode) {
            this.modal.parentNode.removeChild(this.modal);
            this.modal = null;
        }
    }
}

// Global instances
let toastManager = new ToastManager();
let confirmationDialog = new ConfirmationDialog();

// Utility functions
function showConfirmation(options) {
    return confirmationDialog.show(options);
}

function showToast(message, type, duration) {
    toastManager.show(message, type, duration);
}

function showSuccess(message, duration) {
    toastManager.success(message, duration);
}

function showError(message, duration) {
    toastManager.error(message, duration);
}

function showWarning(message, duration) {
    toastManager.warning(message, duration);
}

function showInfo(message, duration) {
    toastManager.info(message, duration);
}

// Form validation setup for common forms
function setupLoginForm() {
    const validator = new FormValidator('loginForm', {
        onSubmit: (e, formValidator) => {
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            
            // Client-side validation
            if (!email) {
                formValidator.setFieldError('email', 'Email address is required.');
                return false;
            }
            
            if (!Validators.email().valid(email)) {
                formValidator.setFieldError('email', 'Please enter a valid email address.');
                return false;
            }
            
            if (!password) {
                formValidator.setFieldError('password', 'Password is required.');
                return false;
            }
            
            // Submit via AJAX or form
            formValidator.submitForm();
        }
    });
    
    // Add validators
    validator.addValidator('email', Validators.required('Email address is required.').and(Validators.email()));
    validator.addValidator('password', Validators.required('Password is required.'));
}

function setupSignupForm() {
    const validator = new FormValidator('signupForm', {
        onSubmit: (e, formValidator) => {
            // Client-side validation
            const requiredFields = ['first_name', 'last_name', 'email', 'password', 'confirm_password', 'role'];
            
            for (const field of requiredFields) {
                const element = document.getElementById(field);
                if (!element || !element.value.trim()) {
                    formValidator.setFieldError(field, `${field.replace('_', ' ')} is required.`);
                    return false;
                }
            }
            
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            if (!Validators.email().valid(email)) {
                formValidator.setFieldError('email', 'Please enter a valid email address.');
                return false;
            }
            
            if (!Validators.password().valid(password)) {
                formValidator.setFieldError('password', 'Password must be at least 8 characters long.');
                return false;
            }
            
            if (password !== confirmPassword) {
                formValidator.setFieldError('confirm_password', 'Passwords do not match.');
                return false;
            }
            
            // Submit via AJAX or form
            formValidator.submitForm();
        }
    });
    
    // Add validators
    validator.addValidator('first_name', Validators.required('First name is required.'));
    validator.addValidator('last_name', Validators.required('Last name is required.'));
    validator.addValidator('email', Validators.required('Email is required.').and(Validators.email()));
    validator.addValidator('password', Validators.required('Password is required.').and(Validators.minLength(8)));
    validator.addValidator('confirm_password', Validators.required('Please confirm your password.').and(Validators.passwordMatch('password')));
}

// Helper for chaining validators
Validators.required.prototype.and = function(otherValidator) {
    const originalValidator = this;
    return (value) => {
        const result1 = originalValidator(value);
        if (!result1.valid) return result1;
        const result2 = otherValidator(value);
        return result2;
    };
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Setup forms if they exist
    if (document.getElementById('loginForm')) {
        setupLoginForm();
    }
    
    if (document.getElementById('signupForm')) {
        setupSignupForm();
    }
});

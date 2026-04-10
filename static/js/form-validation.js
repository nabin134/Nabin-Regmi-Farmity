/**
 * Enhanced Form Validation System
 * Handles all form validation, error display, and user interactions
 */

class EnhancedFormValidator {
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

    _fieldValue(field) {
        if (!field) return '';
        if (field.type === 'checkbox') {
            return field.checked ? '1' : '';
        }
        if (field.type === 'radio') {
            const form = field.form || this.form;
            const sel = form && form.querySelector(`input[name="${field.name}"]:checked`);
            return sel ? sel.value : '';
        }
        return (field.value || '').trim();
    }

    validateField(field) {
        if (!field || !field.name) return true;

        const fieldName = field.name;
        const value = this._fieldValue(field);
        const validator = this.validators[fieldName];

        if (!validator) return true;

        if (this.debounceTimers[fieldName]) {
            clearTimeout(this.debounceTimers[fieldName]);
        }

        this.debounceTimers[fieldName] = setTimeout(() => {
            const result = validator(value, field);
            this.setFieldValidation(fieldName, result);
        }, this.options.debounceMs);

        return true;
    }

    validateFieldSync(field) {
        if (!field || !field.name) return { valid: true, message: '' };
        const fieldName = field.name;
        const validator = this.validators[fieldName];
        if (!validator) return { valid: true, message: '' };
        const value = this._fieldValue(field);
        const result = validator(value, field);
        this.setFieldValidation(fieldName, result);
        return result;
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
        let errorElement = this.form.id
            ? document.getElementById(`${this.form.id}FieldError-${fieldName}`)
            : null;
        if (!errorElement && field) {
            const fg = field.closest('.form-group');
            if (fg) {
                errorElement = fg.querySelector('.register-field-error, .login-field-error, .field-error');
            }
        }

        if (field) {
            field.classList.add('field-invalid');
            field.classList.remove('field-valid');

            const wrapper = field.closest('.input-wrapper');
            if (wrapper) {
                wrapper.classList.add('has-error');
                wrapper.classList.remove('has-success');
            }
            const fg = field.closest('.form-group');
            if (fg) fg.classList.add('has-error');
        }

        if (errorElement) {
            errorElement.textContent = message;
            errorElement.classList.add('show');
            errorElement.style.display = 'block';
            errorElement.style.color = '#dc3545';
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
        let errorElement = this.form.id
            ? document.getElementById(`${this.form.id}FieldError-${fieldName}`)
            : null;
        if (!errorElement && field) {
            const fg = field.closest('.form-group');
            if (fg) {
                errorElement = fg.querySelector('.register-field-error, .login-field-error, .field-error');
            }
        }
        const successElement = this.form.id
            ? document.getElementById(`${this.form.id}FieldSuccess-${fieldName}`)
            : null;

        if (field) {
            field.classList.remove('field-invalid', 'field-valid');

            const wrapper = field.closest('.input-wrapper');
            if (wrapper) {
                wrapper.classList.remove('has-error', 'has-success');
            }
            const fg = field.closest('.form-group');
            if (fg) fg.classList.remove('has-error');
        }

        if (errorElement) {
            errorElement.textContent = '';
            errorElement.classList.remove('show');
            errorElement.style.display = '';
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
        return this.validateAllSync();
    }

    validateAllSync() {
        let isValid = true;
        const seenRadio = new Set();
        const fields = this.form.querySelectorAll('input, select, textarea');

        fields.forEach(field => {
            if (!field.name || field.type === 'hidden' || field.type === 'submit' || field.type === 'button') {
                return;
            }
            if (field.type === 'radio') {
                if (seenRadio.has(field.name)) return;
                seenRadio.add(field.name);
            }
            const result = this.validateFieldSync(field);
            if (!result.valid) {
                isValid = false;
            }
        });

        return isValid;
    }

    handleSubmit(e) {
        e.preventDefault();

        const generalEl = document.getElementById(`${this.form.id}Error-general`);
        if (generalEl) {
            generalEl.textContent = '';
            generalEl.classList.remove('show');
        }

        if (!this.validateAllSync()) {
            const firstInvalid = this.form.querySelector('.field-invalid');
            if (firstInvalid && typeof firstInvalid.focus === 'function') {
                firstInvalid.focus();
            }
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
    
    passwordMatch: (compareFieldName, message = 'Passwords do not match.') => (value, field) => {
        const form = field?.form || document.getElementById('registerForm') || document.getElementById('signupForm');
        const other = form?.querySelector(`[name="${compareFieldName}"]`);
        const ov = other ? other.value : '';
        return {
            valid: value === ov,
            message: message
        };
    },
    
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

        const icon = document.createElement('i');
        icon.className = 'fas ' + this.getIcon(type);
        const span = document.createElement('span');
        span.textContent = message || '';

        toast.appendChild(icon);
        toast.appendChild(span);

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
            title = 'Confirm',
            message = 'Are you sure you want to perform this action?',
            type = 'warning',
            confirmText = 'Yes',
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
            
            const onKey = (e) => {
                if (e.key === 'Escape') {
                    document.removeEventListener('keydown', onKey);
                    handleCancel();
                }
            };
            document.addEventListener('keydown', onKey);
        });
    }

    createModal(options) {
        this.modal = document.createElement('div');
        this.modal.className = 'confirmation-modal';
        
        let iconClass, icon, confirmButtonClass;
        
        if (options.type === 'danger') {
            iconClass = 'danger';
            icon = 'fa-exclamation-triangle';
            confirmButtonClass = 'btn-danger';
        } else if (options.type === 'success') {
            iconClass = 'success';
            icon = 'fa-check-circle';
            confirmButtonClass = 'btn-primary';
        } else {
            iconClass = 'warning';
            icon = 'fa-question-circle';
            confirmButtonClass = 'btn-primary';
        }
        
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
                    <button type="button" class="btn btn-cancel">${options.cancelText}</button>
                    <button type="button" class="btn ${confirmButtonClass} btn-confirm">${options.confirmText}</button>
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
function chainValidators() {
    const parts = Array.prototype.slice.call(arguments);
    return function (value, field) {
        for (let i = 0; i < parts.length; i++) {
            const fn = parts[i];
            const r = fn(value, field);
            if (!r || !r.valid) {
                return r || { valid: false, message: 'Invalid value.' };
            }
        }
        return { valid: true, message: '' };
    };
}

function setupLoginForm() {
    const validator = new EnhancedFormValidator('loginForm', {
        showRealTimeValidation: true,
        onSubmit: function (e, formValidator) {
            formValidator.submitForm();
        },
    });

    validator.addValidator(
        'email',
        chainValidators(Validators.required('Email address is required.'), Validators.email())
    );
    validator.addValidator('password', Validators.required('Password is required.'));
}

/* Login page uses its own Fetch-based flow in login.html; do not auto-bind FormValidator there. */

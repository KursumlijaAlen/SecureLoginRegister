class SSSDApp {
    constructor() {
        this.API_BASE = '../api';
        this.token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');
        this.failedAttempts = 0;
        this.forgotAttempts = 0;
    }

    async makeRequest(endpoint, options = {}) {
        const url = `${this.API_BASE}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        if (this.token && !config.headers.Authorization) {
            config.headers.Authorization = `Bearer ${this.token}`;
        }

        try {
            const response = await fetch(url, config);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Request failed');
            }
            
            return { success: true, data, status: response.status };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    showMessage(elementId, message, type = 'error') {
        const element = document.getElementById(elementId);
        if (element) {
            const className = type === 'success' ? 'success' : 'error';
            element.innerHTML = `<div class="${className}">${message}</div>`;
        }
    }

    validateForm(formData, rules) {
        const errors = [];

        for (const [field, rule] of Object.entries(rules)) {
            const value = formData[field];

            if (rule.required && (!value || value.trim() === '')) {
                errors.push(`${rule.label || field} is required`);
                continue;
            }

            if (value && rule.minLength && value.length < rule.minLength) {
                errors.push(`${rule.label || field} must be at least ${rule.minLength} characters`);
            }

            if (value && rule.pattern && !rule.pattern.test(value)) {
                errors.push(rule.message || `${rule.label || field} format is invalid`);
            }
        }

        return errors;
    }

    // Enhanced security features
    checkPasswordStrength(password) {
        const strength = {
            score: 0,
            feedback: []
        };

        if (password.length >= 8) strength.score++;
        else strength.feedback.push('Use at least 8 characters');

        if (/[a-z]/.test(password)) strength.score++;
        else strength.feedback.push('Include lowercase letters');

        if (/[A-Z]/.test(password)) strength.score++;
        else strength.feedback.push('Include uppercase letters');

        if (/\d/.test(password)) strength.score++;
        else strength.feedback.push('Include numbers');

        if (/[^a-zA-Z\d]/.test(password)) strength.score++;
        else strength.feedback.push('Include special characters');

        return strength;
    }

    sanitizeInput(input) {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    }
}

// Initialize app
const app = new SSSDApp();

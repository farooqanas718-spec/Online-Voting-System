// Notification Toast System
const Toast = {
    show(message, type = 'success') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        container.appendChild(toast);
        
        // Trigger reflow for transition
        void toast.offsetWidth;
        toast.classList.add('show');
        
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 400); // Wait for exit animation
        }, 3000);
    }
};

// Common Fetch Wrapper for JSON APIs
const API = {
    async post(url, data) {
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || 'Server error');
            return result;
        } catch (error) {
            Toast.show(error.message, 'error');
            throw error;
        }
    },
    
    async get(url) {
        try {
            const response = await fetch(url);
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || 'Server error');
            return result;
        } catch (error) {
            Toast.show(error.message, 'error');
            throw error;
        }
    }
};

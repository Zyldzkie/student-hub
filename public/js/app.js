// Global app JavaScript
// This file can be used for shared functionality across all pages

document.addEventListener('DOMContentLoaded', function() {
    // Add any global initialization code here
    console.log('StudentHub loaded');
});

// Utility function for making API calls
async function apiCall(url, options = {}) {
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        return await response.json();
    } catch (error) {
        console.error('API call failed:', error);
        throw error;
    }
}


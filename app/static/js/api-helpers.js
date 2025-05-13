/**
 * API Helper Functions
 * 
 * A collection of utility functions for making API requests with robust error handling,
 * automatic retries, and fallback mechanisms.
 */

// Check if response is HTML instead of JSON
function isHtmlResponse(response) {
    const contentType = response.headers.get('content-type');
    return contentType && contentType.includes('text/html');
}

// Get best available token from various storage locations
function getBestToken() {
    return localStorage.getItem('access_token') || 
           localStorage.getItem('token') || 
           sessionStorage.getItem('token') || 
           '';
}

// Create standard headers for API requests
function createApiHeaders(includeToken = true) {
    const headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    };
    
    if (includeToken) {
        const token = getBestToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
    }
    
    return headers;
}

/**
 * Try loading data from multiple API endpoints
 * 
 * @param {Array} urls - Array of API URLs to try
 * @param {Function} onSuccess - Callback function when data is loaded successfully
 * @param {Function} onAllFailed - Callback function when all endpoints fail
 * @param {Object} options - Additional options (method, body, headers)
 */
async function tryApiEndpoints(urls, onSuccess, onAllFailed, options = {}) {
    // Default options
    const defaultOptions = {
        method: 'GET',
        headers: createApiHeaders(),
        body: null,
        currentIndex: 0,
        retryDelay: 300,
        bypassJwt: false
    };
    
    // Merge options
    const settings = { ...defaultOptions, ...options };
    
    // If we've tried all URLs, call the failure callback
    if (settings.currentIndex >= urls.length) {
        console.error('All API endpoints failed');
        if (onAllFailed && typeof onAllFailed === 'function') {
            onAllFailed();
        }
        return;
    }
    
    // Get current URL to try
    let url = urls[settings.currentIndex];
    
    // Add bypass_jwt parameter if needed
    if (settings.bypassJwt && !url.includes('bypass_jwt=true')) {
        url += (url.includes('?') ? '&' : '?') + 'bypass_jwt=true';
    }
    
    console.log(`[API] Trying ${settings.method} ${url}`);
    
    // Create fetch options
    const fetchOptions = {
        method: settings.method,
        headers: settings.headers
    };
    
    // Add body if present
    if (settings.body && (settings.method === 'POST' || settings.method === 'PUT' || settings.method === 'PATCH')) {
        fetchOptions.body = typeof settings.body === 'string' ? settings.body : JSON.stringify(settings.body);
    }
    
    try {
        const response = await fetch(url, fetchOptions);
        
        // Check if the response is HTML instead of JSON
        if (isHtmlResponse(response)) {
            console.warn(`[API] ${url} returned HTML instead of JSON`);
            throw new Error('Response was HTML instead of JSON');
        }
        
        // Check if response is OK
        if (!response.ok) {
            throw new Error(`Request failed: ${response.status}`);
        }
        
        // Parse JSON response
        const data = await response.json();
        
        // Check for API error
        if (data && data.error) {
            throw new Error(data.error);
        }
        
        // Process data based on format
        let processedData;
        
        if (Array.isArray(data)) {
            processedData = data;
        } else if (data.data && Array.isArray(data.data)) {
            processedData = data.data;
        } else {
            // Look for common array fields
            const arrayFields = ['users', 'projects', 'tasks', 'risks', 'members', 'items', 'results'];
            let foundArray = false;
            
            for (const field of arrayFields) {
                if (data[field] && Array.isArray(data[field])) {
                    processedData = data[field];
                    foundArray = true;
                    break;
                }
            }
            
            // If no array field found, use the original data
            if (!foundArray) {
                processedData = data;
            }
        }
        
        // Call success callback
        if (onSuccess && typeof onSuccess === 'function') {
            onSuccess(processedData, data);
        }
        
    } catch (error) {
        console.error(`[API] ${url} failed:`, error);
        
        // Try the next API endpoint
        settings.currentIndex++;
        setTimeout(() => {
            tryApiEndpoints(urls, onSuccess, onAllFailed, settings);
        }, settings.retryDelay);
    }
}

/**
 * Load data from API with robust error handling
 * 
 * @param {Array|String} endpoints - API endpoint(s) to try
 * @param {Function} onSuccess - Callback function when data is loaded successfully
 * @param {Function} onFailure - Callback function when all endpoints fail
 * @param {Object} options - Additional options
 * @returns {Promise}
 */
function fetchApiData(endpoints, onSuccess, onFailure, options = {}) {
    // Convert single endpoint to array
    const urls = Array.isArray(endpoints) ? endpoints : [endpoints];
    
    // Add standard endpoint variations if not provided
    if (urls.length === 1 && !options.noAutoExpand) {
        const baseEndpoint = urls[0];
        if (baseEndpoint.startsWith('/api/')) {
            // Add variations with auth/ and noauth/ prefixes
            const pathParts = baseEndpoint.split('/');
            pathParts.splice(2, 0, 'auth');
            urls.push(pathParts.join('/'));
            
            pathParts.splice(2, 1, 'noauth');
            urls.push(pathParts.join('/'));
        }
    }
    
    // Try all endpoints
    return tryApiEndpoints(urls, onSuccess, onFailure, options);
}

/**
 * Send data to API with robust error handling
 * 
 * @param {Array|String} endpoints - API endpoint(s) to try
 * @param {Object} data - Data to send
 * @param {Function} onSuccess - Callback function when data is sent successfully
 * @param {Function} onFailure - Callback function when all endpoints fail
 * @param {Object} options - Additional options
 * @returns {Promise}
 */
function sendApiData(endpoints, data, onSuccess, onFailure, options = {}) {
    // Set method to POST by default
    const settings = { 
        method: 'POST', 
        body: data,
        ...options
    };
    
    // Convert single endpoint to array
    const urls = Array.isArray(endpoints) ? endpoints : [endpoints];
    
    // Add standard endpoint variations if not provided
    if (urls.length === 1 && !options.noAutoExpand) {
        const baseEndpoint = urls[0];
        if (baseEndpoint.startsWith('/api/')) {
            // Add variations with auth/ and noauth/ prefixes
            const pathParts = baseEndpoint.split('/');
            pathParts.splice(2, 0, 'auth');
            urls.push(pathParts.join('/'));
            
            pathParts.splice(2, 1, 'noauth');
            urls.push(pathParts.join('/'));
        }
    }
    
    // Try all endpoints
    return tryApiEndpoints(urls, onSuccess, onFailure, settings);
}

/**
 * Update data via API with robust error handling
 * 
 * @param {Array|String} endpoints - API endpoint(s) to try
 * @param {Object} data - Data to send
 * @param {Function} onSuccess - Callback function when data is updated successfully
 * @param {Function} onFailure - Callback function when all endpoints fail
 * @param {Object} options - Additional options
 * @returns {Promise}
 */
function updateApiData(endpoints, data, onSuccess, onFailure, options = {}) {
    // Set method to PUT by default
    const settings = { 
        method: options.method || 'PUT', 
        body: data,
        ...options
    };
    
    return sendApiData(endpoints, data, onSuccess, onFailure, settings);
}

/**
 * Delete data via API with robust error handling
 * 
 * @param {Array|String} endpoints - API endpoint(s) to try
 * @param {Function} onSuccess - Callback function when data is deleted successfully
 * @param {Function} onFailure - Callback function when all endpoints fail
 * @param {Object} options - Additional options
 * @returns {Promise}
 */
function deleteApiData(endpoints, onSuccess, onFailure, options = {}) {
    // Set method to DELETE by default
    const settings = { 
        method: 'DELETE',
        ...options
    };
    
    return fetchApiData(endpoints, onSuccess, onFailure, settings);
}

/**
 * Reset all button states to prevent being stuck in loading state
 */
function resetAllButtonStates() {
    document.querySelectorAll('.btn').forEach(button => {
        if (button.getAttribute('data-original-html')) {
            button.innerHTML = button.getAttribute('data-original-html');
            button.disabled = false;
        }
        
        if (button.classList.contains('btn-loading')) {
            button.classList.remove('btn-loading');
            button.disabled = false;
        }
    });
    console.log('Reset all button states');
}

/**
 * Show a button's loading state and set up auto-reset
 * 
 * @param {HTMLElement} button - Button element to show loading state
 * @param {string} loadingText - Text to show while loading
 * @param {number} timeout - Timeout in ms to auto-reset button
 */
function showButtonLoading(button, loadingText = 'Loading...', timeout = 5000) {
    if (!button) return;
    
    // Save original HTML if not already saved
    if (!button.hasAttribute('data-original-html')) {
        button.setAttribute('data-original-html', button.innerHTML);
    }
    
    // Show loading state
    button.innerHTML = `<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> ${loadingText}`;
    button.disabled = true;
    
    // Set timeout to auto-reset button
    if (timeout > 0) {
        setTimeout(() => {
            if (button.disabled) {
                button.innerHTML = button.getAttribute('data-original-html');
                button.disabled = false;
                console.log('Button state auto-reset');
            }
        }, timeout);
    }
}

/**
 * Reset a button's loading state
 * 
 * @param {HTMLElement} button - Button element to reset
 */
function resetButtonState(button) {
    if (!button) return;
    
    if (button.hasAttribute('data-original-html')) {
        button.innerHTML = button.getAttribute('data-original-html');
        button.disabled = false;
    }
}

// Export functions for use in other scripts
window.ApiHelpers = {
    fetchApiData,
    sendApiData,
    updateApiData,
    deleteApiData,
    resetAllButtonStates,
    showButtonLoading,
    resetButtonState,
    getBestToken,
    createApiHeaders
}; 
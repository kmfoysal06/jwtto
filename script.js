// Function to decode Base64URL
function base64UrlDecode(str) {
    // Replace URL-safe characters
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    
    // Pad with '=' to make length a multiple of 4
    while (str.length % 4) {
        str += '=';
    }
    
    try {
        // Decode base64 and then decode URI component
        const decoded = atob(str);
        return decodeURIComponent(decoded.split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    } catch (e) {
        throw new Error('Invalid Base64 encoding');
    }
}

// Function to parse and display JWT
function parseJWT(token) {
    const errorElement = document.getElementById('error-message');
    const headerOutput = document.getElementById('header-output');
    const payloadOutput = document.getElementById('payload-output');
    const signatureOutput = document.getElementById('signature-output');
    
    // Clear previous outputs
    errorElement.classList.remove('show');
    errorElement.textContent = '';
    headerOutput.textContent = '';
    payloadOutput.textContent = '';
    signatureOutput.textContent = '';
    
    // Remove whitespace
    token = token.trim();
    
    if (!token) {
        return;
    }
    
    try {
        // Split the token into parts
        const parts = token.split('.');
        
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format. A JWT should have 3 parts separated by dots.');
        }
        
        // Decode header
        const header = JSON.parse(base64UrlDecode(parts[0]));
        headerOutput.textContent = JSON.stringify(header, null, 2);
        
        // Decode payload
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        payloadOutput.textContent = JSON.stringify(payload, null, 2);
        
        // Display signature (can't decode without secret key)
        signatureOutput.textContent = parts[2];
        
    } catch (error) {
        errorElement.textContent = 'Error: ' + error.message;
        errorElement.classList.add('show');
    }
}

// Event listener for input changes
document.addEventListener('DOMContentLoaded', function() {
    const jwtInput = document.getElementById('jwt-input');
    
    jwtInput.addEventListener('input', function() {
        parseJWT(this.value);
    });
    
    // Try to parse if there's initial content
    if (jwtInput.value) {
        parseJWT(jwtInput.value);
    }
});

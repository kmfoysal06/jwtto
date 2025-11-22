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

// Function to verify JWT signature using Web Crypto API
async function verifySignature(token, secret) {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { valid: false, reason: 'Invalid JWT format' };
        }

        const header = JSON.parse(base64UrlDecode(parts[0]));
        const algorithm = header.alg;

        // Only support HMAC algorithms for now
        if (!algorithm.startsWith('HS')) {
            return { valid: null, reason: `Verification not supported for ${algorithm}. Signature verification requires the secret key and currently only supports HMAC (HS256, HS384, HS512) algorithms.` };
        }

        // Map JWT algorithm to Web Crypto API algorithm
        const algoMap = {
            'HS256': 'SHA-256',
            'HS384': 'SHA-384',
            'HS512': 'SHA-512'
        };

        const cryptoAlgo = algoMap[algorithm];
        if (!cryptoAlgo) {
            return { valid: null, reason: `Unsupported algorithm: ${algorithm}` };
        }

        // Encode the secret
        const encoder = new TextEncoder();
        const keyData = encoder.encode(secret);
        
        // Import the secret key
        const key = await crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: cryptoAlgo },
            false,
            ['sign']
        );

        // Sign the header.payload
        const data = encoder.encode(parts[0] + '.' + parts[1]);
        const signature = await crypto.subtle.sign('HMAC', key, data);

        // Convert signature to base64url
        const signatureArray = new Uint8Array(signature);
        let binary = '';
        for (let i = 0; i < signatureArray.length; i++) {
            binary += String.fromCharCode(signatureArray[i]);
        }
        const base64 = btoa(binary);
        const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

        // Compare with the provided signature
        if (base64url === parts[2]) {
            return { valid: true, reason: 'Signature verified successfully' };
        } else {
            return { valid: false, reason: 'Signature does not match. The token may have been tampered with or the secret key is incorrect.' };
        }
    } catch (e) {
        return { valid: false, reason: `Verification error: ${e.message}` };
    }
}

// Function to parse and display JWT
async function parseJWT(token, secret = '') {
    const errorElement = document.getElementById('error-message');
    const headerOutput = document.getElementById('header-output');
    const payloadOutput = document.getElementById('payload-output');
    const signatureOutput = document.getElementById('signature-output');
    const signatureStatus = document.getElementById('signature-status');
    
    // Clear previous outputs
    errorElement.classList.remove('show');
    errorElement.textContent = '';
    headerOutput.textContent = '';
    payloadOutput.textContent = '';
    signatureOutput.textContent = '';
    if (signatureStatus) {
        signatureStatus.textContent = '';
        signatureStatus.className = 'signature-status';
    }
    
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
        
        // Verify signature if secret is provided
        if (secret && signatureStatus) {
            const result = await verifySignature(token, secret);
            
            if (result.valid === true) {
                signatureStatus.textContent = '✓ Valid Signature';
                signatureStatus.className = 'signature-status valid';
            } else if (result.valid === false) {
                signatureStatus.textContent = '✗ Invalid Signature: ' + result.reason;
                signatureStatus.className = 'signature-status invalid';
            } else {
                signatureStatus.textContent = 'ℹ ' + result.reason;
                signatureStatus.className = 'signature-status info';
            }
        }
        
    } catch (error) {
        errorElement.textContent = 'Error: ' + error.message;
        errorElement.classList.add('show');
    }
}

// Event listener for input changes
document.addEventListener('DOMContentLoaded', function() {
    const jwtInput = document.getElementById('jwt-input');
    const secretInput = document.getElementById('secret-input');
    
    async function handleInputChange() {
        await parseJWT(jwtInput.value, secretInput ? secretInput.value : '');
    }
    
    jwtInput.addEventListener('input', handleInputChange);
    
    if (secretInput) {
        secretInput.addEventListener('input', handleInputChange);
    }
    
    // Try to parse if there's initial content
    if (jwtInput.value) {
        handleInputChange();
    }
});

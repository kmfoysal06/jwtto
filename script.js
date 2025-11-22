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

// Function to parse PEM format public key
function pemToArrayBuffer(pem) {
    // Remove PEM header/footer and newlines
    const b64 = pem
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\s/g, '');
    
    // Decode base64
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
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

        // Support both HMAC and ECDSA algorithms
        const isHMAC = algorithm.startsWith('HS');
        const isECDSA = algorithm.startsWith('ES');
        const isRSA = algorithm.startsWith('RS') || algorithm.startsWith('PS');

        if (!isHMAC && !isECDSA && !isRSA) {
            return { valid: null, reason: `Unsupported algorithm: ${algorithm}` };
        }

        if (isRSA) {
            return { valid: null, reason: `Verification not supported for ${algorithm}. RSA signature verification requires the public key and is not yet implemented.` };
        }

        // Map JWT algorithm to Web Crypto API algorithm
        const algoMap = {
            'HS256': { name: 'HMAC', hash: 'SHA-256' },
            'HS384': { name: 'HMAC', hash: 'SHA-384' },
            'HS512': { name: 'HMAC', hash: 'SHA-512' },
            'ES256': { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
            'ES384': { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' },
            'ES512': { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' }
        };

        const cryptoAlgo = algoMap[algorithm];
        if (!cryptoAlgo) {
            return { valid: null, reason: `Unsupported algorithm: ${algorithm}` };
        }

        const encoder = new TextEncoder();
        const data = encoder.encode(parts[0] + '.' + parts[1]);

        if (isHMAC) {
            // HMAC verification (existing logic)
            const keyData = encoder.encode(secret);
            
            const key = await crypto.subtle.importKey(
                'raw',
                keyData,
                { name: 'HMAC', hash: cryptoAlgo.hash },
                false,
                ['sign']
            );

            const signature = await crypto.subtle.sign('HMAC', key, data);

            // Convert signature to base64url
            const signatureArray = new Uint8Array(signature);
            const binary = Array.from(signatureArray, byte => String.fromCharCode(byte)).join('');
            const base64 = btoa(binary);
            const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

            if (base64url === parts[2]) {
                return { valid: true, reason: 'Signature verified successfully' };
            } else {
                return { valid: false, reason: 'Signature does not match. The token may have been tampered with or the secret key is incorrect.' };
            }
        } else if (isECDSA) {
            // ECDSA verification (new logic)
            let publicKey;
            
            // Try to parse as PEM format first
            if (secret.includes('-----BEGIN PUBLIC KEY-----')) {
                try {
                    const keyData = pemToArrayBuffer(secret);
                    publicKey = await crypto.subtle.importKey(
                        'spki',
                        keyData,
                        { name: 'ECDSA', namedCurve: cryptoAlgo.namedCurve },
                        false,
                        ['verify']
                    );
                } catch (e) {
                    return { valid: false, reason: `Invalid PEM public key: ${e.message}` };
                }
            } else {
                // Try to parse as JWK format
                try {
                    const jwk = JSON.parse(secret);
                    // Ensure required JWK parameters are present
                    if (!jwk.kty || !jwk.crv || !jwk.x || !jwk.y) {
                        return { valid: false, reason: 'Invalid JWK format. Must contain kty, crv, x, and y parameters.' };
                    }
                    publicKey = await crypto.subtle.importKey(
                        'jwk',
                        jwk,
                        { name: 'ECDSA', namedCurve: cryptoAlgo.namedCurve },
                        false,
                        ['verify']
                    );
                } catch (e) {
                    return { valid: false, reason: `Invalid public key format. Please provide either PEM format or JWK JSON. Error: ${e.message}` };
                }
            }

            // Decode the signature from base64url
            const signatureB64 = parts[2].replace(/-/g, '+').replace(/_/g, '/');
            const paddedSignature = signatureB64 + '==='.slice((signatureB64.length + 3) % 4);
            const signatureBinary = atob(paddedSignature);
            const signatureBytes = new Uint8Array(signatureBinary.length);
            for (let i = 0; i < signatureBinary.length; i++) {
                signatureBytes[i] = signatureBinary.charCodeAt(i);
            }

            // Verify the signature
            const isValid = await crypto.subtle.verify(
                { name: 'ECDSA', hash: cryptoAlgo.hash },
                publicKey,
                signatureBytes,
                data
            );

            if (isValid) {
                return { valid: true, reason: 'Signature verified successfully' };
            } else {
                return { valid: false, reason: 'Signature does not match. The token may have been tampered with or the public key is incorrect.' };
            }
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

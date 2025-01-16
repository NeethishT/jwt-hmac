const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');

// Load RSA keys
const privateKey = fs.readFileSync('./keys/private.pem', 'utf8');
const publicKey = fs.readFileSync('./keys/public.pem', 'utf8');

// In-memory nonce store for replay prevention (use Redis in production)
const usedNonces = new Set();

// Generate HMAC for message integrity
function generateHMAC(data, secretKey) {
    return crypto.createHmac('sha512', secretKey).update(data).digest('base64');
}

// Create a hybrid JWT + HMAC token
function createSecureJWT(payload, secretKey) {
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    const exp = Math.floor(Date.now() / 1000) + 300; // Token expires in 5 mins

    // Add nonce and timestamp to the payload
    const extendedPayload = { ...payload, nonce, iat: timestamp, exp };

    // Generate HMAC based on payload + secret key
    const hmac = generateHMAC(JSON.stringify(extendedPayload), secretKey);

    // Sign JWT with private key (RS512 algorithm)
    const token = jwt.sign({ ...extendedPayload, hmac }, privateKey, {
        algorithm: 'RS512'
    });

    // Store the nonce temporarily to prevent replay attacks
    usedNonces.add(nonce);
    return token;
}

// Verify the JWT + HMAC token
function verifySecureJWT(token, secretKey) {
    try {
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS512'] });
        
        // Check replay attack (nonce validation)
        if (usedNonces.has(decoded.nonce)) {
            return { valid: false, error: 'Replay attack detected!' };
        }

        // Validate HMAC integrity
        const calculatedHMAC = generateHMAC(
            JSON.stringify({
                user: decoded.user, 
                nonce: decoded.nonce, 
                iat: decoded.iat, 
                exp: decoded.exp
            }),
            secretKey
        );

        if (calculatedHMAC !== decoded.hmac) {
            return { valid: false, error: 'HMAC signature mismatch!' };
        }

        // Expiry check (JWT built-in)
        if (decoded.exp * 1000 < Date.now()) {
            return { valid: false, error: 'Token expired!' };
        }

        // Valid token and remove nonce to avoid reuse
        usedNonces.delete(decoded.nonce);
        return { valid: true, decoded };
    } catch (err) {
        return { valid: false, error: err.message };
    }
}

module.exports = {
    createSecureJWT,
    verifySecureJWT
};

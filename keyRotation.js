const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Load all keys
const keys = {
    current: {
        privateKey: fs.readFileSync(path.join(__dirname, 'keys/private_2025.pem'), 'utf8'),
        publicKey: fs.readFileSync(path.join(__dirname, 'keys/public_2025.pem'), 'utf8'),
        kid: '2025'
    },
    previous: {
        privateKey: fs.readFileSync(path.join(__dirname, 'keys/private_2024.pem'), 'utf8'),
        publicKey: fs.readFileSync(path.join(__dirname, 'keys/public_2024.pem'), 'utf8'),
        kid: '2024'
    }
};

// In-memory storage for nonce prevention
const usedNonces = new Set();

// Generate HMAC for message integrity
function generateHMAC(data, secretKey) {
    return crypto.createHmac('sha512', secretKey).update(data).digest('base64');
}

// Create JWT with HMAC and Key ID (`kid`)
function createSecureJWT(payload, secretKey) {
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    const exp = Math.floor(Date.now() / 1000) + 300; // Expires in 5 mins

    // Extend the payload with nonce and timestamp
    const extendedPayload = { ...payload, nonce, iat: timestamp, exp };

    // Generate HMAC
    const hmac = generateHMAC(JSON.stringify(extendedPayload), secretKey);

    // Sign JWT with the current private key and attach `kid`
    const token = jwt.sign({ ...extendedPayload, hmac }, keys.current.privateKey, {
        algorithm: 'RS512',
        header: { kid: keys.current.kid }
    });

    // Store nonce for replay prevention
    usedNonces.add(nonce);
    return token;
}

// Verify JWT and handle Key Rotation
function verifySecureJWT(token, secretKey) {
    try {
        const decodedHeader = jwt.decode(token, { complete: true }).header;

        // Determine the key used based on `kid`
        const publicKey = decodedHeader.kid === keys.current.kid
            ? keys.current.publicKey
            : keys.previous.publicKey;

        // Verify JWT
        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS512'] });

        // Prevent Replay Attacks using Nonce
        if (usedNonces.has(decoded.nonce)) {
            return { valid: false, error: 'Replay attack detected!' };
        }

        // Recalculate HMAC and verify integrity
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

        // Expiry Check (JWT `exp`)
        if (decoded.exp * 1000 < Date.now()) {
            return { valid: false, error: 'Token expired!' };
        }

        // Remove nonce to prevent reuse
        usedNonces.delete(decoded.nonce);
        return { valid: true, decoded };
    } catch (error) {
        return { valid: false, error: error.message };
    }
}

module.exports = {
    createSecureJWT,
    verifySecureJWT
};

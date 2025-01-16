const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

// Ensure the keys directory exists
const keysDir = path.resolve(__dirname, 'keys');
if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir);
}

// Generate RSA key pair (2048-bit secure)
crypto.generateKeyPair('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem'
    }
}, (err, publicKey, privateKey) => {
    if (err) {
        console.error('Error generating keys:', err);
        return;
    }

    // Save keys to the keys directory
    fs.writeFileSync(`${keysDir}/private.pem`, privateKey);
    fs.writeFileSync(`${keysDir}/public.pem`, publicKey);

    console.log('✅ RSA Key Pair Generated Successfully!');
});

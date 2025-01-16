const { createSecureJWT, verifySecureJWT } = require('./index');
const secretKey = 'my-very-secure-key';

// Generate a secure token
const token = createSecureJWT({ user: 'Vidhya' }, secretKey);
console.log('Generated Token:', token);

// Verify the token
const verificationResult = verifySecureJWT(token, secretKey);
console.log('Verification Result:', verificationResult);
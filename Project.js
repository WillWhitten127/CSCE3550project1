const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const jwksRSA = require('jwks-rsa');

const app = express();
const port = 8080;

// Generate a new RSA key pair for signing JWTs
function generateKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'pkcs1',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs1',
            format: 'pem'
        }
    });
}

let currentKeyPair = generateKeyPair();

// Set an expiration time for the key (e.g. 24 hours)
let keyExpirationTime = Date.now() + 24 * 60 * 60 * 1000;

app.use(express.json()); // To parse JSON requests

// Define the JWKS route for retrieving the public keys with unique identifiers
app.get('/jwks', (req, res) => {
    const jwk = jwksRSA.createPublicKey(currentKeyPair.publicKey).toJWK();
    res.json({
        keys: [jwk]
    });
});

// Define the authentication route for verifying credentials and issuing JWTs
app.post('/auth', (req, res) => {
    // Verify the user's credentials (e.g. username and password)
    const { username, password } = req.body;
    if (username === 'admin' && password === 'password') {
        // Generate a new JWT using the current RSA key
        const token = jwt.sign({ sub: 'admin' }, currentKeyPair.privateKey, {
            algorithm: 'RS256',
            expiresIn: '1h',
            keyid: 'current'
        });
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if the current RSA key has expired
    if (Date.now() > keyExpirationTime) {
        // Generate a new RSA key pair and use it to sign the JWT
        currentKeyPair = generateKeyPair();
        keyExpirationTime = Date.now() + 24 * 60 * 60 * 1000;
    }
});

// Add error handling and logging middleware to the server
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

// Start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = 8080; // Changed from 3000 to 8080 as per your project requirements

// Body parser middleware
app.use(express.json());

// Middleware to log requests
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

// RSA key pair generation function
const generateKeyPair = () => {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
}

let currentKeyPair = generateKeyPair();
let keyExpirationTime = Date.now() + 24 * 60 * 60 * 1000;

app.get('/jwks', (req, res) => {
    const publicKey = currentKeyPair.publicKey;
    res.json({
        keys: [
            {
                alg: 'RS256',
                kty: 'RSA',
                use: 'sig',
                n: publicKey,
                e: 'AQAB', // Common public exponent for RSA
                kid: 'current'
            }
        ]
    });
});

app.post('/auth', (req, res) => {
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
        const token = jwt.sign({ sub: 'admin' }, currentKeyPair.privateKey, {
            algorithm: 'RS256',
            expiresIn: '1h',
            keyid: 'current'
        });
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }

    if (Date.now() > keyExpirationTime) {
        currentKeyPair = generateKeyPair();
        keyExpirationTime = Date.now() + 24 * 60 * 60 * 1000;
    }
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});

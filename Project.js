const express = require('express');
const jwt = require('jsonwebtoken');
const jwksRSA = require('jwks-rsa');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

app.use(bodyParser.json());

let expiredKeyPair = null; // Store the last key that expired

// Generate a new RSA key pair with unique 'kid'
function generateKeyPair() {
    const keyPair = jwksRSA.generateSync('RSA', 2048);
    keyPair.kid = Date.now().toString();  // Unique identifier using timestamp
    return keyPair;
}

let currentKeyPair = generateKeyPair();
let keyExpirationTime = Date.now() + 24 * 60 * 60 * 1000;

app.get('/jwks', (req, res) => {
    if (Date.now() > keyExpirationTime) {
        expiredKeyPair = currentKeyPair;
        currentKeyPair = generateKeyPair();
        keyExpirationTime = Date.now() + 24 * 60 * 60 * 1000;
    }

    res.json({
        keys: [{
            alg: 'RS256',
            kty: 'RSA',
            use: 'sig',
            n: currentKeyPair.rsaPublicKey.n.toString('base64'),
            e: currentKeyPair.rsaPublicKey.e.toString('base64'),
            kid: currentKeyPair.kid
        }]
    });
});

app.post('/auth', (req, res) => {
    const { username, password } = req.body;

    let signingKey = currentKeyPair.privateKey;
    let signingKid = currentKeyPair.kid;

    if (req.query.expired && expiredKeyPair) {
        signingKey = expiredKeyPair.privateKey;
        signingKid = expiredKeyPair.kid;
    }

    if (username === 'admin' && password === 'password') {
        const token = jwt.sign({ sub: 'admin' }, signingKey, {
            algorithm: 'RS256',
            expiresIn: '1h',
            keyid: signingKid
        });
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});

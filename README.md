# CSCE3550project1

How to run Project.js:

Commands for packages needed to install:
sudo apt update
sudo apt install nodejs

sudo apt install npm

npm init -y

npm install express jsonwebtoken jwks-rsa

Once you finsihed installing the necessary packages, you can run the sever by using the comand: "node Project1.js".

Explaining the code:

In the first part of the code section import libraries to help with the web framework. I used the express web framework for Node.js, and jsonwebtoken to help work with JSON Web Tokens(JWTs). In the second part of the code I used middleware to get Express to parse incoming request bodies with the JSON payload. The app.use function logs every request from HTTP GET and POST and the request URL. next() is then called to move on to the next middleware or route handler. The generateKeyPair generates an RSA key pair and returns it. 

The let currentKeyPair = generateKeyPair(); and let keyExpirationTime = Date.now() + 24 * 60 * 60 * 1000; generate an initial RSA key pair and set its expiration time to 24 hours from the current time. The app.get function  is an endpoint for the JSON Web Key Set (JWKS). It responds with the current public key in JWKS format. The key's modulus and exponent are provided, and a unique key identifier ("kid") is set as 'current'. The app.use function will log any error and respond with a 500 status code. The app.listen function sets up an Express server with two main endpoints: one for retrieving the current public key in JWKS format and one for user authentication that returns a JWT auth. The server uses RSA key pairs to sign and verify JWTs, and it rotates the key pair every 24 hours.








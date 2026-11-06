<<<<<<< HEAD
SecureTalk – Cryptographic Chat Application

1. Project Overview

SecureTalk is an educational cryptographic chat application that demonstrates how two users can exchange messages using browser-based encryption.

The application uses public-key cryptography to establish a shared secret and symmetric encryption to protect chat messages.

2. Technologies Used

- HTML5 – Webpage structure
- CSS3 – Dark-themed user interface
- JavaScript – Client-side functionality
- Node.js – Server runtime
- Express.js – Web server
- Socket.IO – Real-time communication
- Web Crypto API – Cryptographic operations

3. Cryptographic Algorithms

Algorithm| Purpose
ECDH P-256| Shared secret agreement
HKDF SHA-256| Key derivation
AES-256-GCM| Message encryption and authentication

4. Project Structure

SecureTalk/
├── public/
│   ├── index.html
│   ├── style.css
│   └── client.js
├── server.js
├── package.json
├── package-lock.json
└── README.md

5. Installation and Execution

1. Install Node.js.

2. Open the SecureTalk project folder in VS Code.

3. Install dependencies:
   
   "npm install"

4. Start the server:
   
   "node server.js"

5. Open the browser:
   
   "http://localhost:3000"

6. Open two separate browser sessions.

7. Enter the same room ID in both sessions.

8. Join the room and test messaging.

6. How It Works

1. Each participant generates an ECDH key pair.
2. Public keys are exchanged through the server.
3. Both browsers independently derive a shared secret.
4. HKDF derives an AES-256-GCM encryption key.
5. Messages are encrypted before being sent to the server.
6. The receiving browser decrypts the messages.

7. Project Features

- Two-participant chat rooms
- Real-time message exchange
- Browser-based cryptographic operations
- ECDH key agreement
- AES-256-GCM message encryption
- Dark cybersecurity dashboard
- Encrypted-message relay through Socket.IO

8. Security Limitations

This project is an educational prototype, not a production-ready secure messaging system.

It does not yet implement authenticated public-key verification, robust identity management, replay protection, or a complete secure session lifecycle. The key exchange has not been independently audited.

Do not use it to exchange confidential information.

9. Future Enhancements

- Public-key fingerprint verification
- User authentication
- Secure session management
- Replay protection
- Improved error handling
- Security testing and auditing
- Secure deployment using HTTPS

10. Author

ESWARAVAKA DHANUSHYA

B.Tech – Cyber Security

Project: SecureTalk – Cryptographic Chat Application
=======
# SecureTalk
>>>>>>> 1feb79d1cd81ebd93868bbdac08af15255641f6f

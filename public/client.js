const socket = io();

// ===============================
// HTML ELEMENTS
// ===============================

const joinSection = document.getElementById("joinSection");
const joinButton = document.getElementById("joinButton");
const roomInput = document.getElementById("roomInput");
const joinError = document.getElementById("joinError");

const messagesArea = document.getElementById("messagesArea");
const messageForm = document.getElementById("messageForm");
const messageInput = document.getElementById("messageInput");
const sendButton = document.getElementById("sendButton");

const securityStatus = document.getElementById("securityStatus");
const connectionStatus = document.getElementById("connectionStatus");
const peerStatus = document.getElementById("peerStatus");
const chatSubtitle = document.getElementById("chatSubtitle");

const fingerprintCard = document.getElementById("fingerprintCard");
const peerFingerprint = document.getElementById("peerFingerprint");
const myFingerprint = document.getElementById("myFingerprint");
const verificationStatus = document.getElementById("verificationStatus");

const verifyFingerprintButton =
    document.getElementById("verifyFingerprintButton");

// ===============================
// CRYPTOGRAPHIC STATE
// ===============================

let identityKeyPair = null;
let identityPublicKeyBase64 = null;
let identityFingerprint = null;

let ephemeralKeyPair = null;
let sharedKey = null;

// ===============================
// CONNECTION STATE
// ===============================

let currentRoom = null;
let joinedRoom = false;
let peerKeyReceived = false;
let peerVerified = false;
let shouldRejoin = false;

// ===============================
// PEER IDENTITY STATE
// ===============================

let pendingPeerIdentity = null;
let identityMismatch = false;

// ===============================
// REPLAY ATTACK PROTECTION
// ===============================

// Sequence number of outgoing messages
let outgoingSequence = 0;

// Sequence number of incoming messages
let incomingSequence = 0;

// Process incoming messages in order
let receiveQueue = Promise.resolve();

// Prevent simultaneous message encryption
let isSending = false;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const IDENTITY_DB_NAME = "SecureTalkIdentityDB";
const IDENTITY_DB_VERSION = 1;

// ===============================
// INDEXEDDB STORAGE
// ===============================

function openIdentityDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(
            IDENTITY_DB_NAME,
            IDENTITY_DB_VERSION
        );

        request.onupgradeneeded = () => {
            const db = request.result;

            if (!db.objectStoreNames.contains("identity")) {
                db.createObjectStore("identity", {
                    keyPath: "id"
                });
            }

            if (!db.objectStoreNames.contains("peerPins")) {
                db.createObjectStore("peerPins", {
                    keyPath: "roomId"
                });
            }
        };

        request.onsuccess = () => resolve(request.result);

        request.onerror = () => {
            reject(new Error("Could not open identity storage."));
        };
    });
}

function dbGet(db, storeName, key) {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(storeName, "readonly");

        const request = transaction
            .objectStore(storeName)
            .get(key);

        request.onsuccess = () => resolve(request.result);

        request.onerror = () => {
            reject(new Error("Could not read identity storage."));
        };
    });
}

function dbPut(db, storeName, value) {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(storeName, "readwrite");

        transaction.objectStore(storeName).put(value);

        transaction.oncomplete = () => resolve();

        transaction.onerror = () => {
            reject(new Error("Could not save identity information."));
        };

        transaction.onabort = () => {
            reject(new Error("Identity storage transaction was cancelled."));
        };
    });
}

// ===============================
// BASE64 HELPERS
// ===============================

function toBase64(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

function fromBase64(value) {
    const binary = atob(value);

    return Uint8Array.from(binary, char =>
        char.charCodeAt(0)
    );
}

function isValidBase64(value) {
    if (typeof value !== "string" || value.length === 0) {
        return false;
    }

    try {
        return toBase64(fromBase64(value)) === value;
    } catch {
        return false;
    }
}

// ===============================
// FINGERPRINT GENERATION
// ===============================

async function generateFingerprint(publicKeyBase64) {
    const publicKeyBytes = fromBase64(publicKeyBase64);

    const hash = await crypto.subtle.digest(
        "SHA-256",
        publicKeyBytes
    );

    const hashBytes = new Uint8Array(hash);

    const hex = Array.from(hashBytes)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();

    return hex.match(/.{1,4}/g).join(" ");
}

// ===============================
// LOAD OR CREATE PERSISTENT IDENTITY
// ===============================

async function initializeIdentity() {
    const db = await openIdentityDB();

    try {
        let record = await dbGet(db, "identity", "local");

        if (!record) {
            addSystemMessage(
                "Creating your SecureTalk identity for this browser..."
            );

            const newKeyPair = await crypto.subtle.generateKey(
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                false,
                ["sign", "verify"]
            );

            record = {
                id: "local",
                keyPair: newKeyPair,
                createdAt: new Date().toISOString()
            };

            await dbPut(db, "identity", record);
        }

        identityKeyPair = record.keyPair;

        const publicKeyBuffer = await crypto.subtle.exportKey(
            "raw",
            identityKeyPair.publicKey
        );

        identityPublicKeyBase64 = toBase64(
            new Uint8Array(publicKeyBuffer)
        );

        identityFingerprint = await generateFingerprint(
            identityPublicKeyBase64
        );

        myFingerprint.textContent = identityFingerprint;

        securityStatus.textContent = "Persistent identity ready";

        verifyFingerprintButton.disabled = true;

    } finally {
        db.close();
    }
}

// ===============================
// CREATE TEMPORARY ECDH KEY
// ===============================

async function generateSessionKey() {
    ephemeralKeyPair = await crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        false,
        ["deriveBits"]
    );

    const publicKeyBuffer = await crypto.subtle.exportKey(
        "raw",
        ephemeralKeyPair.publicKey
    );

    return toBase64(new Uint8Array(publicKeyBuffer));
}

// ===============================
// SIGN TEMPORARY SESSION KEY
// ===============================

async function signSessionKey(publicKeyBase64, roomId) {
    const message = encoder.encode(
        "SecureTalk-Session-v1|" +
        roomId +
        "|" +
        publicKeyBase64
    );

    const signature = await crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: "SHA-256"
        },
        identityKeyPair.privateKey,
        message
    );

    return toBase64(new Uint8Array(signature));
}

// ===============================
// VERIFY PEER IDENTITY SIGNATURE
// ===============================

async function verifyPeerSignature(data) {
    if (
        !data ||
        !isValidBase64(data.publicKey) ||
        !isValidBase64(data.identityPublicKey) ||
        !isValidBase64(data.signature)
    ) {
        throw new Error("Invalid peer key information.");
    }

    const sessionPublicBytes = fromBase64(data.publicKey);

    const identityPublicBytes = fromBase64(
        data.identityPublicKey
    );

    const signatureBytes = fromBase64(data.signature);

    if (
        sessionPublicBytes.length !== 65 ||
        sessionPublicBytes[0] !== 0x04 ||
        identityPublicBytes.length !== 65 ||
        identityPublicBytes[0] !== 0x04 ||
        signatureBytes.length !== 64
    ) {
        throw new Error("Invalid public key or signature format.");
    }

    const identityPublicKey = await crypto.subtle.importKey(
        "raw",
        identityPublicBytes,
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        false,
        ["verify"]
    );

    const signedMessage = encoder.encode(
        "SecureTalk-Session-v1|" +
        currentRoom +
        "|" +
        data.publicKey
    );

    const signatureIsValid = await crypto.subtle.verify(
        {
            name: "ECDSA",
            hash: "SHA-256"
        },
        identityPublicKey,
        signatureBytes,
        signedMessage
    );

    if (!signatureIsValid) {
        throw new Error(
            "Peer identity signature verification failed."
        );
    }

    return true;
}

// ===============================
// SAVED PEER IDENTITY
// ===============================

async function getSavedPeerPin(roomId) {
    const db = await openIdentityDB();

    try {
        return await dbGet(db, "peerPins", roomId);
    } finally {
        db.close();
    }
}

async function savePeerPin(roomId, fingerprint, publicKey) {
    const db = await openIdentityDB();

    try {
        await dbPut(db, "peerPins", {
            roomId,
            fingerprint,
            publicKey,
            verifiedAt: new Date().toISOString()
        });
    } finally {
        db.close();
    }
}

// ===============================
// DERIVE SHARED AES KEY
// ===============================

async function deriveSharedKey(publicKeyBase64) {
    const publicKeyBytes = fromBase64(publicKeyBase64);

    const peerPublicKey = await crypto.subtle.importKey(
        "raw",
        publicKeyBytes,
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        false,
        []
    );

    const sharedSecret = await crypto.subtle.deriveBits(
        {
            name: "ECDH",
            public: peerPublicKey
        },
        ephemeralKeyPair.privateKey,
        256
    );

    const hkdfKey = await crypto.subtle.importKey(
        "raw",
        sharedSecret,
        "HKDF",
        false,
        ["deriveKey"]
    );

    sharedKey = await crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: encoder.encode("SecureTalk-HKDF-Salt-v1"),
            info: encoder.encode(
                "SecureTalk-Chat-Key-v1|" + currentRoom
            )
        },
        hkdfKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

// ===============================
// PROCESS PEER PUBLIC KEY
// ===============================

async function processPeerKey(data) {
    if (!joinedRoom || peerKeyReceived) {
        return;
    }

    peerKeyReceived = true;
    peerVerified = false;
    sharedKey = null;
    pendingPeerIdentity = null;
    identityMismatch = false;

    try {
        await verifyPeerSignature(data);

        const fingerprint = await generateFingerprint(
            data.identityPublicKey
        );

        const savedPin = await getSavedPeerPin(currentRoom);

        pendingPeerIdentity = {
            fingerprint,
            publicKey: data.identityPublicKey
        };

        peerFingerprint.textContent = fingerprint;
        fingerprintCard.hidden = false;

        if (
            savedPin &&
            savedPin.fingerprint !== fingerprint
        ) {
            identityMismatch = true;

            verificationStatus.textContent =
                "WARNING: Peer identity has changed!";

            verifyFingerprintButton.disabled = true;

            peerStatus.textContent = "Identity mismatch";

            securityStatus.textContent =
                "Peer identity verification blocked";

            connectionStatus.textContent =
                "Do not trust this peer";

            addSystemMessage(
                "WARNING: The peer identity does not match the previously saved identity. Chat is blocked."
            );

            updateChatControls();
            return;
        }

        await deriveSharedKey(data.publicKey);

        if (savedPin && savedPin.fingerprint === fingerprint) {
            peerVerified = true;

            verificationStatus.textContent =
                "Previously verified identity recognized";

            verifyFingerprintButton.disabled = true;

            addSystemMessage(
                "Previously verified peer identity recognized."
            );

        } else {
            verificationStatus.textContent =
                "First-time verification required";

            verifyFingerprintButton.disabled = false;

            addSystemMessage(
                "Compare the peer identity fingerprint through a separate trusted channel before verifying."
            );
        }

        peerStatus.textContent = "Peer connected";

        securityStatus.textContent = peerVerified
            ? "Peer identity verified"
            : "Session key ready - verification required";

        connectionStatus.textContent = peerVerified
            ? "Chat ready"
            : "Verify peer identity";

        updateChatControls();

    } catch (error) {
        console.error("Peer verification failed:", error);

        sharedKey = null;
        peerVerified = false;
        pendingPeerIdentity = null;

        verificationStatus.textContent =
            "Identity verification failed";

        verifyFingerprintButton.disabled = true;

        securityStatus.textContent = "Key verification failed";
        connectionStatus.textContent = "Connection not trusted";

        addSystemMessage(
            "Peer identity could not be verified. Chat is blocked."
        );

        updateChatControls();
    }
}

// ===============================
// CHAT CONTROL
// ===============================

function updateChatControls() {
    const ready = Boolean(
        sharedKey &&
        peerVerified &&
        socket.connected &&
        joinedRoom
    );

    messageInput.disabled = !ready;
    sendButton.disabled = !ready || isSending;

    messageInput.placeholder = ready
        ? "Type your message..."
        : "Verify the peer identity first...";
}

// ===============================
// ENCRYPT MESSAGE WITH SEQUENCE
// ===============================

async function encryptMessage(message) {
    if (!sharedKey) {
        throw new Error("Encryption key is not ready.");
    }

    const sequence = outgoingSequence + 1;

    const iv = crypto.getRandomValues(
        new Uint8Array(12)
    );

    // Sequence number is included inside encrypted content
    const payload = JSON.stringify({
        sequence,
        message
    });

    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv
        },
        sharedKey,
        encoder.encode(payload)
    );

    return {
        iv: toBase64(iv),
        ciphertext: toBase64(
            new Uint8Array(encrypted)
        ),
        sequence
    };
}

// ===============================
// DECRYPT AND CHECK SEQUENCE
// ===============================

async function decryptMessage(
    ivBase64,
    ciphertextBase64,
    receivedSequence
) {
    if (!sharedKey) {
        throw new Error("Encryption key is not ready.");
    }

    const iv = fromBase64(ivBase64);
    const ciphertext = fromBase64(ciphertextBase64);

    if (iv.length !== 12) {
        throw new Error("Invalid message IV.");
    }

    if (
        !Number.isSafeInteger(receivedSequence) ||
        receivedSequence !== incomingSequence + 1
    ) {
        throw new Error(
            "Replay attack detected or invalid sequence."
        );
    }

    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv
        },
        sharedKey,
        ciphertext
    );

    const payload = JSON.parse(
        decoder.decode(decrypted)
    );

    if (
        payload.sequence !== receivedSequence ||
        typeof payload.message !== "string"
    ) {
        throw new Error("Invalid encrypted message payload.");
    }

    incomingSequence = receivedSequence;

    return payload.message;
}

// ===============================
// DISPLAY MESSAGES
// ===============================

function addMessage(message, type) {
    const row = document.createElement("div");

    row.className = `message-row ${type}`;

    const bubble = document.createElement("div");

    bubble.className = "message-bubble";

    const content = document.createElement("p");

    content.textContent = message;

    const time = document.createElement("span");

    time.className = "message-time";

    time.textContent = new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit"
    });

    bubble.appendChild(content);
    bubble.appendChild(time);

    row.appendChild(bubble);

    messagesArea.appendChild(row);

    messagesArea.scrollTop = messagesArea.scrollHeight;
}

function addSystemMessage(message) {
    const system = document.createElement("div");

    system.className = "system-message";

    system.textContent = message;

    messagesArea.appendChild(system);

    messagesArea.scrollTop = messagesArea.scrollHeight;
}

// ===============================
// MANUAL FIRST-TIME VERIFICATION
// ===============================

verifyFingerprintButton.addEventListener(
    "click",
    async () => {

        if (
            !sharedKey ||
            !pendingPeerIdentity ||
            identityMismatch ||
            !socket.connected
        ) {
            return;
        }

        try {
            await savePeerPin(
                currentRoom,
                pendingPeerIdentity.fingerprint,
                pendingPeerIdentity.publicKey
            );

            peerVerified = true;

            verificationStatus.textContent =
                "Identity verified and saved on this browser";

            verifyFingerprintButton.disabled = true;

            securityStatus.textContent = "Peer identity verified";

            connectionStatus.textContent = "Chat ready";

            chatSubtitle.textContent =
                `Room: ${currentRoom} - Identity verified`;

            updateChatControls();

            addSystemMessage(
                "Peer identity verification saved. Chat is now enabled."
            );

        } catch (error) {
            console.error(error);

            verificationStatus.textContent =
                "Could not save identity verification.";

            addSystemMessage(
                "Identity verification could not be saved."
            );
        }
    }
);

// ===============================
// JOIN ROOM
// ===============================

async function joinRoom(roomId, isReconnect = false) {
    if (!socket.connected || !identityKeyPair) {
        throw new Error("Server or identity is not ready.");
    }

    sharedKey = null;
    ephemeralKeyPair = null;

    peerKeyReceived = false;
    peerVerified = false;

    pendingPeerIdentity = null;
    identityMismatch = false;

    // Reset replay counters for the new encrypted session
    outgoingSequence = 0;
    incomingSequence = 0;

    // Clear pending incoming processing
    receiveQueue = Promise.resolve();

    fingerprintCard.hidden = true;

    verifyFingerprintButton.disabled = true;

    currentRoom = roomId;

    const sessionPublicKey = await generateSessionKey();

    const signature = await signSessionKey(
        sessionPublicKey,
        roomId
    );

    socket.emit("join-room", {
        roomId,
        publicKey: sessionPublicKey,
        identityPublicKey: identityPublicKeyBase64,
        signature
    });

    if (isReconnect) {
        addSystemMessage(
            "Reconnected to the server. Joining your room again..."
        );
    }

    updateChatControls();
}

// ===============================
// JOIN BUTTON
// ===============================

joinButton.disabled = true;

joinButton.textContent = "Loading identity...";

joinButton.addEventListener("click", async () => {
    const roomId = roomInput.value.trim();

    joinError.textContent = "";

    if (!/^[a-zA-Z0-9_-]{1,40}$/.test(roomId)) {
        joinError.textContent = "Enter a valid room ID.";
        return;
    }

    if (!socket.connected) {
        joinError.textContent = "Server is not connected.";
        return;
    }

    joinButton.disabled = true;

    joinButton.textContent = "Connecting...";

    try {
        await joinRoom(roomId);

    } catch (error) {
        console.error(error);

        joinError.textContent =
            "Could not join the room. Please try again.";

        joinButton.disabled = false;

        joinButton.textContent = "Join Secure Room";
    }
});

// ===============================
// ROOM JOINED
// ===============================

socket.on("room-joined", (data) => {
    joinedRoom = true;

    joinSection.hidden = true;

    messagesArea.hidden = false;

    messageForm.hidden = false;

    chatSubtitle.textContent = `Room: ${data.roomId}`;

    connectionStatus.textContent =
        "Waiting for second participant";

    peerStatus.textContent = "Waiting for peer";

    updateChatControls();

    addSystemMessage(
        "You joined the room. Waiting for another participant..."
    );
});

// ===============================
// RECEIVE PEER KEY
// ===============================

socket.on("peer-key", async (data) => {
    await processPeerKey(data);
});

// ===============================
// PEER DISCONNECTED
// ===============================

socket.on("peer-disconnected", (data) => {
    sharedKey = null;

    peerKeyReceived = false;
    peerVerified = false;

    pendingPeerIdentity = null;
    identityMismatch = false;

    outgoingSequence = 0;
    incomingSequence = 0;

    receiveQueue = Promise.resolve();

    fingerprintCard.hidden = true;

    verifyFingerprintButton.disabled = true;

    peerStatus.textContent = "Peer disconnected";

    securityStatus.textContent = "Waiting for peer";

    connectionStatus.textContent = "Peer disconnected";

    updateChatControls();

    addSystemMessage(
        data?.message || "Your peer disconnected."
    );
});

// ===============================
// SEND MESSAGE
// ===============================

messageForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const message = messageInput.value.trim();

    if (
        !message ||
        !sharedKey ||
        !peerVerified ||
        !currentRoom ||
        !joinedRoom ||
        isSending
    ) {
        return;
    }

    isSending = true;

    updateChatControls();

    try {
        const encryptedData = await encryptMessage(message);

        if (!sharedKey || !peerVerified || !joinedRoom) {
            throw new Error("Secure session is no longer active.");
        }

        socket.emit("encrypted-message", {
            roomId: currentRoom,
            iv: encryptedData.iv,
            ciphertext: encryptedData.ciphertext,
            sequence: encryptedData.sequence
        });

        outgoingSequence = encryptedData.sequence;

        addMessage(message, "sent");

        messageInput.value = "";

    } catch (error) {
        console.error("Encryption failed:", error);

        addSystemMessage(
            "Message could not be encrypted or sent."
        );

    } finally {
        isSending = false;

        updateChatControls();

        messageInput.focus();
    }
});

// ===============================
// RECEIVE MESSAGE
// ===============================

socket.on("encrypted-message", (data) => {

    // Queue messages so sequence checks happen in order
    receiveQueue = receiveQueue
        .then(async () => {

            if (!sharedKey || !peerVerified || !joinedRoom || !data) {
                return;
            }

            const message = await decryptMessage(
                data.iv,
                data.ciphertext,
                data.sequence
            );

            addMessage(message, "received");

        })
        .catch(error => {

            console.error(
                "Message verification/decryption failed:",
                error
            );

            addSystemMessage(
                "Message rejected: invalid sequence, replay attempt, or decryption failure."
            );
        });
});

// ===============================
// SERVER ERROR
// ===============================

socket.on("chat-error", (message) => {
    joinError.textContent = message;

    if (joinedRoom) {
        addSystemMessage(message);
    } else {
        joinButton.disabled = false;

        joinButton.textContent = "Join Secure Room";
    }
});

// ===============================
// SERVER CONNECTION
// ===============================

socket.on("connect", async () => {
    securityStatus.textContent = "Server connected";

    updateChatControls();

    if (shouldRejoin && currentRoom && identityKeyPair) {
        shouldRejoin = false;

        try {
            await joinRoom(currentRoom, true);

        } catch (error) {
            console.error("Reconnection failed:", error);

            addSystemMessage(
                "Automatic room reconnection failed. Please refresh."
            );
        }
    }
});

// ===============================
// SERVER DISCONNECTION
// ===============================

socket.on("disconnect", () => {
    shouldRejoin = Boolean(currentRoom);

    joinedRoom = false;

    sharedKey = null;
    ephemeralKeyPair = null;

    peerKeyReceived = false;
    peerVerified = false;

    pendingPeerIdentity = null;
    identityMismatch = false;

    outgoingSequence = 0;
    incomingSequence = 0;

    receiveQueue = Promise.resolve();

    fingerprintCard.hidden = true;

    verifyFingerprintButton.disabled = true;

    securityStatus.textContent = "Server disconnected";

    connectionStatus.textContent = "Connection lost";

    peerStatus.textContent = "Disconnected";

    updateChatControls();

    addSystemMessage(
        "Server connection lost. Waiting to reconnect..."
    );
});

socket.on("connect_error", (error) => {
    console.error("Connection error:", error);

    securityStatus.textContent = "Connection error";
});

// ===============================
// INITIALIZE APPLICATION
// ===============================

async function startSecureTalk() {
    try {
        if (!window.crypto?.subtle || !window.indexedDB) {
            throw new Error(
                "This browser does not support the required security features."
            );
        }

        await initializeIdentity();

        joinButton.disabled = false;

        joinButton.textContent = "Join Secure Room";

        addSystemMessage(
            "Persistent SecureTalk identity loaded successfully."
        );

    } catch (error) {
        console.error("Initialization failed:", error);

        joinButton.disabled = true;

        securityStatus.textContent =
            "Identity initialization failed";

        joinError.textContent =
            "SecureTalk could not initialize identity storage. Use a supported browser and try again.";
    }

    updateChatControls();
}

startSecureTalk();
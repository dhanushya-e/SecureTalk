const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    maxHttpBufferSize: 30 * 1024
});

const PORT = 3000;

const rooms = new Map();

const MAX_ROOM_SIZE = 2;
const MAX_MESSAGE_SIZE = 20000;
const MAX_REQUESTS_PER_MINUTE = 60;

app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (req, res) => {
    res.json({
        status: "SecureTalk server is running",
        timestamp: new Date().toISOString()
    });
});

// Base64 validation
function isValidBase64(value) {
    if (typeof value !== "string" || value.length === 0) {
        return false;
    }

    try {
        const decoded = Buffer.from(value, "base64");

        return (
            decoded.length > 0 &&
            decoded.toString("base64") === value
        );
    } catch {
        return false;
    }
}

// P-256 public key validation
function isValidPublicKey(value) {
    if (!isValidBase64(value)) return false;

    const decoded = Buffer.from(value, "base64");

    return decoded.length === 65 && decoded[0] === 0x04;
}

// ECDSA signature validation
function isValidSignature(value) {
    if (!isValidBase64(value)) return false;

    return Buffer.from(value, "base64").length === 64;
}

// AES-GCM IV validation
function isValidIV(value) {
    if (!isValidBase64(value)) return false;

    return Buffer.from(value, "base64").length === 12;
}

// Ciphertext validation
function isValidCiphertext(value) {
    if (
        !isValidBase64(value) ||
        value.length > MAX_MESSAGE_SIZE
    ) {
        return false;
    }

    return Buffer.from(value, "base64").length >= 16;
}

// Rate limiting
function checkRateLimit(socket) {
    const now = Date.now();

    if (!socket.data.rateLimit) {
        socket.data.rateLimit = {
            count: 1,
            startTime: now
        };

        return true;
    }

    const rate = socket.data.rateLimit;

    if (now - rate.startTime >= 60000) {
        rate.count = 1;
        rate.startTime = now;
        return true;
    }

    rate.count++;

    return rate.count <= MAX_REQUESTS_PER_MINUTE;
}

// Remove participant from room
function removeFromRoom(socket) {
    const roomId = socket.data.roomId;

    if (!roomId || !rooms.has(roomId)) {
        return;
    }

    const members = rooms.get(roomId);

    socket.to(roomId).emit("peer-disconnected", {
        message: "Your peer disconnected."
    });

    members.delete(socket.id);
    socket.leave(roomId);

    if (members.size === 0) {
        rooms.delete(roomId);
    }

    socket.data.roomId = null;
    socket.data.publicKey = null;
    socket.data.identityPublicKey = null;
    socket.data.signature = null;
    socket.data.lastSentSequence = 0;
}

io.on("connection", (socket) => {

    console.log("User connected:", socket.id);

    // JOIN ROOM
    socket.on("join-room", (data) => {

        if (!checkRateLimit(socket)) {
            socket.emit("chat-error", "Too many requests.");
            return;
        }

        if (
            !data ||
            typeof data.roomId !== "string" ||
            !/^[a-zA-Z0-9_-]{1,40}$/.test(data.roomId) ||
            !isValidPublicKey(data.publicKey) ||
            !isValidPublicKey(data.identityPublicKey) ||
            !isValidSignature(data.signature)
        ) {
            socket.emit(
                "chat-error",
                "Invalid room or identity information."
            );
            return;
        }

        if (socket.data.roomId) {
            socket.emit(
                "chat-error",
                "You have already joined a room."
            );
            return;
        }

        const {
            roomId,
            publicKey,
            identityPublicKey,
            signature
        } = data;

        let members = rooms.get(roomId);

        if (!members) {
            members = new Set();
            rooms.set(roomId, members);
        }

        if (members.size >= MAX_ROOM_SIZE) {
            socket.emit("chat-error", "Room is full.");
            return;
        }

        socket.join(roomId);
        members.add(socket.id);

        socket.data.roomId = roomId;
        socket.data.publicKey = publicKey;
        socket.data.identityPublicKey = identityPublicKey;
        socket.data.signature = signature;

        // Replay protection: reset sequence for new session
        socket.data.lastSentSequence = 0;

        socket.emit("room-joined", { roomId });

        // Send new participant information
        socket.to(roomId).emit("peer-key", {
            publicKey,
            identityPublicKey,
            signature
        });

        // Send existing participant information
        for (const memberId of members) {

            if (memberId === socket.id) continue;

            const peerSocket = io.sockets.sockets.get(memberId);

            if (peerSocket) {
                socket.emit("peer-key", {
                    publicKey: peerSocket.data.publicKey,
                    identityPublicKey:
                        peerSocket.data.identityPublicKey,
                    signature: peerSocket.data.signature
                });
            }
        }

        console.log(`User joined room: ${roomId}`);
    });

    // ENCRYPTED MESSAGE WITH REPLAY PROTECTION
    socket.on("encrypted-message", (data) => {

        if (!checkRateLimit(socket)) {
            socket.emit(
                "chat-error",
                "Message rate limit exceeded."
            );
            return;
        }

        if (!data || !socket.data.roomId) {
            socket.emit("chat-error", "You are not in a room.");
            return;
        }

        const { roomId, iv, ciphertext, sequence } = data;

        if (
            roomId !== socket.data.roomId ||
            !isValidIV(iv) ||
            !isValidCiphertext(ciphertext) ||
            !Number.isSafeInteger(sequence) ||
            sequence < 1
        ) {
            socket.emit(
                "chat-error",
                "Invalid encrypted message."
            );
            return;
        }

        // Reject duplicate, old, or out-of-order messages
        if (sequence !== socket.data.lastSentSequence + 1) {
            socket.emit(
                "chat-error",
                "Replay or invalid sequence detected. Message rejected."
            );

            console.log(
                `Rejected sequence ${sequence} from ${socket.id}`
            );

            return;
        }

        const members = rooms.get(roomId);

        if (!members || members.size !== 2) {
            socket.emit(
                "chat-error",
                "Your peer is not connected."
            );
            return;
        }

        // Save sequence only after validation
        socket.data.lastSentSequence = sequence;

        // Forward encrypted message only
        socket.to(roomId).emit("encrypted-message", {
            iv,
            ciphertext,
            sequence
        });

        console.log(
            `Message sequence ${sequence} forwarded.`
        );
    });

    // LEAVE ROOM
    socket.on("leave-room", () => {
        removeFromRoom(socket);
        console.log("User left room:", socket.id);
    });

    // DISCONNECT
    socket.on("disconnect", () => {
        removeFromRoom(socket);
        console.log("User disconnected:", socket.id);
    });

});

// START SERVER
server.listen(PORT, () => {
    console.log("--------------------------------");
    console.log("       SECURETALK SERVER");
    console.log("--------------------------------");
    console.log(`Server: http://localhost:${PORT}`);
    console.log(`Port: ${PORT}`);
    console.log("Replay protection: Enabled");
    console.log("Status: Running");
    console.log("--------------------------------");
});
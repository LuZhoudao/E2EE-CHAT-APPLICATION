// Define global variables for storing keys
console.log("ecdh.js is loaded");

let sharedSecret;
const derivedKeys = {};

// Function to generate an ECDH key pair using P-384 curve
async function generateKeyPair() {
    return window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-384",
        },
        true,
        ["deriveKey", "deriveBits"]
    );
}

// Function to export a public key to a sharable format
async function exportPublicKey(key) {
    return window.crypto.subtle.exportKey("raw", key);
}

// Function to import a public key from a shared format
async function importPublicKey(rawKey) {
    return window.crypto.subtle.importKey(
        "raw",
        rawKey,
        {
            name: "ECDH",
            namedCurve: "P-384"
        },
        true,
        []
    );
}

// Placeholder function for sending the public key to the server
// Implement actual AJAX/Fetch request to your Flask endpoint
async function sendPublicKeyToServer(userId, publicKey) {
    // Example: POST request to Flask server
}

// Placeholder function for getting the other user's public key from the server
// Implement actual AJAX/Fetch request to your Flask endpoint
async function getOtherPublicKeyFromServer(otherUserId) {
    // Example: GET request to Flask server
}

// Function to derive the shared secret using your private key and the other user's public key
async function deriveSharedSecret(yourPrivateKey, othersPublicKey) {
    const importedPublicKey = await importPublicKey(othersPublicKey);
    return window.crypto.subtle.deriveBits(
        {
            name: "ECDH",
            public: importedPublicKey
        },
        yourPrivateKey,
        384 // Length in bits
    );
}

// Function to derive encryption and MAC keys from the shared secret using HKDF
async function deriveEncryptionAndMacKeys(sharedSecret, salt, infoPrefix) {
    // Derive a key for encryption
    const encryptionKey = await window.crypto.subtle.deriveKey(
        {
            name: "HKDF",
            salt: salt,
            info: new TextEncoder().encode(infoPrefix + "_ENCRYPTION"),
            hash: "SHA-256"
        },
        await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            {name: "HKDF"},
            false,
            ["deriveKey"]
        ),
        {name: "AES-GCM", length: 256},
        true,
        ["encrypt", "decrypt"]
    );

    // Derive a key for MAC
    const macKey = await window.crypto.subtle.deriveKey(
        {
            name: "HKDF",
            salt: salt,
            info: new TextEncoder().encode(infoPrefix + "_MAC"),
            hash: "SHA-256"
        },
        await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            {name: "HKDF"},
            false,
            ["deriveKey"]
        ),
        {name: "HMAC", hash: "SHA-256"},
        true,
        ["sign", "verify"]
    );

    return { encryptionKey, macKey };
}

// start the ECDH key exchange and key derivation process
async function startKeyExchange(yourUserId, otherUserId) {
    // Generate key pair and export the public key
    console.log("Starting key exchange...");
    const yourKeyPair = await generateKeyPair();
    const exportedPublicKey = await exportPublicKey(yourKeyPair.publicKey);

    // Send your public key to the server and retrieve the other user's public key
    await sendPublicKeyToServer(yourUserId, exportedPublicKey);
    const othersExportedPublicKey = await getOtherPublicKeyFromServer(otherUserId);

    // Derive the shared secret
    sharedSecret = await deriveSharedSecret(yourKeyPair.privateKey, othersExportedPublicKey);

    // Example salt and info for key derivation
    const salt = window.crypto.getRandomValues(new Uint8Array(16)); // Example salt, should be unique for each derivation
    const infoPrefix = `CHAT_KEY_${yourUserId}to${otherUserId}`;

    // Derive encryption and MAC keys from the shared secret
    derivedKeys[otherUserId] = await deriveEncryptionAndMacKeys(sharedSecret, salt, infoPrefix);

    console.log("Keys derived successfully", derivedKeys[otherUserId]);
}

// Example: Expose the startKeyExchange function to be callable from the global scope for testing
window.startKeyExchange = startKeyExchange;


async function generateAndSetPublicKey() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-384"
        },
        true, 
        ["deriveKey", "deriveBits"] // can only be used to derive bits or keys
    );

    const exportedPublicKey = await window.crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
    );

    // Convert the exported key to a Base64 URL string to send to the server
    const exportedAsBase64 = window.btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));
    document.getElementById('publicKey').value = exportedAsBase64;

    // Now, submit the form
    document.getElementById('registrationForm').submit();
}

document.getElementById('registrationForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent the form from submitting immediately
    generateAndSetPublicKey();
});

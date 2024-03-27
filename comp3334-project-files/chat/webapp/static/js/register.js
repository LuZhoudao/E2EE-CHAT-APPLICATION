
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

function validateInputClientSide(form) {
    
    /**
     * Client-side input validation. Return true if all inputs are valid, false otherwise
     */

    const username = form.elements['username'].value;
    const password = form.elements['password'].value;
    const securityAnswer = form.elements['securityAnswer'].value;
    const memorizedSecret = form.elements['memorizedSecret'].value;

    // Check for empty fields
    if (!username || !password || !securityAnswer || !memorizedSecret) {
        alert('All fields are required.');
        return false;
    }

    const n = 3
    // Check for minimum length
    if (username.length < n || password.length < n || securityAnswer.length < n || memorizedSecret.length < n) {
        alert(`All fields should be at least ${n} characters long.`);
        return false;
    }

    // Check that password and memorizedSecret are different
    if (password == memorizedSecret) {
        alert('Password and Memorized Secret must be different.');
        return false;
    }

    // If all checks pass, return true
    return true;

}


document.getElementById('registrationForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent the form from submitting immediately

    // Input Validation
    form = event.target;
    
    clientSideValidation = validateInputClientSide(form); // Client-side input validation
    
    if (!clientSideValidation) { 
        return;
    }

    // Server feels safe for SQL Injection and XSS because of prepared statements??
    
    generateAndSetPublicKey();

});

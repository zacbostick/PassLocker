let masterPassword = '';

async function deriveKey(password) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode("some-salt"),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encrypt(data, key) {
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        enc.encode(JSON.stringify(data))
    );
    return btoa(String.fromCharCode.apply(null, new Uint8Array(iv))) + 
           btoa(String.fromCharCode.apply(null, new Uint8Array(encrypted)));
}

async function decrypt(encryptedData, key) {
    const dec = new TextDecoder();
    const iv = Uint8Array.from(atob(encryptedData.slice(0, 16)), c => c.charCodeAt(0));
    const data = Uint8Array.from(atob(encryptedData.slice(16)), c => c.charCodeAt(0));
    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        data
    );
    return JSON.parse(dec.decode(decrypted));
}

async function checkLoginStatus() {
    try {
        const { masterPasswordHash, isLoggedIn, encryptedMasterPassword } = await chrome.storage.local.get(['masterPasswordHash', 'isLoggedIn', 'encryptedMasterPassword']);
        console.log('Retrieved data:', { masterPasswordHash: !!masterPasswordHash, isLoggedIn, encryptedMasterPassword: !!encryptedMasterPassword });

        if (masterPasswordHash) {
            if (isLoggedIn && encryptedMasterPassword) {
                document.getElementById('login-section').style.display = 'none';
                document.getElementById('main-section').style.display = 'block';
                document.getElementById('setup-section').style.display = 'none';
                
                try {
                    const key = await deriveKey(masterPasswordHash);
                    masterPassword = await decrypt(encryptedMasterPassword, key);
                    console.log('Master password decrypted successfully');
                    displayPasswords();
                } catch (decryptError) {
                    console.error('Error decrypting master password:', decryptError);
                    await chrome.storage.local.set({ isLoggedIn: false });
                    document.getElementById('login-section').style.display = 'block';
                    document.getElementById('main-section').style.display = 'none';
                    alert('Session expired. Please log in again.');
                }
            } else {
                document.getElementById('login-section').style.display = 'block';
                document.getElementById('main-section').style.display = 'none';
                document.getElementById('setup-section').style.display = 'none';
            }
        } else {
            document.getElementById('setup-section').style.display = 'block';
            document.getElementById('login-section').style.display = 'none';
            document.getElementById('main-section').style.display = 'none';
        }
    } catch (error) {
        console.error('Error in checkLoginStatus:', error);
        alert('An error occurred while checking login status. Please check the console for more details.');
    }
}

document.getElementById('create-master-password').addEventListener('click', async () => {
    try {
        const newPassword = document.getElementById('new-master-password').value;
        const confirmPassword = document.getElementById('confirm-master-password').value;

        if (newPassword !== confirmPassword) {
            alert('Passwords do not match');
            return;
        }

        const key = await deriveKey(newPassword);
        const masterPasswordHash = await encrypt('test', key);
        const encryptedMasterPassword = await encrypt(newPassword, key);

        await chrome.storage.local.set({ masterPasswordHash, encryptedMasterPassword, isLoggedIn: true });
        console.log('Master password created and stored successfully');
        
        masterPassword = newPassword;
        document.getElementById('setup-section').style.display = 'none';
        document.getElementById('main-section').style.display = 'block';
        displayPasswords();
    } catch (error) {
        console.error('Error creating master password:', error);
        alert('An error occurred while creating the master password. Please check the console for more details.');
    }
});

document.getElementById('login-button').addEventListener('click', async () => {
    const enteredPassword = document.getElementById('master-password').value;
    try {
        const { masterPasswordHash } = await chrome.storage.local.get('masterPasswordHash');
        const key = await deriveKey(enteredPassword);

        await decrypt(masterPasswordHash, key);
        
        const encryptedMasterPassword = await encrypt(enteredPassword, key);
        await chrome.storage.local.set({ isLoggedIn: true, encryptedMasterPassword });
        
        masterPassword = enteredPassword;
        document.getElementById('login-section').style.display = 'none';
        document.getElementById('main-section').style.display = 'block';
        displayPasswords();
    } catch (error) {
        console.error('Login error:', error);
        alert('Incorrect master password');
    }
});

document.getElementById('add-password').addEventListener('click', async () => {
    const site = prompt("Enter site:");
    const username = prompt("Enter username:");
    const password = prompt("Enter password:");

    if (!site || !username || !password) {
        alert('Please fill in all fields');
        return;
    }

    try {
        const key = await deriveKey(masterPassword);
        const encryptedData = await encrypt({ site, username, password }, key);

        const { passwords } = await chrome.storage.local.get('passwords');
        const updatedPasswords = passwords ? [...passwords, encryptedData] : [encryptedData];
        await chrome.storage.local.set({ passwords: updatedPasswords });
        
        console.log('Password saved successfully');
        alert('Password saved!');
        displayPasswords();
    } catch (error) {
        console.error('Error saving password:', error);
        alert('Error saving password. Please try again.');
    }
});

async function displayPasswords() {
    try {
        const key = await deriveKey(masterPassword);
        const { passwords } = await chrome.storage.local.get('passwords');
        const passwordList = document.getElementById('password-list');
        passwordList.innerHTML = '';

        console.log('Number of encrypted passwords:', passwords ? passwords.length : 0);

        if (!passwords || passwords.length === 0) {
            passwordList.innerHTML = '<p>No passwords saved yet.</p>';
            return;
        }

        for (const encryptedData of passwords) {
            try {
                const { site, username, password } = await decrypt(encryptedData, key);
                const div = document.createElement('div');
                div.className = 'password-item';
                div.innerHTML = `
                    <strong>${site}</strong><br>
                    Username: ${username}<br>
                    Password: <span class="password-text">Click to show</span>
                    <button class="copy-button">Copy</button>
                `;
                
                const passwordText = div.querySelector('.password-text');
                const copyButton = div.querySelector('.copy-button');
                
                passwordText.addEventListener('click', () => {
                    passwordText.textContent = passwordText.textContent === 'Click to show' ? password : 'Click to show';
                });
                
                copyButton.addEventListener('click', () => {
                    navigator.clipboard.writeText(password).then(() => {
                        alert('Password copied to clipboard');
                    });
                });
                
                passwordList.appendChild(div);
            } catch (error) {
                console.error('Decryption failed:', error);
            }
        }
    } catch (error) {
        console.error('Error displaying passwords:', error);
    }
}

document.getElementById('view-raw-data').addEventListener('click', async () => {
    const { passwords } = await chrome.storage.local.get('passwords');
    console.log('Raw stored data:', passwords);
    alert('Raw data logged to console. Check the developer tools.');
});

document.getElementById('logout').addEventListener('click', async () => {
    masterPassword = '';
    await chrome.storage.local.set({ isLoggedIn: false });
    document.getElementById('main-section').style.display = 'none';
    document.getElementById('login-section').style.display = 'block';
    document.getElementById('master-password').value = '';
});

document.addEventListener('DOMContentLoaded', checkLoginStatus);

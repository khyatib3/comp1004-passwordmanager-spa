//global variables
/**
 *
 */
let userIDHash = "";
/**
 *
 */
let masterKey = null;


//aes gcm encryption
/**
 *
 */
async function aesEncrypt(plaintext, key) {
    //using an initialisation vector
    const initialisationVector = crypto.getRandomValues(new Uint8Array(12));
    const encoded = strToUint8(plaintext);

    const cipherText = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: initialisationVector
        },
        key,
        encoded
    );

    return {
        cipherText: new Uint8Array(cipherText),
        iv: initialisationVector
    };

}

//aes gcm decryption
/**
 *
 */
async function aesDecrypt(cipherText, key, initialisationVector) {
    const plainText = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: initialisationVector
        },
        key,
        cipherText
    );

    //return the password
    return uint8ToStr(new Uint8Array(plainText));

}

//example usage below for testing and understanding purposes
(async () => {
    const key = await makeMasterKey("helloWorld");
    const message = "Hello, all!";
    console.log("original:", message);

    const {cipherText, iv} = await aesEncrypt(message, key);
    console.log("Encrypted:", cipherText);
    const decrypted = await aesDecrypt(cipherText, key, iv);
    console.log("decrypted:", decrypted);

})();

/**
 *
 */
function strToUint8(string) {
    return new TextEncoder().encode(string);
}

/**
 *
 */
function uint8ToStr(array) {
    return new TextDecoder().decode(array);
}

//making masterKey to from userId+password hash
/**
 *
 */
async function makeMasterKey(myString) {
    // const salt = crypto.getRandomValues(new Uint8Array(16));
    const salt = new TextEncoder().encode("saltToMakeTastey");
    const encoder = new TextEncoder();
    const initialKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(myString),
        {name: "PBKDF2"},
        false,
        ["deriveKey"]
    );

    //deriving key using PBKDF2
    const finalKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt, // random salt that is stored along with cipherText
            iterations: 100000,
            hash: "SHA-256",
        },
        initialKey,
        {
            name: "AES-GCM", length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
    return finalKey;
}

//function to show the relevant section when needed, so all sections don't get displayed automatically
/**
 *
 */
function showSection(sectionId) {
    //hiding all the sections
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    })


    //then showing the selected section
    let selectedSection = document.getElementById(sectionId);
    if (selectedSection) {
        selectedSection.classList.add('active');
    } else {
        console.error("Couldn't find section:", sectionId);
    }
}

//function which is used for hashing usernames and passwords
//will be used to make the masterKey
/**
 *
 */
async function hash(value) {
    const encoder = new TextEncoder();
    const data = encoder.encode(value);
    const hashedValue = await crypto.subtle.digest('SHA-256', data);


    let hashedStringValue = Array.from(new Uint8Array(hashedValue))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    //to test
    console.log(hashedStringValue);

    //return
    return hashedStringValue;
}


//method that checks whether the suer has logged into PH before they choose to see accounts.
//ensures security
/**
 *
 */
function checkUserLoggedIn(sectionId) {
    let userLoggedIn = localStorage.getItem("loggedIn");
    if (userLoggedIn !== "true") {
        alert("You must login to PasswordHaven first!");
        //only show them home section so they either sign up or log in
        showSection("home");
        return;
    }

    showSection(sectionId);
}

//PasswordHaven click
function home() {
    let userLoggedIn = localStorage.getItem("loggedIn");
    if (userLoggedIn === "true") {
        showSection("homeSectionPostLogin");
    } else {
        showSection("home");
        return;
    }
}

function uint8ToBase64(uint8array) {
    let binary = '';
    uint8array.forEach((b) => binary += String.fromCharCode(b));
    return window.btoa(binary);
}

function base64ToUint8(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 *
 */
function readFromLocalStorage(readItem) {
    return JSON.parse(localStorage.getItem(readItem.toString()));
}

/**
 *
 */
function writeToLocalStorage(key, value) {
    localStorage.setItem(key, JSON.stringify(value));
}

/**
 *
 */
async function protectedReadFromLocalStorage(key, index) {
    let accountData = localStorage.getItem(key);
    let sensitiveData = JSON.parse(accountData);
    let account = sensitiveData[index];
    let ct = base64ToUint8(account.password.cipherText);
    let iv = base64ToUint8(account.password.iv);
    let decryptedValue = await aesDecrypt(ct, masterKey, iv);
    return decryptedValue;
}

/**
 *
 */
function protectedWriteToLocalStorage(key, value) {
    aesEncrypt(value, masterKey).then((encValue, iv) => {
        let sensitiveData = {encValue, iv};
        localStorage.setItem(key, JSON.stringify(sensitiveData));
    });

}

/**
 *
 */
function displayPasswordStrength() {
    let password = document.getElementById("password").value;
    let indicator = document.getElementById("passwordStrengthIndicator");
    let strengthBar = document.getElementById("passwordStrengthBar");
    let passwordStrength = calculatePasswordStrength(password);

    let width = 0;
    let colour = "red";
    if (passwordStrength === "Weak") {
        width = 30;
        colour = "red";
        indicator.innerText = "You should make it longer and add more numbers, special characters and capitals!";
        indicator.classList.add("text-danger");
    } else if (passwordStrength === "Medium") {
        width = 60;
        colour = "orange";
        indicator.innerText = "Try adding more characters, and add a few numbers!";
        indicator.classList.remove("text-danger");
        indicator.classList.add("text-warning");
    } else if (passwordStrength === "Strong") {
        width = 100;
        colour = "green";
        indicator.innerText = "Perfect! This is a strong password to use.";
        indicator.classList.remove("text-warning");
        indicator.classList.add("text-success");
    }

    //applying the styles
    strengthBar.style.width = width + "%";
    strengthBar.style.backgroundColor = colour;

}

/**
 *
 */
function calculatePasswordStrength(password) {
    //creating a strength 'score'
    let strengthScore = 0;

    //checking length of password
    if (password.length === 0) { // if they typed nothing
        return "Weak";
    }
    if (password.length >= 2 && password.length <= 7) {
        strengthScore += 1;
    } else if (password.length >= 8) {
        strengthScore += 2;
    }

    //checking for uppercase characters
    let hasUpperCase = /[A-Z]/.test(password) ? 1 : 0;

    //checking for lowercase characters
    let hasLowerCase = /[a-z]/.test(password) ? 1 : 0;

    //checking for numbers
    let hasNumbers = /[0-9]/.test(password) ? 1 : 0;

    //checking for special chars
    let hasSpecialCharacters = /[!"£$%^&*()_+-={}[]:@~#<>?]/.test(password) ? 1 : 0;

    strengthScore = strengthScore + hasSpecialCharacters + hasNumbers + hasLowerCase + hasUpperCase;

    if (strengthScore <= 2) {
        return "Weak";
    } else if (strengthScore > 2 && strengthScore <= 4) {
        return "Medium"
    } else {
        return "Strong";
    }
}

//toggling between password and confirm password input fields visibility
document.addEventListener("DOMContentLoaded", function () {
    const togglePassword = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password');

    const toggleConfirmPassword = document.getElementById('toggleConfirmPassword');
    const confirmPasswordInput = document.getElementById('confirmPassword');

    togglePassword.addEventListener('click', function () {
        const icon = this.querySelector('i');
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        icon.classList.toggle('bi-eye');
        icon.classList.toggle('bi-eye-slash');
    });

    toggleConfirmPassword.addEventListener('click', function () {
        const icon = this.querySelector('i');
        const type = confirmPasswordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        confirmPasswordInput.setAttribute('type', type);
        icon.classList.toggle('bi-eye');
        icon.classList.toggle('bi-eye-slash');
    });
});

//live message display for confirm password input against password input
document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("confirmPassword").addEventListener("input", function () {
        let password = document.getElementById("password").value;
        let confirmPassword = this.value;
        let confirmMsg = document.getElementById("confirmPasswordMsg");

        if (confirmPassword === "") {
            confirmMsg.innerText = "No password detected!";
            confirmMsg.classList.add("text-warning");
        } else if (confirmPassword === password) {
            confirmMsg.innerText = "Passwords match!";
            confirmMsg.classList.remove("text-danger");
            confirmMsg.classList.remove("text-warning");
            confirmMsg.classList.add("text-success");
        } else {
            confirmMsg.innerText = "Passwords do not match! Please try again!";
            confirmMsg.classList.remove("text-success");
            confirmMsg.classList.remove("text-warning");
            confirmMsg.classList.add("text-danger");
        }

    });
});

//to show the logout option
function showLogoutOption() {
    document.getElementById('logoutId').style.display = 'block';
}

//to hide the logout option
function hideLogoutOption() {
    document.getElementById('logoutId').style.display = 'none';
    checkUserLoggedIn('homeSectionPostLogin');
}

class User {
    constructor(username, password) {
        this.username = username;
        this.password = password; // Store hashed password
    }

    //adding user to local storage
    static async saveUser(username, password) {
        userIDHash = await hash(username);
        let hashedFromLocalStorage = readFromLocalStorage(userIDHash);
        if (hashedFromLocalStorage !== null) {
            alert("An account already exists. Please login!")
            return false;
        } else {
            let hashedPassword = await hash(password);

            // adding the user to local storage
            writeToLocalStorage(userIDHash, hashedPassword);

            //creating the master key by hashing a combination of username and password
            masterKey = await makeMasterKey(hash(username + password));
            return true;
        }
    }

    //retrieving the user's details from local storage
    static getUser(userIDHash) {
        let userInfo = localStorage.getItem(userIDHash);
        return userInfo ? JSON.parse(userInfo) : null;
    }

    //checking if login details match entered details
    static async login(username, inputPassword) {
        userIDHash = await hash(username);
        let hashedPasswordFromLocalStorage = readFromLocalStorage(userIDHash);
        if (hashedPasswordFromLocalStorage == null) {
            return false;
        } else {
            let computedHashedPassword = await hash(inputPassword);
            if (computedHashedPassword === hashedPasswordFromLocalStorage) {
                masterKey = await makeMasterKey(hash(username + inputPassword));
                return true;
            }
        }
    }

    //method which handles the user signing up to password haven
    static handleSignUp() {
        //retrieving the email and password used in the fields
        let username = document.getElementById('signUpEmail').value;
        let password = document.getElementById('signUpPassword').value;
        let signUpMsg = document.getElementById('signUpMsg');

        //in the case that the user doesn't fill in all the fields
        if (username === '' || password === '') {
            signUpMsg.innerText = '⚠️ Please fill out all the details!';
            signUpMsg.classList.remove('text-success');
            signUpMsg.classList.add('text-danger');
            return;
        }

        User.saveUser(username, password).then(result => {
            if (result) {
                //changing the sign-up message to notify the user
                signUpMsg.innerText = '✅Your account was created successfully! Please login now!';
                signUpMsg.classList.remove('text-danger');
                signUpMsg.classList.add('text-success');

                //clearing the input fields after successful creation
                document.getElementById('signUpEmail').value = "";
                document.getElementById('signUpPassword').value = "";

                // //closing the modal afterward
                // setTimeout(()=>{
                //     let signUpModal = new bootstrap.Modal(document.getElementById('createPHAccountModal'));
                //     if (signUpModal) {
                //         signUpModal.hide();
                //     }
                // }, 1000); //close after 1 second

            } else {
                signUpMsg.innerText = "⚠️ Your account with us already exists! Please login.";
                signUpMsg.classList.remove('text-success');
                signUpMsg.classList.add('text-danger');
            }
        });
    }

    //function that deals with user logging into password haven
    static async handleLogin() {
        let email = document.getElementById('loginEmail').value;
        let password = document.getElementById('loginPassword').value;
        let loginMsg = document.getElementById('loginMsg');
        let modal = document.getElementById('loginModal');

        let detailsMatch = await User.login(email, password);
        if (detailsMatch) {
            localStorage.setItem("loggedIn", "true");
            bootstrap.Modal.getOrCreateInstance(document.getElementById('loginModal')).hide();
            checkUserLoggedIn('homeSectionPostLogin');
            showLogoutOption();

        } else {
            loginMsg.innerHTML = " ❌ Invalid details entered!";
        }
    }

    static handleLogout() {
        // let currentUser = User.getUser(userIDHash);
        // currentUser.
    }
}

/**
 *
 */
class PasswordManager {
    //function to retrieve the accounts from localStorage
    static getAccounts() {
        return JSON.parse(localStorage.getItem(userIDHash + "-accounts")) || [];
    }

    //adding account to local storage method
    static addAccount() {
        let site = document.getElementById('nickname').value;
        let url = document.getElementById('url').value;
        let username = document.getElementById('username').value;
        let password = document.getElementById('password').value;
        let confirmPassword = document.getElementById('confirmPassword').value;
        let accountAddMsg = document.getElementById('accountAddMsg');

        //checking if that account already exists
        let accounts = PasswordManager.getAccounts();
        let accountExists = accounts.some(account => account.site === site && account.username === username && account.password === password);
        if (accountExists) {
            accountAddMsg.innerText = "⚠️This account already exists in the password manager! You can find it in 'View Accounts'.";
            accountAddMsg.classList.remove('text-success');
            accountAddMsg.classList.add('text-danger');
        } else {
            PasswordManager.saveSiteAccountDetails(site, url, username, password)
            checkUserLoggedIn('accountSuccessfulAddMsg');
        }
    }

    static saveSiteAccountDetails(siteName, url, username, password) {
        //encrypting the password first before storing it
        aesEncrypt(password, masterKey).then(encryptedPassword => {
            //getting local date as d/m/yyyy
            let date = new Date();
            const dateString = date.getDate() + "-" + (date.getMonth() + 1) + "-" + date.getFullYear();

            //get list of accounts against user logged in.
            let accountList = PasswordManager.getAccounts();

            // Remove any existing account for the same siteName
            accountList = accountList.filter(acc => acc.siteName !== siteName);

            //formatting encrypted password to base64
            let ep = {};
            ep.cipherText = uint8ToBase64(encryptedPassword.cipherText);
            ep.iv = uint8ToBase64(encryptedPassword.iv);

            //creating instance of new account
            const account = new Account(siteName, url, username, ep, dateString);

            //adding account to list
            accountList.push(account);
            localStorage.setItem(userIDHash + "-accounts", JSON.stringify(accountList));
            console.log("Saving account with username and password: ", username, password, ep);
        });
    }


    static async displayAccounts() {
        document.querySelectorAll('.section').forEach(sec => sec.classList.remove('active'));
        document.getElementById('viewAccounts').classList.add('active');

        let savedAccounts = PasswordManager.getAccounts();
        const accountsContainer = document.getElementById('accountsList');

        accountsContainer.innerHTML = '';

        //if there are no saved accounts since user may have yet to add
        if (savedAccounts.length === 0) {
            accountsContainer.innerHTML = "<p class='text-center mt-3'>No accounts stored yet.</p>";
            return;
        }

        //iterating through the saved accounts
        savedAccounts.forEach((account, index) => {
            const row = document.createElement('div');
            row.classList.add('row', 'text-center', 'fw', 'bold', 'border-bottom', 'pb-2', 'row-value');
            row.id = `accountRow${index}`;
            row.setAttribute('data-index', index);

            //creating dom ids
            const accountRecordId = "-" + index;
            const siteId = `s${accountRecordId}`;
            const dateId = `d${accountRecordId}`;
            const userDivId = `uD${accountRecordId}`;
            const passwordDivId = `pD${accountRecordId}`;
            const usernameId = `u${accountRecordId}`;
            const passwordId = `p${accountRecordId}`;
            const editBtnId = `e${accountRecordId}`;
            const deleteBtnId = `del${accountRecordId}`;
            const userEyeIconId = `uIcon${accountRecordId}`;
            const passwordEyeIconId = `pIcon${accountRecordId}`;

            const accountSiteNameDiv = document.createElement('div');
            accountSiteNameDiv.id = siteId;
            accountSiteNameDiv.classList.add('col-2');
            accountSiteNameDiv.innerText = account.siteName;
            row.appendChild(accountSiteNameDiv);

            const accountDateAddedDiv = document.createElement('div');
            accountDateAddedDiv.id = dateId;
            accountDateAddedDiv.classList.add('col-2');
            accountDateAddedDiv.innerText = account.dateAdded;
            row.appendChild(accountDateAddedDiv);

            const accountUserIdDiv = document.createElement('div');
            accountUserIdDiv.classList.add('col-2');
            accountUserIdDiv.id = userDivId;

            const accountUserIdLabel = document.createElement('label');
            accountUserIdLabel.id = usernameId;
            accountUserIdLabel.innerText = "*******";
            accountUserIdLabel.dataset.editable = 'true';
            accountUserIdDiv.appendChild(accountUserIdLabel);

            const usernameEyeBtn = document.createElement('button');
            usernameEyeBtn.id = userEyeIconId;
            usernameEyeBtn.classList.add('btn', 'btn-sm', 'btn-outline-secondary');
            usernameEyeBtn.innerText = "👁️";
            accountUserIdDiv.appendChild(usernameEyeBtn);
            row.appendChild(accountUserIdDiv);

            const passwordDiv = document.createElement('div');
            passwordDiv.classList.add('col-2');
            passwordDiv.id = passwordDivId;

            const passwordLabel = document.createElement('label');
            passwordLabel.id = passwordId;
            passwordLabel.innerText = "*******";
            passwordLabel.dataset.editable = 'true';
            passwordDiv.appendChild(passwordLabel);

            const passwordEyeBtn = document.createElement('button');
            passwordEyeBtn.id = passwordEyeIconId;
            passwordEyeBtn.classList.add('btn', 'btn-sm', 'btn-outline-secondary');
            passwordEyeBtn.innerText = "👁️";
            passwordDiv.appendChild(passwordEyeBtn);
            row.appendChild(passwordDiv);

            const editBtn = document.createElement('button');
            editBtn.classList.add('col-2');
            editBtn.id = editBtnId;
            editBtn.classList.add('btn', 'btn-sm', 'btn-outline-primary');
            editBtn.innerText = "Edit";
            row.appendChild(editBtn);

            const deleteBtn = document.createElement('button');
            deleteBtn.classList.add('col-2');
            deleteBtn.id = deleteBtnId;
            deleteBtn.classList.add('btn', 'btn-sm', 'btn-outline-danger');
            deleteBtn.innerText = "Delete";
            row.appendChild(deleteBtn);

            //adding eye buttons functionality
            //username eye icon
            row.querySelector(`#${userEyeIconId}`).addEventListener('click', async () => {
                accountUserIdLabel.innerText = accountUserIdLabel.dataset.editable === 'true' ? account.username : '*******';
                accountUserIdLabel.dataset.editable = accountUserIdLabel.dataset.editable === 'true' ? 'false' : 'true';
            });

            //password eye icon
            row.querySelector(`#${passwordEyeIconId}`).addEventListener('click', async (event) => {
                const parts = event.target.id.split('-');
                const counter = parts[parts.length - 1];
                const passwordLabel = document.getElementById(`p-${counter}`);
                const decrypted = await protectedReadFromLocalStorage(userIDHash + "-accounts", counter);
                passwordLabel.innerText = passwordLabel.dataset.editable === 'true' ? decrypted : '*******';
                passwordLabel.dataset.editable = passwordLabel.dataset.editable === 'true' ? 'false' : 'true';
            });

            //edit button functionality
            row.querySelector(`#${editBtnId}`).addEventListener('click', async () => {
                const editButton = document.getElementById(`${editBtnId}`);

                const usernameSpan = document.getElementById(userDivId);
                const passwordSpan = document.getElementById(passwordDivId);
                const siteNameSpan = document.getElementById(siteId);
                const dateAddedSpan = document.getElementById(dateId);

                let textValue = editButton.innerText;
                console.log("Edit buttoninnertext", textValue);
                //checking what state the button is in, edit or save
                if (textValue == "Edit") { // "Edit️"
                    //retrieving decrypted password from local storage to be displayed
                    const parts = event.target.id.split('-');
                    const counter = parts[parts.length - 1];
                    const passwordLabel = document.getElementById(`p-${counter}`);
                    const decrypted = await protectedReadFromLocalStorage(userIDHash + "-accounts", counter);

                    // make username and password fields editable
                    usernameSpan.innerHTML = `<input type="text" class="form-control form-control-sm" value="${account.username}" />`;
                    passwordSpan.innerHTML = `<input type="text" class="form-control form-control-sm" value="${decrypted}" />`;
                    siteNameSpan.innerHTML = `<input type="text" class="form-control form-control-sm" value="${account.siteName}" />`;
                    dateAddedSpan.innerHTML = `<input type="text" class="form-control form-control-sm" value="${account.dateAdded}" />`;
                    //changing button state to save to let users save modification
                    editButton.innerText = 'Save';
                } else {
                    //button is in save state, so save changes made
                    const newUsername = usernameSpan.querySelector('input').value.trim();
                    const newPassword = passwordSpan.querySelector('input').value.trim();
                    const newSiteName = siteNameSpan.querySelector('input').value.trim();
                    const newDateAdded = dateAddedSpan.querySelector('input').value.trim();

                    //rewriting account details
                    account.username = newUsername;
                    //not encrypting again here, since encryption is being called in saveSiteAccountDetails()
                    account.password = newPassword;
                    account.siteName = newSiteName;
                    account.dateAdded = newDateAdded;

                    //first deleting the existing record of that account, so duplicates aren't stored
                    savedAccounts.splice(index, 1);
                    //then saving the updated account
                    PasswordManager.saveSiteAccountDetails(account.siteName, account.url, account.username, account.password, account.dateAdded);


                    usernameSpan.innerHTML = `<label id="${usernameId}" class="account-detail">${newUsername}</label>`;
                    passwordSpan.innerHTML = `<label id="${passwordId}" class="account-detail">*******</label>`;
                    siteNameSpan.innerHTML = `<label id="${siteId}" class="account-detail">${newSiteName}</label>`;
                    dateAddedSpan.innerHTML = `<label id="${dateId}" class="account-detail">${newDateAdded}</label>`;

                    //username with eye button
                    usernameSpan.innerHTML = `<label id="${usernameId}" class="account-detail">*******</label>
                    <button id="${userEyeIconId}" class="btn btn-sm btn-outline-secondary">👁️</button>`;

                    //password with eye button
                    passwordSpan.innerHTML = `<label id="${passwordId}" class="account-detail">*******</label>  <!-- Masked password initially -->
                    <button id="${passwordEyeIconId}" class="btn btn-sm btn-outline-secondary">👁️</button>`;

                    //reapplying the eye icon toggle functionality
                    //username eye button toggle logic
                    row.querySelector(`#${userEyeIconId}`).addEventListener('click', () => {
                        const usernameLabel = document.getElementById(usernameId);
                        usernameLabel.innerText = usernameLabel.innerText === '*******' ? account.username : '*******';
                    });

                    //password eye button toggle logic
                    row.querySelector(`#${passwordEyeIconId}`).addEventListener('click', async () => {
                        const passwordLabel = document.getElementById(passwordId);
                        passwordLabel.innerText = passwordLabel.innerText === '*******' ? account.password : '*******';
                    });

                    //since save button is used now, set state back to edit
                    editButton.innerText = 'Edit';
                }
            });

            //delete button functionality
            row.querySelector(`#${deleteBtnId}`).addEventListener('click', async () => {
                // Remove any existing modal
                const existingModal = document.getElementById('deletePHAccountModal');
                if (existingModal) existingModal.remove();

                // Create modal container
                const modal = document.createElement('div');
                modal.classList.add('modal', 'fade');
                modal.id = 'deletePHAccountModal';
                modal.tabIndex = -1;
                modal.setAttribute('aria-hidden', 'true');

                // Inner modal dialog
                modal.innerHTML = `
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Delete Account</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body text-center">
                    <p>⚠️ You are about to delete this account from PasswordHaven. Do you want to continue?</p>
                    <div id="deleteModalMessage"></div>
                </div>
                <div class="modal-footer">
                    <button id="confirmDeleteBtn" class="btn btn-danger">Yes, Delete</button>
                    <button class="btn btn-secondary" data-bs-dismiss="modal">No, Cancel</button>
                </div>
            </div>
        </div>
    `
                //appending the modal
                document.body.appendChild(modal);

                // Initialize Bootstrap modal
                const bootstrapModal = new bootstrap.Modal(modal);
                bootstrapModal.show();
                const confirmDeleteBtn = modal.querySelector('#confirmDeleteBtn');
                const modalBody = modal.querySelector('.modal-body');

                confirmDeleteBtn.addEventListener('click', () => {
                    //remove the chosen account
                    savedAccounts.splice(index, 1);
                    writeToLocalStorage(userIDHash + "-accounts", savedAccounts);

                    //updating user with deletion confirmation
                    modalBody.innerHTML = `<p class="text-success">✅ The account has been deleted.</p>`;

                    //replace footer buttons with Close button after deletion confirmation
                    const modalFooter = modal.querySelector('.modal-footer');
                    modalFooter.innerHTML = `<button class="btn btn-primary" data-bs-dismiss="modal">Close</button>`;

                    //refreshing the accounts display
                    modal.addEventListener('hidden.bs.modal', () => {
                        PasswordManager.displayAccounts();
                        modal.remove(); // clean up DOM
                    });
                });
            });

            //add row to container
            accountsContainer.appendChild(row);

        });
    }
}

// Account class below
/**
 *
 */
class Account {
    constructor(siteName, url, username, password, dateAdded) {
        this.siteName = siteName;
        this.url = url;
        this.username = username;
        this.password = password;
        this.dateAdded = dateAdded;
    }
}

/**
 *
 */
class PasswordGenerator {
    static generatePassword() {
        const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        let password = "";
        for (let i = 0; i < 12; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        this.showGeneratedPassword(password);
    }

    static showGeneratedPassword(password) {
        let message = document.getElementById("generatedPassword");
        message.innerText = password;
        message.classList.remove("error");
    }
}

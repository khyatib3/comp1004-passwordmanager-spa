//global variables
let userIDHash = "";
let masterKey = "";


//function to show the relevant section when needed, so all sections don't get displayed automatically
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

function readFromLocalStorage(readItem) {
    return JSON.parse(localStorage.getItem(readItem.toString()));
    //decryptPassword()
}

function writeToLocalStorage(key, value) {
    //encryptPassword()
    localStorage.setItem(value, JSON.stringify(value));
}

function displayPasswordStrength() {
    let password = document.getElementById("enteredPassword").value;
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

function calculatePasswordStrength(password) {
    //creating a strength 'score'
    let strengthScore = 0;

    //checking length of password
    if (password.length === 0) { // if they typed nothing
        return "Weak";
    }
    if (password.length >= 2 && password.length <=7) {
        strengthScore += 1;
    }else if (password.length >= 8) {
        strengthScore += 2;
    }

    //checking for uppercase characters
    let hasUpperCase = /[A-Z]/.test(password) ? 1 : 0;

    //checking for lowercase characters
    let hasLowerCase = /[a-z]/.test(password) ? 1 : 0;

    //checking for numbers
    let hasNumbers = /[0-9]/.test(password) ? 1 : 0;

    //checking for special chars
    let hasSpecialCharacters= /[!"£$%^&*()_+-={}[]:@~#<>?]/.test(password) ? 1 : 0;

    strengthScore = strengthScore + hasSpecialCharacters + hasNumbers + hasLowerCase + hasUpperCase;

    if (strengthScore <= 2) {
        return "Weak";
    } else if (strengthScore > 2 && strengthScore <= 4) {
        return "Medium"
    } else {
        return "Strong";
    }
}

//live message display for confirm password input against password input
document.addEventListener("DOMContentLoaded", function() {
    document.getElementById("confirmPassword").addEventListener("input", function () {
        let password = document.getElementById("enteredPassword").value;
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


class User {
    constructor(username, password) {
        this.username = username;
        this.password = password; // Store hashed password
    }

    //adding user to local storage
    static async saveUser(username, password) {
        userIDHash = hash(username);
        let hashedFromLocalStorage = readFromLocalStorage(userIDHash);
        if (hashedFromLocalStorage !== null) {
            alert("An account already exists. Please login!")
            return false;
        } else {
            let hashedPassword = hash(password);

            //initiating an instance of the user
            let newUser = new User(userIDHash, hashedPassword);

            // adding the user to local storage
            writeToLocalStorage(JSON.stringify(newUser));

            //creating the master key by hashing a combination of username and password
            masterKey = hash(username + password);
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
        userIDHash = hash(username);
        let hashedPasswordFromLocalStorage = readFromLocalStorage(userIDHash);
        if (hashedPasswordFromLocalStorage == null) {
            return false;
        } else {
            let computedHashedPassword = hash(inputPassword);
            if (computedHashedPassword === hashedPasswordFromLocalStorage) {
                masterKey = hash(username + inputPassword);
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

        let success = User.saveUser(username, password);

        if (success) {
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

    }

    //function that deals with user logging into password haven
    static handleLogin() {
        let email = document.getElementById('loginEmail').value;
        let password = document.getElementById('loginPassword').value;
        let loginMsg = document.getElementById('loginMsg');


        let detailsMatch = User.login(email, password);
        if (detailsMatch) {
            localStorage.setItem("loggedIn", "true");

            loginMsg.innerHTML = "✅Successful Login!";
            loginMsg.classList.remove('text-danger');
            loginMsg.classList.add('text-success');
            // //closing the modal afterward
            // setTimeout(()=>{
            //     let loginModal = new bootstrap.Modal(document.getElementById('loginModal'));
            //     if (loginModal) {
            //         loginModal.hide();
            //     }
            // }, 1000); //close after 1 second
        } else {
            loginMsg.innerHTML = " ❌ Invalid details entered!";
        }
    }
}

const algorithm = {
    name: "AES-GCM",
    length: 256
};


class PasswordManager {
    //function to retrieve the accounts from localStorage
    static getAccounts(accounts) {
        return readFromLocalStorage(accounts);
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
        let accounts = JSON.parse(localStorage.getItem("accounts")) || [];
        let accountExists = accounts.some(account => account.site === site && account.username === username && account.password === password);
        if (accountExists) {
            accountAddMsg.innerText = "⚠️This account already exists in the password manager! You can find it in 'View Accounts'.";
            accountAddMsg.classList.remove('text-success');
            accountAddMsg.classList.add('text-danger');
        } else {
            PasswordManager.saveSiteAccountDetails(site,url,username,password)
            checkUserLoggedIn('accountSuccessfulAddMsg');
        }
    }

    static saveSiteAccountDetails(siteName, url, username, password, dateOfCreation){
        //encrypting the password first before storing it
        const encryptedPassword = Account.aesEncryptPassword(password);
        let account = new Account(siteName, username, encryptedPassword, dateOfCreation);
        const accountMap = new Map();
        accountMap.set(siteName, account);
        writeToLocalStorage("accountList",accountMap);

    }


    static async displayAccounts(){
        let savedAccounts = PasswordManager.getAccounts();
        let accountsContainer = document.getElementById('accountsList');

        accountsContainer.innerHTML = '';

        //if there are no saved accounts since user may have yet to add
        if(savedAccounts.length === 0){
            accountsContainer.innerHTML = "<p class='text-center mt-3'>No accounts stored yet.</p>";
            return;
        }

        //iterating through the saved accounts
        savedAccounts.forEach((account, index)=> {
            const row = document.createElement('div');
            row.className = 'row align-items-center mb-2 row value';
            row.id = `accountRow${index}`;
            row.setAttribute('data-index', index);

            //creating the IDs for UI elements
            const accountRecordId = index + 1;
            const siteId = `s${accountRecordId}`;
            const dateAddedId = `d${accountRecordId}`;
            const usernameId = `u${accountRecordId}`;
            const passwordId = `p${accountRecordId}`;
            const userEyeIconId = `uIcon${accountRecordId}`;
            const passwordEyeIconId = `pIcon${accountRecordId}`;
            const editBtnId = `e${accountRecordId}`;
            const deleteBtn = `del${accountRecordId}`;

            //setting the elements with the account record details
            row.innerHTML = `
            <div class="d-flex justify-content-between align-items-center row${accountRecordId}">
                <div class="account-info">
                    <div> <span id="a${accountRecordId}"> ${account.siteName}</span> </div>
                    <div> <span id="${dateAddedId}"> ${account.dateAdded}</span></div>
                    <div> <span id="${usernameId}">Username</span> </div>
                   <div> <span id="${passwordId}"> ${passwordEyeIconId}</span> </div>
                </div>
            </div>`

        })

        accountsContainer.appendChild(row)
    }

    static viewCredentials(site, email, password) {

    }

    static deleteAccount(){

    }

}

function arrayBufferToBase64(arrayBuffer) {
    return btoa(String.fromCharCode(new Uint8Array(arrayBuffer)));
}

function base64ToArrayBuffer(base64Data){
    const binaryString = atob(base64Data);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = bytes.charCodeAt(i);
    }
    return bytes.buffer;
}

// Account class below
class Account {
    constructor(siteName, url, username, password, dateAdded) {
        this.siteName = siteName;
        this.url = url;
        this.username = username;
        this.password = password;
        this.dateAdded = dateAdded;
    }

    //aes gcm encryption
    static async aesEncryptPassword(password) {
        try{
            //importing my masterKey as a cryptoKey
            const cryptoKey = await crypto.subtle.importKey(
                "raw",
                masterKey,
                {name: 'AES-GCM'},
                false,
                ['encrypt', 'decrypt']
            );

            //using an initialisation vector without random values
            const initialisationVector = new Uint8Array(12);

            //encrypting
            const encryptedData = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: initialisationVector,
                    tagLength: 128
                },
                cryptoKey,
                new TextEncoder().encode(password)
            );
            return{
                iv: arrayBufferToBase64(initialisationVector.buffer),
                cipherText:arrayBufferToBase64(encryptedData)
            };
        } catch(e){
            console.error("Encryption failed:", e);
            throw e;
        }
    }


    static async decryptPassword(encryptedPassword) {
      try{
          const cryptoKey = await crypto.subtle.importKey(
              "raw",
              masterKey,
              {name: 'AES-GCM'},
              false,
              ['encrypt', 'decrypt']
          );

          //converting from base 64
          const initialisationVector = base64ToArrayBuffer(encryptedPassword.iv);
          const cipherText = base64ToArrayBuffer(encryptedPassword.cipherText);

          //decrypting
          const decryptedPassword = await crypto.subtle.decrypt(
              {
                  name: 'AES-GCM',
                  iv: initialisationVector,
                  tagLength: 128
              },
              cryptoKey,
              cipherText
          );

          //return the password
          return new TextDecoder().decode(decryptedPassword);
      }catch(e){
          console.error("Decryption failed:", e);
      }
    }

}

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

//global variables
let userIDHash = "";
let masterKey = "";

//function to show the relevant section when needed, so all sections don't get displayed automatically
function showSection(sectionId){
    //hiding all the sections
    document.querySelectorAll('.section').forEach(section =>{
        section.classList.remove('active');
    })

    //then showing the selected section
    let selectedSection = document.getElementById(sectionId);
    if(selectedSection){
        selectedSection.classList.add('active');
    }else {
        console.error("Couldn't find section:", sectionId);
    }
}

//function which is used for hashing usernames and passwords
//will be used to make the masterKey
async function hash(value){
    const encoder = new TextEncoder();
    const data = encoder.encode(value);
    const hashedValue = await crypto.subtle.digest('SHA-256', data);

    //then convert to a hexadecimal string
    return Array.from(new Uint8Array(hashedValue)).map(b => b.toString(16).padStart(2, '0'));
}


//method that checks whether the suer has logged into PH before they choose to see accounts.
//ensures security
function checkLoginBeforeViewAccounts(sectionId){
    if(localStorage.getItem("loggedIn") !== "true"){
        alert("You must login to PasswordHaven first!");
        showSection("home");
        return;
    }
    showSection(sectionId);
}

function readFromLocalStorage(readItem){
    return JSON.parse(localStorage.getItem(readItem.toString()));
    //decryptPasword()
}

function writeToLocalStorage(key, value){
    //encryptPassword()
    localStorage.setItem(value, JSON.stringify(value));
}

class User {
    constructor(username, password) {
        this.username = username;
        this.password = password; // Store hashed password
    }

    //adding user to local storage
    static saveUser(username, password) {
        userIDHash = hash(username);
        let hashedFromLocalStorage = readFromLocalStorage(userIDHash);
        if (hashedFromLocalStorage !== null) {
            alert("An account already exists. Please login!")
            return false;
        }else{
            let hashedPassword = hash(password);

            //initiating an instance of the user
            let newUser = new User(userIDHash, hashedPassword);

            // adding the user to local storage
            localStorage.setItem(userIDHash, JSON.stringify(newUser));

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


    static login(username, inputPassword) {
        userIDHash = hash(username);
        let hashedPasswordFromLocalStorage = readFromLocalStorage(userIDHash);
        if (hashedPasswordFromLocalStorage == null) {
            return false;
        }else{
            let computedHashedPassword = hash(inputPassword);
            if (computedHashedPassword == hashedPasswordFromLocalStorage) {
                return true;
            } else
                masterKey = hash(username + inputPassword);
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
            signUpMsg.innerText = 'Your account was created successfully! Please login now!';
            signUpMsg.classList.remove('text-danger');
            signUpMsg.classList.add('text-success');

            //clearing the input fields after successful creation
            document.getElementById('signUpEmail').value = "";
            document.getElementById('signUpPassword').value = "";

            //closing the modal afterward
            setTimeout(()=>{
                let signUpModal = bootstrap.Modal(document.getElementById('createPHAccountModal'));
                if (signUpModal) {
                    signUpModal.hide();
                }
            }, 1000); //close after 1 second

        } else {
            signUpMsg.innerText = '⚠️ Your account with us already exists! Please login.';
            signUpMsg.classList.remove('text-success');
            signUpMsg.classList.add('text-danger');
        }

    }

    //function that deals with user logging into password haven
    static handleLogin() {
        let email = document.getElementById('loginEmail').value;
        let password = document.getElementById('loginPassword').value;
        let loginMsg = document.getElementById('loginMsg');

        if (User.login(email, password)) {
            localStorage.setItem("loggedIn", "true");

            loginMsg.innerHTML = "Successful Login!";
            loginMsg.classList.remove('text-danger');
            loginMsg.classList.add('text-success');

            //closing the modal afterward
            setTimeout(()=>{
                let loginModal = bootstrap.Modal(document.getElementById('createPHAccountModal'));
                if (loginModal) {
                    loginModal.hide();
                }
            }, 1000); //close after 1 second
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
    static saveAccount(site, username, password) {
        let accounts = JSON.parse(localStorage.geetItem("accounts")) || [];
        accounts.push({site, username, password: btoa(password)});
        localStorage.setItem("accounts", JSON.stringify(accounts));

    }

    //function to retrieve the accounts from localStorage
    static getAccounts() {
        return JSON.parse(localStorage.getItem("accounts")) || [];
    }

    //adding account to local storage method
    static addAccount(){
        let site = document.getElementById('siteName').value;
        let email = document.getElementById('email').value;
        let password = document.getElementById('password').value;
        let accountAddMsg = document.getElementById('accountAddMsg');

        //checking if that account already exists
        let accounts = JSON.parse(localStorage.getItem("accounts")) || [];
        let accountExists = accounts.some(account => account.site === site && account.username === username && account.password === password);
        if (accountExists) {
            accountAddMsg.innerText = "This account already exists in the password manager! You can find it in 'View Accounts'.";
            accountAddMsg.classList.remove('text-success');
            accountAddMsg.classList.add('text-danger');
        } else{

            PasswordManager.saveAccount(site, email, password);
            accountAddMsg.innerText = "Your account has been saved successfully!";
            accountAddMsg.classList.remove('text-danger');
            accountAddMsg.classList.add('text-success');
        }
    }

}

// Account class below
class Account{
    constructor(siteName, url, username, password, dateAdded) {
        this.siteName = siteName;
        this.url = url;
        this.username = username;
        this.password = this.encryptPassword(password);
        this.dateAdded = dateAdded;
    }

    static async hashing(password) {
        //TODO find different way that doesn't use random values but
        //first generate a random salt
        const salt = crypto.getRandomValues(new Uint8Array(16));

        //converting the Uint8Array into a normal javascript array
        //and converting each byte into a hexadecimal string, joined together
        //this way the salt becomes readable to humans
        const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0').join(''));

        //prepending the salt to the password
        const saltedPassword = saltHex + password;

        //encoding the salted password to a Uint8Array
        const encoder = new TextEncoder();
        const data = encoder.encode(saltedPassword);

        //hash the salted password using SHA-256 encryption
        const encryptedPassword = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(encryptedPassword));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0').join(''));

        //store the salt and the hash
        return {salt : saltHex, hash: hashHex};
    }

    static async aesEncryptPassword(password, key) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encodedData = this.textToUint8Array(password);

        const encryptedData = await crypto.subtle.encrypt(
            {name : "AES-GCM", iv},
            key,
            encodedData
        );

        return{
            iv : Array.from(iv), // convert to array to store
            encrypted: Array.from(new Uint8Array(encryptedData))
        };
    }

    //this is to convert a string into a Uint8Array
    static textToUint8Array (text){
        return new TextEncoder().encode(text);
    }

    //to convert from Uint8Array to string
    static uint8ArrayToText(uint8Array) {
        return new TextEncoder().encode(uint8Array);
    }
    async generateKey(){
        return await crypto.subtle.generateKey(
            algorithm,
            true,
            ["encrypt", "decrypt"]
        );
    }

    static async decryptPassword(encryptedPassword, key){
        const {iv, encrypted} = encryptedPassword;
        const encryptedArray = new Uint8Array(encrypted);
        const ivArray = new Uint8Array(iv);

        const decryptedPassword = await crypto.subtle.decrypt(
            {name : "AES-GCM", iv: iv, ivArray},
            key,
            encryptedArray
        );
        return this.uint8ArrayToText(new Uint8Array(decryptedPassword));
    }

}

class PasswordStrengthValidator {
    static checkStrength(password) {
        const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        return strongRegex.test(password) ? "Strong" : "Weak";
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

    static showGeneratedPassword(password){
        let message = document.getElementById("generatedPassword");
        message.innerText = password;
        message.classList.remove("error");
    }
}

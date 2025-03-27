// Global variables, computed every time when user uses this application.
let userIdHash = "";
let masterKey ="";

function signup(userName, password) {
    // compute the userIdHash and passwordHash
    userIdHash = hash(userName);
    // check if the userIdHash is already there in the internal storage.
    hashedPasswordFromLocalStorage = readFromLocalStorage(userIdHash);
    if (hashedPasswordFromLocalStorage !== null) {
        // Display message user already exists.
    } else {
        hashedPassword = hash(password);
        writeToLocalStorage(userIdHash, hashedPassword);
        masterKey = hash(userName + password);
    }
}

function login(userName, password) {
    // compute the userIdHash and passwordHash
    userIdHash = hash(userName);
    // check if the userIdHash is already there in the internal storage.
    hashedPasswordFromLocalStorage = readFromLocalStorage(userIdHash);
    if (hashedPasswordFromLocalStorage == null) {
        // Display message user does not exists.
    } else {
        // check if hashed password from local storage is same as computed hash password.
        computedPasswordHash = hash(password);
        if ( computedPasswordHash !== hashedPasswordFromLocalStorage) {
            // display message that password entered is wrong.
        } else {
            masterKey = hash(userName + password);
        }
    }
}


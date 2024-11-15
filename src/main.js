import { getAuth, onAuthStateChanged, signInWithRedirect, GoogleAuthProvider, getRedirectResult } from 'firebase/auth';
import app from '../firebase/firebaseConfig'; // Import the initialized app

const auth = getAuth(app);
const button = document.querySelector('button');

console.log('Firebase app initialized:', app);
console.log('Auth instance:', auth);

onAuthStateChanged(auth, (user) => {
    if (user == null) {
        console.log('No user signed in');
        return;
    }
    console.log('User signed in:', user);
});

button?.addEventListener('click', () => {
    console.log('Sign-in button clicked');
    signInWithRedirect(auth, new GoogleAuthProvider())
        .then(() => {
            console.log('Redirecting to sign-in provider');
        })
        .catch((error) => {
            console.error('Error during sign-in redirect:', error);
        });
});

getRedirectResult(auth)
    .then((result) => {
        if (result && result.user) {
            console.log('User signed in after redirect:', result.user);
            // Store the user's email in localStorage
            localStorage.setItem('userEmail', result.user.email);
            // Redirect to the user info page
            window.location.href = './userpage/user.html';
        } else {
            console.log('No redirect result available');
        }
    })
    .catch((error) => {
        console.error('Error during sign-in with redirect:', error);
    });
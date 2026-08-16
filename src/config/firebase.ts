import {
    cert,
    getApps,
    initializeApp,
} from 'firebase-admin/app';

import {
    getAuth,
} from 'firebase-admin/auth';

import {
    getDatabase,
} from 'firebase-admin/database';

import dotenv from 'dotenv';

dotenv.config();

const projectId = process.env.FIREBASE_PROJECT_ID;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const privateKey = process.env.FIREBASE_PRIVATE_KEY;
const databaseURL = process.env.FIREBASE_DATABASE_URL;

if (!projectId) {
    throw new Error('Missing FIREBASE_PROJECT_ID');
}

if (!clientEmail) {
    throw new Error('Missing FIREBASE_CLIENT_EMAIL');
}

if (!privateKey) {
    throw new Error('Missing FIREBASE_PRIVATE_KEY');
}

if (!databaseURL) {
    throw new Error('Missing FIREBASE_DATABASE_URL');
}

const firebasePrivateKey = privateKey.replace(/\\n/g, '\n');

const firebaseApp =
    getApps().length > 0
        ? getApps()[0]
        : initializeApp({
            credential: cert({
                projectId,
                clientEmail,
                privateKey: firebasePrivateKey,
            }),
            databaseURL,
        });

export const adminAuth = getAuth(firebaseApp);

export const realtimeDb = getDatabase(firebaseApp);

console.log('✅ Firebase Admin initialized');
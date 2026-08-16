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

import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const serviceAccountPath =
    process.env.FIREBASE_ADMIN_SDK_PATH;

if (!serviceAccountPath) {
    throw new Error(
        'Missing FIREBASE_ADMIN_SDK_PATH in .env'
    );
}

const databaseURL =
    process.env.FIREBASE_DATABASE_URL;

if (!databaseURL) {
    throw new Error(
        'Missing FIREBASE_DATABASE_URL in .env'
    );
}

const absolutePath =
    path.resolve(serviceAccountPath);

console.log(
    '🔍 Looking for service account at:',
    absolutePath
);

console.log(
    '🔥 Firebase Database URL:',
    databaseURL
);

const serviceAccount =
    require(absolutePath);

const firebaseApp =
    getApps().length > 0
        ? getApps()[0]
        : initializeApp({
            credential: cert(serviceAccount),
            databaseURL: databaseURL,
        });

export const adminAuth =
    getAuth(firebaseApp);

export const realtimeDb =
    getDatabase(firebaseApp);
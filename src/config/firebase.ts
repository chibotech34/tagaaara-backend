import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

import {
    cert,
    getApps,
    initializeApp,
} from 'firebase-admin/app';

import {
    getAuth,
    Auth,
} from 'firebase-admin/auth';

import {
    getDatabase,
    Database,
} from 'firebase-admin/database';

dotenv.config();

let firebaseApp;

if (getApps().length === 0) {
    const databaseURL = process.env.FIREBASE_DATABASE_URL;

    if (!databaseURL) {
        throw new Error('Missing FIREBASE_DATABASE_URL');
    }

    // ============================================================
    // LOCAL DEVELOPMENT
    // Uses Firebase service-account JSON
    // ============================================================

    const serviceAccountPath = process.env.FIREBASE_ADMIN_SDK_PATH;

    if (serviceAccountPath) {
        const resolvedPath = path.resolve(
            process.cwd(),
            serviceAccountPath,
        );

        if (!fs.existsSync(resolvedPath)) {
            throw new Error(
                `Firebase service account file not found: ${resolvedPath}`,
            );
        }

        const serviceAccount = JSON.parse(
            fs.readFileSync(resolvedPath, 'utf8'),
        );

        firebaseApp = initializeApp({
            credential: cert(serviceAccount),
            databaseURL,
        });

        console.log(
            '✅ Firebase Admin initialized using service account file',
        );
    }

    // ============================================================
    // RENDER / PRODUCTION
    // Uses environment variables
    // ============================================================

    else {
        const projectId = process.env.FIREBASE_PROJECT_ID;
        const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
        const privateKey = process.env.FIREBASE_PRIVATE_KEY;

        if (!projectId) {
            throw new Error('Missing FIREBASE_PROJECT_ID');
        }

        if (!clientEmail) {
            throw new Error('Missing FIREBASE_CLIENT_EMAIL');
        }

        if (!privateKey) {
            throw new Error('Missing FIREBASE_PRIVATE_KEY');
        }

        firebaseApp = initializeApp({
            credential: cert({
                projectId,
                clientEmail,
                privateKey: privateKey.replace(/\\n/g, '\n'),
            }),
            databaseURL,
        });

        console.log(
            '✅ Firebase Admin initialized using environment variables',
        );
    }
} else {
    firebaseApp = getApps()[0];

    console.log('ℹ️ Firebase Admin already initialized');
}

// ============================================================
// Firebase services
// ============================================================

export const adminAuth: Auth = getAuth(firebaseApp);

export const realtimeDb: Database = getDatabase(firebaseApp);

export default firebaseApp;
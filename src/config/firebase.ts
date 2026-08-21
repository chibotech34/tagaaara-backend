import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

import {
    App,
    cert,
    getApps,
    initializeApp,
} from 'firebase-admin/app';

import { getAuth, Auth } from 'firebase-admin/auth';
import { getDatabase, Database } from 'firebase-admin/database';
import { getMessaging, Messaging } from 'firebase-admin/messaging'; // 👈 ADD THIS

dotenv.config();

/*
|--------------------------------------------------------------------------
| Environment variables
|--------------------------------------------------------------------------
*/

const firebaseProjectId = process.env.FIREBASE_PROJECT_ID;
const firebaseClientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const firebasePrivateKey = process.env.FIREBASE_PRIVATE_KEY;
const firebaseDatabaseUrl = process.env.FIREBASE_DATABASE_URL;
const firebaseAdminSdkPath = process.env.FIREBASE_ADMIN_SDK_PATH;

/*
|--------------------------------------------------------------------------
| Initialize Firebase Admin
|--------------------------------------------------------------------------
*/

let firebaseApp: App;

/*
|--------------------------------------------------------------------------
| Option 1: Service account JSON file
|--------------------------------------------------------------------------
*/

if (firebaseAdminSdkPath) {
    const resolvedPath = path.resolve(
        process.cwd(),
        firebaseAdminSdkPath,
    );

    if (!fs.existsSync(resolvedPath)) {
        throw new Error(
            `Firebase service account file not found: ${resolvedPath}`,
        );
    }

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const serviceAccount = require(resolvedPath);

    firebaseApp =
        getApps().length > 0
            ? getApps()[0]
            : initializeApp({
                credential: cert(serviceAccount),
                databaseURL: firebaseDatabaseUrl,
            });

    console.log('✅ Firebase Admin initialized using service account file');
}

/*
|--------------------------------------------------------------------------
| Option 2: Render / production environment variables
|--------------------------------------------------------------------------
*/

else if (
    firebaseProjectId &&
    firebaseClientEmail &&
    firebasePrivateKey
) {
    const privateKey = firebasePrivateKey.replace(/\\n/g, '\n');

    firebaseApp =
        getApps().length > 0
            ? getApps()[0]
            : initializeApp({
                credential: cert({
                    projectId: firebaseProjectId,
                    clientEmail: firebaseClientEmail,
                    privateKey,
                }),
                databaseURL: firebaseDatabaseUrl,
            });

    console.log(
        '✅ Firebase Admin initialized using environment variables',
    );
}

/*
|--------------------------------------------------------------------------
| Firebase configuration missing
|--------------------------------------------------------------------------
*/

else {
    throw new Error(
        'Firebase configuration is missing. Set either FIREBASE_ADMIN_SDK_PATH or FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY.',
    );
}

/*
|--------------------------------------------------------------------------
| Firebase services
|--------------------------------------------------------------------------
*/

export const firebaseAuth: Auth = getAuth(firebaseApp);
export const realtimeDb: Database = getDatabase(firebaseApp);
export const firebaseMessaging: Messaging = getMessaging(firebaseApp); // 👈 ADD THIS

export default firebaseApp;
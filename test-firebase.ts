import dotenv from 'dotenv';
dotenv.config();

import fs from 'fs';
import path from 'path';

import {
    initializeApp,
    cert,
    getApps,
} from 'firebase-admin/app';

import { getAuth } from 'firebase-admin/auth';

const serviceAccountPath =
    process.env.FIREBASE_ADMIN_SDK_PATH;

if (!serviceAccountPath) {
    throw new Error(
        'FIREBASE_ADMIN_SDK_PATH is missing'
    );
}

const resolvedPath = path.resolve(
    process.cwd(),
    serviceAccountPath
);

console.log('Service account path:');
console.log(resolvedPath);

if (!fs.existsSync(resolvedPath)) {
    throw new Error(
        `Service account file does not exist: ${resolvedPath}`
    );
}

const serviceAccount =
    require(resolvedPath);

console.log('Project ID:');
console.log(serviceAccount.project_id);

console.log('Client email:');
console.log(serviceAccount.client_email);

console.log('Private key ID:');
console.log(serviceAccount.private_key_id);

if (getApps().length === 0) {
    initializeApp({
        credential: cert(serviceAccount),
    });
}

async function testFirebase() {
    try {
        console.log(
            '\nTesting Firebase Admin authentication...'
        );

        /*
         * This forces the Admin SDK to obtain
         * a Google OAuth access token.
         */
        const user =
            await getAuth().listUsers(1);

        console.log(
            '\n✅ Firebase Admin authentication works.'
        );

        console.log(
            `Users returned: ${user.users.length}`
        );
    } catch (error) {
        console.error(
            '\n❌ Firebase Admin authentication FAILED:'
        );

        console.error(error);
    }
}

testFirebase();
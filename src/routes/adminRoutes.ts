import { Router, Request, Response } from 'express';
import { adminAuth, realtimeDb } from '../config/firebase';
import pool from '../config/database';

const router = Router();

/*
|--------------------------------------------------------------------------
| CREATE ADMIN
|--------------------------------------------------------------------------
| Creates the admin in:
| 1. Firebase Authentication
| 2. PostgreSQL
| 3. Firebase Realtime Database
|--------------------------------------------------------------------------
*/

router.post('/create', async (req: Request, res: Response) => {
    const {
        email,
        password,
        fullName,
        phoneNumber,
        username,
        profilePhoto,
        accountStatus,
    } = req.body;

    // ---------------------------------------------------------
    // Validate required fields
    // ---------------------------------------------------------

    if (!email || !password || !fullName) {
        return res.status(400).json({
            success: false,
            error: 'Email, password and full name are required.',
        });
    }

    try {
        // ---------------------------------------------------------
        // 1. CREATE USER IN FIREBASE AUTHENTICATION
        // ---------------------------------------------------------

        const firebaseUser = await adminAuth.createUser({
            email,
            password,
            displayName: fullName,
        });

        const firebaseUid = firebaseUser.uid;

        console.log(
            '✅ Firebase Auth user created:',
            firebaseUid
        );

        // ---------------------------------------------------------
        // 2. SAVE ADMIN IN POSTGRESQL
        // ---------------------------------------------------------

        const query = `
            INSERT INTO public.admins
            (
                firebase_uid,
                email,
                full_name,
                phone_number,
                username,
                profile_photo_url,
                account_status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id;
        `;

        const values = [
            firebaseUid,
            email,
            fullName,
            phoneNumber || null,
            username || null,
            profilePhoto || null,
            accountStatus || 'active',
        ];

        let result;

        try {
            result = await pool.query(query, values);

            console.log(
                '✅ Admin saved to PostgreSQL:',
                result.rows[0].id
            );
        } catch (postgresError) {
            /*
             * PostgreSQL failed after Firebase Auth succeeded.
             *
             * Delete Firebase user so we don't leave
             * an incomplete admin account behind.
             */

            console.error(
                '❌ PostgreSQL insert failed:',
                postgresError
            );

            try {
                await adminAuth.deleteUser(firebaseUid);

                console.log(
                    '↩️ Firebase Auth user rolled back.'
                );
            } catch (rollbackError) {
                console.error(
                    '❌ Firebase rollback failed:',
                    rollbackError
                );
            }

            throw postgresError;
        }

        // ---------------------------------------------------------
        // 3. SAVE ADMIN IN FIREBASE REALTIME DATABASE
        // ---------------------------------------------------------

        const adminData = {
            uid: firebaseUid,
            email: email,
            fullName: fullName,
            phoneNumber: phoneNumber || '',
            username: username || '',
            profilePhoto: profilePhoto || '',
            accountStatus: accountStatus || 'active',
            role: 'admin',
            postgresId: result.rows[0].id,
            createdAt: new Date().toISOString(),
        };

        try {
            await realtimeDb
                .ref(`admins/${firebaseUid}`)
                .set(adminData);

            console.log(
                '✅ Admin saved to Firebase Realtime Database'
            );
        } catch (firebaseDbError) {
            /*
             * Realtime Database failed.
             *
             * Delete the PostgreSQL record and Firebase Auth
             * user to prevent an incomplete account.
             */

            console.error(
                '❌ Firebase Realtime Database failed:',
                firebaseDbError
            );

            try {
                await pool.query(
                    'DELETE FROM public.admins WHERE id = $1',
                    [result.rows[0].id]
                );

                await adminAuth.deleteUser(firebaseUid);

                console.log(
                    '↩️ Account creation rolled back.'
                );
            } catch (rollbackError) {
                console.error(
                    '❌ Rollback failed:',
                    rollbackError
                );
            }

            throw firebaseDbError;
        }

        // ---------------------------------------------------------
        // SUCCESS
        // ---------------------------------------------------------

        return res.status(201).json({
            success: true,
            message: 'Admin created successfully.',
            uid: firebaseUid,
            adminId: result.rows[0].id,
            realtimeDatabasePath: `admins/${firebaseUid}`,
        });

    } catch (error: any) {
        console.error(
            '❌ Error creating admin:',
            error
        );

        // Firebase duplicate email
        if (error.code === 'auth/email-already-exists') {
            return res.status(409).json({
                success: false,
                error: 'An account with this email already exists.',
            });
        }

        // PostgreSQL duplicate constraint
        if (error.code === '23505') {
            return res.status(409).json({
                success: false,
                error: 'An admin with this email, username, or Firebase UID already exists.',
            });
        }

        return res.status(500).json({
            success: false,
            error:
                error.message ||
                'Failed to create admin account.',
        });
    }
});

export default router;
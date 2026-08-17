import { Router, Request, Response } from 'express';
import { firebaseAuth, realtimeDb } from '../config/firebase';
import pool from '../config/database';

const router = Router();

/*
|--------------------------------------------------------------------------
| POST /api/admin/create
|--------------------------------------------------------------------------
| Creates an admin in:
|
| 1. Firebase Authentication
| 2. PostgreSQL
| 3. Firebase Realtime Database
|
| If a later step fails, earlier steps are rolled back where possible.
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

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedFullName = String(fullName).trim();

    try {
        // ---------------------------------------------------------
        // Check if admin already exists in PostgreSQL
        // ---------------------------------------------------------

        const existingAdmin = await pool.query(
            `
            SELECT id
            FROM public.admins
            WHERE LOWER(email) = $1
            LIMIT 1
            `,
            [normalizedEmail],
        );

        if (existingAdmin.rows.length > 0) {
            return res.status(409).json({
                success: false,
                error: 'An admin with this email already exists.',
                code: 'ADMIN_ALREADY_EXISTS',
            });
        }

        // ---------------------------------------------------------
        // 1. CREATE USER IN FIREBASE AUTHENTICATION
        // ---------------------------------------------------------

        const firebaseUser = await firebaseAuth.createUser({
            email: normalizedEmail,
            password,
            displayName: normalizedFullName,
        });

        const firebaseUid = firebaseUser.uid;

        console.log(
            '✅ Firebase Auth user created:',
            firebaseUid,
        );

        // ---------------------------------------------------------
        // 2. SAVE ADMIN IN POSTGRESQL
        // ---------------------------------------------------------

        let result;

        try {
            const query = `
                INSERT INTO public.admins
                (
                    firebase_uid,
                    email,
                    full_name,
                    phone_number,
                    username,
                    profile_photo_url,
                    account_status,
                    role
                )
                VALUES
                (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5,
                    $6,
                    $7,
                    $8
                )
                RETURNING *;
            `;

            const values = [
                firebaseUid,
                normalizedEmail,
                normalizedFullName,
                phoneNumber || null,
                username || null,
                profilePhoto || null,
                accountStatus || 'active',
                'admin',
            ];

            result = await pool.query(query, values);

            console.log(
                '✅ Admin saved to PostgreSQL:',
                result.rows[0].id,
            );
        } catch (postgresError: any) {
            console.error(
                '❌ PostgreSQL insert failed:',
                postgresError,
            );

            // -----------------------------------------------------
            // Roll back Firebase Authentication
            // -----------------------------------------------------

            try {
                await firebaseAuth.deleteUser(firebaseUid);

                console.log(
                    '↩️ Firebase Auth user rolled back.',
                );
            } catch (rollbackError) {
                console.error(
                    '❌ Firebase Auth rollback failed:',
                    rollbackError,
                );
            }

            throw postgresError;
        }

        // ---------------------------------------------------------
        // 3. SAVE ADMIN IN FIREBASE REALTIME DATABASE
        // ---------------------------------------------------------

        const adminData = {
            uid: firebaseUid,
            email: normalizedEmail,
            fullName: normalizedFullName,
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
                '✅ Admin saved to Firebase Realtime Database:',
                `admins/${firebaseUid}`,
            );
        } catch (firebaseDbError: any) {
            console.error(
                '❌ Firebase Realtime Database failed:',
                firebaseDbError,
            );

            // -----------------------------------------------------
            // Roll back PostgreSQL
            // -----------------------------------------------------

            try {
                await pool.query(
                    `
                    DELETE FROM public.admins
                    WHERE id = $1
                    `,
                    [result.rows[0].id],
                );

                console.log(
                    '↩️ PostgreSQL admin record rolled back.',
                );
            } catch (postgresRollbackError) {
                console.error(
                    '❌ PostgreSQL rollback failed:',
                    postgresRollbackError,
                );
            }

            // -----------------------------------------------------
            // Roll back Firebase Authentication
            // -----------------------------------------------------

            try {
                await firebaseAuth.deleteUser(firebaseUid);

                console.log(
                    '↩️ Firebase Auth user rolled back.',
                );
            } catch (firebaseRollbackError) {
                console.error(
                    '❌ Firebase Auth rollback failed:',
                    firebaseRollbackError,
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
            admin: {
                id: result.rows[0].id,
                firebaseUid: result.rows[0].firebase_uid,
                email: result.rows[0].email,
                fullName: result.rows[0].full_name,
                phoneNumber: result.rows[0].phone_number,
                username: result.rows[0].username,
                profilePhoto: result.rows[0].profile_photo_url,
                accountStatus: result.rows[0].account_status,
                role: result.rows[0].role,
                createdAt: result.rows[0].created_at,
            },
        });
    } catch (error: any) {
        console.error(
            '❌ Error creating admin:',
            error,
        );

        // ---------------------------------------------------------
        // Firebase duplicate email
        // ---------------------------------------------------------

        if (
            error?.code ===
            'auth/email-already-exists'
        ) {
            return res.status(409).json({
                success: false,
                error: 'An account with this email already exists in Firebase.',
                code: 'FIREBASE_EMAIL_EXISTS',
            });
        }

        // ---------------------------------------------------------
        // Firebase invalid email
        // ---------------------------------------------------------

        if (
            error?.code ===
            'auth/invalid-email'
        ) {
            return res.status(400).json({
                success: false,
                error: 'The email address is invalid.',
                code: 'INVALID_EMAIL',
            });
        }

        // ---------------------------------------------------------
        // Firebase weak password
        // ---------------------------------------------------------

        if (
            error?.code ===
            'auth/password-does-not-meet-requirements'
        ) {
            return res.status(400).json({
                success: false,
                error: 'The password does not meet Firebase password requirements.',
                code: 'WEAK_PASSWORD',
            });
        }

        // ---------------------------------------------------------
        // PostgreSQL duplicate constraint
        // ---------------------------------------------------------

        if (error?.code === '23505') {
            return res.status(409).json({
                success: false,
                error:
                    'An admin with this email, username, or Firebase UID already exists.',
                code: 'ADMIN_DUPLICATE',
            });
        }

        // ---------------------------------------------------------
        // Generic server error
        // ---------------------------------------------------------

        return res.status(500).json({
            success: false,
            error:
                error?.message ||
                'Failed to create admin account.',
            code: 'ADMIN_CREATION_FAILED',
        });
    }
});

/*
|--------------------------------------------------------------------------
| GET /api/admin/exists
|--------------------------------------------------------------------------
*/

router.get('/exists', async (_req: Request, res: Response) => {
    try {
        const result = await pool.query(
            `
            SELECT id
            FROM public.admins
            LIMIT 1
            `,
        );

        return res.status(200).json({
            success: true,
            exists: result.rows.length > 0,
        });
    } catch (error: any) {
        console.error(
            '❌ Error checking admin existence:',
            error,
        );

        return res.status(500).json({
            success: false,
            exists: false,
            error: 'Database error while checking admin existence.',
        });
    }
});

export default router;
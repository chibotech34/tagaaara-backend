import {
    Router,
    Response,
} from 'express';

import pool from '../config/database';

import {
    verifyFirebaseToken,
    AuthenticatedRequest,
} from '../middleware/firebaseAdmin';

const router = Router();

/*
|--------------------------------------------------------------------------
| POST /api/notifications/register-token
|--------------------------------------------------------------------------
|
| Registers an FCM token for the authenticated Firebase user.
|
| The client does NOT send the Firebase UID.
|
| The UID comes from:
|
| Authorization: Bearer <Firebase ID token>
|
|--------------------------------------------------------------------------
*/

router.post(
    '/register-token',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const uid =
                req.decodedToken?.uid;

            if (
                !uid ||
                typeof uid !== 'string' ||
                !uid.trim()
            ) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            const token =
                req.body?.token;

            const deviceType =
                typeof req.body?.deviceType ===
                    'string' &&
                    req.body.deviceType.trim()
                    ? req.body.deviceType.trim()
                    : 'mobile';

            if (
                typeof token !== 'string' ||
                !token.trim()
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'A valid FCM token is required.',
                });
            }

            const cleanToken =
                token.trim();

            /*
            |--------------------------------------------------------------------------
            | Verify that the authenticated user is a passenger or driver.
            |--------------------------------------------------------------------------
            */

            const userResult =
                await pool.query(
                    `
                    SELECT
                        'driver' AS user_type
                    FROM public.drivers
                    WHERE uid = $1::text

                    UNION ALL

                    SELECT
                        'passenger' AS user_type
                    FROM public.passengers
                    WHERE firebase_uid = $1::text

                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                userResult.rows.length ===
                0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger or driver profile not found.',
                });
            }

            const userType =
                userResult.rows[0]
                    .user_type;

            /*
            |--------------------------------------------------------------------------
            | Upsert FCM token
            |--------------------------------------------------------------------------
            */

            const result =
                await pool.query(
                    `
                    INSERT INTO public.fcm_tokens
                    (
                        user_id,
                        token,
                        device_type,
                        created_at,
                        updated_at
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        NOW(),
                        NOW()
                    )
                    ON CONFLICT
                    (
                        user_id,
                        token
                    )
                    DO UPDATE SET
                        device_type =
                            EXCLUDED.device_type,
                        updated_at =
                            NOW()
                    RETURNING
                        id,
                        user_id,
                        token,
                        device_type,
                        created_at,
                        updated_at
                    `,
                    [
                        uid,
                        cleanToken,
                        deviceType,
                    ],
                );

            console.log(
                `✅ FCM token registered: ${userType} ${uid}`,
            );

            return res.status(200).json({
                success: true,
                message:
                    'FCM token registered successfully.',
                userType,
                tokenId:
                    result.rows[0].id,
            });
        } catch (error: unknown) {
            console.error(
                '❌ FCM token registration error:',
                error,
            );

            const dbError =
                error as {
                    code?: string;
                    message?: string;
                };

            return res.status(500).json({
                success: false,
                message:
                    'Server error while registering FCM token.',
                code:
                    dbError.code ||
                    'FCM_TOKEN_REGISTRATION_ERROR',
                error:
                    dbError.message ||
                    'Unknown error',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| DELETE /api/notifications/token
|--------------------------------------------------------------------------
|
| Removes one token from the authenticated user.
|
|--------------------------------------------------------------------------
*/

router.delete(
    '/token',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const uid =
                req.decodedToken?.uid;

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            const token =
                req.body?.token;

            if (
                typeof token !== 'string' ||
                !token.trim()
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'A valid FCM token is required.',
                });
            }

            const result =
                await pool.query(
                    `
                    DELETE FROM public.fcm_tokens
                    WHERE user_id = $1
                      AND token = $2
                    `,
                    [
                        uid,
                        token.trim(),
                    ],
                );

            return res.status(200).json({
                success: true,
                message:
                    'FCM token removed successfully.',
                deleted:
                    result.rowCount || 0,
            });
        } catch (error) {
            console.error(
                '❌ FCM token deletion error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while deleting FCM token.',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /api/notifications/tokens
|--------------------------------------------------------------------------
|
| Debug endpoint.
|
| Returns token metadata but NEVER exposes the actual FCM token.
|
|--------------------------------------------------------------------------
*/

router.get(
    '/tokens',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const uid =
                req.decodedToken?.uid;

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        device_type,
                        created_at,
                        updated_at
                    FROM public.fcm_tokens
                    WHERE user_id = $1
                    ORDER BY updated_at DESC
                    `,
                    [uid],
                );

            return res.status(200).json({
                success: true,
                tokens:
                    result.rows,
            });
        } catch (error) {
            console.error(
                '❌ Get FCM tokens error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while fetching FCM tokens.',
            });
        }
    },
);

export default router;
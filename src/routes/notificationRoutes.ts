// routes/notificationRoutes.ts

import {
    Router,
    Request,
    Response,
    NextFunction,
} from 'express';

import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';

const router = Router();

/*
|--------------------------------------------------------------------------
| Types
|--------------------------------------------------------------------------
*/

interface DecodedFirebaseToken {
    uid: string;
    email?: string;
    name?: string;
}

interface AuthedRequest extends Request {
    decodedToken?: DecodedFirebaseToken;
}

/*
|--------------------------------------------------------------------------
| Firebase ID Token middleware (same shape as driverRoutes.ts)
|--------------------------------------------------------------------------
*/

const verifyFirebaseToken = async (
    req: AuthedRequest,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (
        !authHeader ||
        !authHeader.startsWith('Bearer ')
    ) {
        res.status(401).json({
            success: false,
            message:
                'Missing or invalid Authorization header. Expected Bearer token.',
            code: 'AUTH_HEADER_MISSING',
        });
        return;
    }

    const token = authHeader
        .substring('Bearer '.length)
        .trim();

    if (!token) {
        res.status(401).json({
            success: false,
            message: 'Firebase ID token is missing.',
            code: 'AUTH_TOKEN_MISSING',
        });
        return;
    }

    try {
        const decoded = await firebaseAuth.verifyIdToken(token);

        req.decodedToken = {
            uid: decoded.uid,
            email: decoded.email,
            name: decoded.name,
        };

        next();
    } catch (error: unknown) {
        console.error(
            '❌ Notification route token verification failed:',
            error,
        );

        const fbErr = error as { code?: string };

        if (fbErr.code === 'auth/id-token-expired') {
            res.status(401).json({
                success: false,
                message:
                    'Firebase ID token expired. Please refresh authentication and try again.',
                code: 'AUTH_TOKEN_EXPIRED',
            });
            return;
        }

        if (fbErr.code === 'auth/id-token-revoked') {
            res.status(401).json({
                success: false,
                message:
                    'Firebase ID token has been revoked. Please sign in again.',
                code: 'AUTH_TOKEN_REVOKED',
            });
            return;
        }

        res.status(401).json({
            success: false,
            message: 'Firebase authentication failed.',
            code: 'AUTH_TOKEN_INVALID',
        });
    }
};

/*
|--------------------------------------------------------------------------
| Helper: resolve the numeric driver id from the Firebase UID
|--------------------------------------------------------------------------
|
| driver_notifications.driver_id references public.drivers.id (numeric PK).
| The authenticated identity is a Firebase UID, so we must translate.
|
*/

const resolveDriverId = async (
    uid: string,
): Promise<number | null> => {
    const r = await pool.query(
        `
        SELECT id
        FROM public.drivers
        WHERE uid = $1
        LIMIT 1
        `,
        [uid],
    );

    return r.rows[0]?.id ?? null;
};

/*
|--------------------------------------------------------------------------
| Helper: normalise a route param
|--------------------------------------------------------------------------
*/

const normaliseParam = (
    value: string | string[] | undefined,
): string => {
    if (value === undefined) return '';
    return Array.isArray(value) ? value[0] ?? '' : value;
};

/* ==========================================================================
 * FCM TOKEN REGISTRATION
 * ==========================================================================
 *
 * The Flutter app calls POST /api/notifications/register-token right
 * after every successful login (driver or passenger). The token is
 * stored in public.fcm_tokens, keyed by the Firebase UID so both roles
 * share the same table.
 *
 * Backend senders (rideRoutes.ts, passengerWalletRoutes.ts) already
 * look up tokens with:
 *
 *   SELECT token FROM public.fcm_tokens
 *   WHERE user_id = $1::text
 *   ORDER BY updated_at DESC NULLS LAST LIMIT 1
 *
 * so this endpoint must keep that contract.
 * ========================================================================== */

router.post(
    '/register-token',
    verifyFirebaseToken,
    async (req: AuthedRequest, res: Response) => {
        try {
            const uid = req.decodedToken?.uid;

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const token =
                typeof req.body?.token === 'string'
                    ? req.body.token.trim()
                    : '';

            const deviceType =
                typeof req.body?.deviceType === 'string' &&
                    req.body.deviceType.trim()
                    ? req.body.deviceType.trim()
                    : 'mobile';

            const userIdFromBody =
                typeof req.body?.userId === 'string'
                    ? req.body.userId.trim()
                    : '';

            // The authenticated UID and the body's userId must match.
            // (Prevents registering a device for a different user.)
            if (userIdFromBody && userIdFromBody !== uid) {
                return res.status(403).json({
                    success: false,
                    message:
                        'userId in body does not match the authenticated user.',
                    code: 'UID_MISMATCH',
                });
            }

            if (!token) {
                return res.status(400).json({
                    success: false,
                    message: 'FCM token is required.',
                    code: 'TOKEN_MISSING',
                });
            }

            /*
            |------------------------------------------------------------------
            | Upsert: one row per (user_id, token).
            |------------------------------------------------------------------
            | Unique constraint expected:
            |   UNIQUE (user_id, token)  OR  UNIQUE (token)
            |
            | The ON CONFLICT target is (token) — a device's FCM token is
            | globally unique, so if a device changes users we simply
            | overwrite the user_id.
            */

            await pool.query(
                `
                INSERT INTO public.fcm_tokens (
                    user_id,
                    token,
                    device_type,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1::text,
                    $2::text,
                    $3::varchar,
                    NOW(),
                    NOW()
                )
                ON CONFLICT (token)
                DO UPDATE SET
                    user_id     = EXCLUDED.user_id,
                    device_type = EXCLUDED.device_type,
                    updated_at  = NOW()
                `,
                [uid, token, deviceType],
            );

            console.log(
                `✅ FCM token registered for ${uid} (${deviceType})`
            );

            return res.status(200).json({
                success: true,
                message: 'FCM token registered.',
            });
        } catch (error: unknown) {
            console.error(
                '❌ POST /notifications/register-token failed:',
                error,
            );

            const dbError = error as {
                code?: string;
                message?: string;
                detail?: string;
            };

            return res.status(500).json({
                success: false,
                message: 'Failed to register FCM token.',
                code: dbError.code ?? 'FCM_REGISTER_FAILED',
                detail: dbError.detail ?? null,
            });
        }
    },
);

/* ==========================================================================
 * FCM TOKEN UNREGISTRATION (logout)
 * ========================================================================== */

router.post(
    '/unregister-token',
    verifyFirebaseToken,
    async (req: AuthedRequest, res: Response) => {
        try {
            const uid = req.decodedToken?.uid;

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const token =
                typeof req.body?.token === 'string'
                    ? req.body.token.trim()
                    : '';

            if (token) {
                await pool.query(
                    `
                    DELETE FROM public.fcm_tokens
                    WHERE user_id = $1::text
                      AND token   = $2::text
                    `,
                    [uid, token],
                );
            } else {
                // No token provided → clear all tokens for this user.
                await pool.query(
                    `
                    DELETE FROM public.fcm_tokens
                    WHERE user_id = $1::text
                    `,
                    [uid],
                );
            }

            console.log(`🗑️ FCM token unregistered for ${uid}`);

            return res.status(200).json({
                success: true,
                message: 'FCM token unregistered.',
            });
        } catch (error: unknown) {
            console.error(
                '❌ POST /notifications/unregister-token failed:',
                error,
            );

            return res.status(500).json({
                success: false,
                message: 'Failed to unregister FCM token.',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /api/notifications
|--------------------------------------------------------------------------
|
| Query params:
|   - page        (default 1)
|   - limit       (default 20, max 100)
|   - category    (optional)
|   - unreadOnly  ('true' | 'false', default false)
|
| Response shape matches driver_notification_service.dart:
|   {
|     success: true,
|     notifications: [...],
|     pagination: { page, limit, total, pages },
|     unreadCount: <int>
|   }
|
|--------------------------------------------------------------------------
*/

router.get(
    '/',
    verifyFirebaseToken,
    async (req: AuthedRequest, res: Response) => {
        try {
            const uid = req.decodedToken?.uid;
            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const driverId = await resolveDriverId(uid);
            if (driverId === null) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            const page = Math.max(
                parseInt(String(req.query.page ?? '1'), 10) || 1,
                1,
            );

            const limit = Math.min(
                Math.max(
                    parseInt(String(req.query.limit ?? '20'), 10) || 20,
                    1,
                ),
                100,
            );

            const offset = (page - 1) * limit;

            const category =
                typeof req.query.category === 'string' &&
                    req.query.category.trim().length > 0
                    ? req.query.category.trim()
                    : null;

            const unreadOnly =
                String(req.query.unreadOnly ?? 'false') === 'true';

            const where: string[] = ['driver_id = $1'];
            const values: unknown[] = [driverId];
            let idx = 2;

            if (category) {
                where.push(`category = $${idx++}`);
                values.push(category);
            }

            if (unreadOnly) {
                where.push(`is_read = FALSE`);
            }

            const whereSql = `WHERE ${where.join(' AND ')}`;

            const countRes = await pool.query(
                `
                SELECT
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE is_read = FALSE)::int AS unread
                FROM public.driver_notifications
                ${whereSql}
                `,
                values,
            );

            const total: number = countRes.rows[0]?.total ?? 0;
            const unreadCount: number =
                countRes.rows[0]?.unread ?? 0;

            const dataRes = await pool.query(
                `
                SELECT
                    id,
                    driver_id,
                    type,
                    category,
                    title,
                    message,
                    priority,
                    ride_id,
                    transaction_id,
                    withdrawal_id,
                    target_screen,
                    metadata,
                    is_read,
                    read_at,
                    created_at
                FROM public.driver_notifications
                ${whereSql}
                ORDER BY created_at DESC
                LIMIT $${idx} OFFSET $${idx + 1}
                `,
                [...values, limit, offset],
            );

            return res.status(200).json({
                success: true,
                notifications: dataRes.rows,
                pagination: {
                    page,
                    limit,
                    total,
                    pages: Math.max(1, Math.ceil(total / limit)),
                },
                unreadCount,
            });
        } catch (error: unknown) {
            console.error(
                '❌ GET /notifications failed:',
                error,
            );

            return res.status(500).json({
                success: false,
                message: 'Failed to load notifications.',
                code: 'NOTIFICATIONS_FETCH_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /api/notifications/unread-count
|--------------------------------------------------------------------------
|
| IMPORTANT: declared BEFORE any '/:id' route.
|
*/

router.get(
    '/unread-count',
    verifyFirebaseToken,
    async (req: AuthedRequest, res: Response) => {
        try {
            const uid = req.decodedToken?.uid;
            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const driverId = await resolveDriverId(uid);
            if (driverId === null) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            const r = await pool.query(
                `
                SELECT COUNT(*)::int AS c
                FROM public.driver_notifications
                WHERE driver_id = $1
                  AND is_read = FALSE
                `,
                [driverId],
            );

            return res.status(200).json({
                success: true,
                unreadCount: r.rows[0]?.c ?? 0,
            });
        } catch (error: unknown) {
            console.error(
                '❌ GET /notifications/unread-count failed:',
                error,
            );

            return res.status(200).json({
                success: true,
                unreadCount: 0,
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| PATCH /api/notifications/read-all
|--------------------------------------------------------------------------
*/

router.patch(
    '/read-all',
    verifyFirebaseToken,
    async (req: AuthedRequest, res: Response) => {
        try {
            const uid = req.decodedToken?.uid;
            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const driverId = await resolveDriverId(uid);
            if (driverId === null) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            await pool.query(
                `
                UPDATE public.driver_notifications
                SET
                    is_read = TRUE,
                    read_at = NOW()
                WHERE driver_id = $1
                  AND is_read = FALSE
                `,
                [driverId],
            );

            return res.status(200).json({
                success: true,
                message: 'All notifications marked as read.',
            });
        } catch (error: unknown) {
            console.error(
                '❌ PATCH /notifications/read-all failed:',
                error,
            );

            return res.status(500).json({
                success: false,
                message: 'Failed to mark notifications as read.',
                code: 'READ_ALL_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| PATCH /api/notifications/:id/read
|--------------------------------------------------------------------------
*/

router.patch(
    '/:id/read',
    verifyFirebaseToken,
    async (req: AuthedRequest, res: Response) => {
        try {
            const uid = req.decodedToken?.uid;
            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const driverId = await resolveDriverId(uid);
            if (driverId === null) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            const id = normaliseParam(req.params.id);
            if (!/^\d+$/.test(id)) {
                return res.status(400).json({
                    success: false,
                    message: 'Notification id must be numeric.',
                    code: 'INVALID_NOTIFICATION_ID',
                });
            }

            const r = await pool.query(
                `
                UPDATE public.driver_notifications
                SET
                    is_read = TRUE,
                    read_at = NOW()
                WHERE id = $1
                  AND driver_id = $2
                RETURNING id
                `,
                [id, driverId],
            );

            if (r.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Notification not found.',
                    code: 'NOTIFICATION_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message: 'Notification marked as read.',
            });
        } catch (error: unknown) {
            console.error(
                '❌ PATCH /notifications/:id/read failed:',
                error,
            );

            return res.status(500).json({
                success: false,
                message: 'Failed to mark notification as read.',
                code: 'MARK_READ_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| DELETE /api/notifications/:id
|--------------------------------------------------------------------------
*/

router.delete(
    '/:id',
    verifyFirebaseToken,
    async (req: AuthedRequest, res: Response) => {
        try {
            const uid = req.decodedToken?.uid;
            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const driverId = await resolveDriverId(uid);
            if (driverId === null) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            const id = normaliseParam(req.params.id);
            if (!/^\d+$/.test(id)) {
                return res.status(400).json({
                    success: false,
                    message: 'Notification id must be numeric.',
                    code: 'INVALID_NOTIFICATION_ID',
                });
            }

            const r = await pool.query(
                `
                DELETE FROM public.driver_notifications
                WHERE id = $1
                  AND driver_id = $2
                RETURNING id
                `,
                [id, driverId],
            );

            if (r.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Notification not found.',
                    code: 'NOTIFICATION_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message: 'Notification deleted.',
            });
        } catch (error: unknown) {
            console.error(
                '❌ DELETE /notifications/:id failed:',
                error,
            );

            return res.status(500).json({
                success: false,
                message: 'Failed to delete notification.',
                code: 'DELETE_NOTIFICATION_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| DELETE /api/notifications   (clear all)
|--------------------------------------------------------------------------
*/

router.delete(
    '/',
    verifyFirebaseToken,
    async (req: AuthedRequest, res: Response) => {
        try {
            const uid = req.decodedToken?.uid;
            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const driverId = await resolveDriverId(uid);
            if (driverId === null) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            await pool.query(
                `
                DELETE FROM public.driver_notifications
                WHERE driver_id = $1
                `,
                [driverId],
            );

            return res.status(200).json({
                success: true,
                message: 'All notifications cleared.',
            });
        } catch (error: unknown) {
            console.error(
                '❌ DELETE /notifications failed:',
                error,
            );

            return res.status(500).json({
                success: false,
                message: 'Failed to clear notifications.',
                code: 'CLEAR_NOTIFICATIONS_FAILED',
            });
        }
    },
);

export default router;
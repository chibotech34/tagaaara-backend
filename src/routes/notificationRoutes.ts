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

            // Badge is non-critical: return 0 rather than 500.
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
|
| IMPORTANT: declared BEFORE any '/:id/read' route, otherwise
| '/read-all' would be interpreted as an id.
|
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
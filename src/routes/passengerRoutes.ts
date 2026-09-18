// src/routes/passengerRoutes.ts

import {
    Router,
    Request,
    Response,
    NextFunction,
} from 'express';

import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';

const router = Router();

/* ==========================================================================
 * TYPES
 * ========================================================================== */

interface DecodedFirebaseToken {
    uid: string;
    email?: string;
    name?: string;
    phone_number?: string;
}

interface AuthenticatedRequest extends Request {
    decodedToken?: DecodedFirebaseToken;
}

/* ==========================================================================
 * FIREBASE ID-TOKEN MIDDLEWARE
 * ========================================================================== */

const verifyFirebaseToken = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
            success: false,
            message: 'Missing or invalid Authorization header.',
            code: 'AUTH_HEADER_MISSING',
        });
        return;
    }

    const token = authHeader.substring('Bearer '.length).trim();

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
            phone_number: decoded.phone_number,
        };

        next();
    } catch (err: unknown) {
        console.error('❌ Firebase token verification failed:', err);

        const firebaseError = err as { code?: string };

        if (firebaseError.code === 'auth/id-token-expired') {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token expired.',
                code: 'AUTH_TOKEN_EXPIRED',
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

/* ==========================================================================
 * GET AUTHENTICATED FIREBASE UID
 * ========================================================================== */

const getAuthenticatedUid = (
    req: AuthenticatedRequest,
): string | null => {
    return req.decodedToken?.uid ?? null;
};

/* ==========================================================================
 * GET /api/passengers/profile
 * ========================================================================== */

router.get(
    '/profile',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const result = await pool.query(
                `
                SELECT
                    id,
                    firebase_uid,
                    full_name,
                    phone,
                    email,
                    gender,
                    emergency_contact_name,
                    emergency_contact_phone,
                    emergency_relationship,
                    home_address,
                    region,
                    district,
                    town_city,
                    saved_locations,
                    preferred_payment_method,
                    mobile_money_number,
                    language_preference,
                    notification_enabled,
                    privacy_enabled,
                    created_at,
                    profile_photo_url,
                    account_status,
                    phone_verified,
                    email_verified,
                    updated_at,
                    is_online,
                    last_online_at,
                    current_latitude,
                    current_longitude,
                    last_location_update,
                    fcm_token
                FROM public.passengers
                WHERE firebase_uid = $1
                LIMIT 1
                `,
                [uid],
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger profile not found.',
                    code: 'PASSENGER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                passenger: result.rows[0],
            });
        } catch (error: unknown) {
            const e = error as { message?: string; code?: string };

            console.error('❌ Error fetching passenger profile:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch passenger profile.',
                code: 'PASSENGER_FETCH_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * PATCH /api/passengers/profile
 * ========================================================================== */

router.patch(
    '/profile',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const client = await pool.connect();
        let transactionStarted = false;

        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                client.release();
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required.',
                    code: 'AUTH_REQUIRED',
                });
            }

            const body = req.body ?? {};

            if (
                typeof body !== 'object' ||
                Array.isArray(body) ||
                body === null
            ) {
                client.release();
                return res.status(400).json({
                    success: false,
                    message: 'Request body must be a JSON object.',
                    code: 'INVALID_REQUEST_BODY',
                });
            }

            const receivedFields = Object.keys(body);

            if (receivedFields.length === 0) {
                client.release();
                return res.status(400).json({
                    success: false,
                    message: 'No profile fields were provided for update.',
                    code: 'NO_FIELDS_TO_UPDATE',
                });
            }

            const allowedFields = new Set([
                'full_name',
                'phone',
                'email',
                'gender',
                'emergency_contact_name',
                'emergency_contact_phone',
                'emergency_relationship',
                'home_address',
                'region',
                'district',
                'town_city',
                'saved_locations',
                'preferred_payment_method',
                'mobile_money_number',
                'language_preference',
                'notification_enabled',
                'privacy_enabled',
                'profile_photo_url',
            ]);

            const unknownFields = receivedFields.filter(
                (field) => !allowedFields.has(field),
            );

            if (unknownFields.length > 0) {
                client.release();
                return res.status(400).json({
                    success: false,
                    message: 'One or more fields cannot be updated.',
                    code: 'INVALID_PROFILE_FIELDS',
                    fields: unknownFields,
                });
            }

            const updateParts: string[] = [];
            const values: unknown[] = [];

            const addField = (column: string, value: unknown): void => {
                values.push(value);
                updateParts.push(`${column} = $${values.length}`);
            };

            if (Object.prototype.hasOwnProperty.call(body, 'full_name')) {
                const fullName = String(body.full_name ?? '').trim();

                if (!fullName) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Full name cannot be empty.',
                        code: 'INVALID_FULL_NAME',
                    });
                }

                if (fullName.length > 150) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Full name is too long.',
                        code: 'INVALID_FULL_NAME',
                    });
                }

                addField('full_name', fullName);
            }

            if (Object.prototype.hasOwnProperty.call(body, 'phone')) {
                const phone = String(body.phone ?? '').trim();

                if (phone && phone.length > 30) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Phone number is invalid.',
                        code: 'INVALID_PHONE',
                    });
                }

                addField('phone', phone || null);
            }

            if (Object.prototype.hasOwnProperty.call(body, 'email')) {
                const email = String(body.email ?? '').trim().toLowerCase();

                if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Please provide a valid email address.',
                        code: 'INVALID_EMAIL',
                    });
                }

                addField('email', email || null);
            }

            if (Object.prototype.hasOwnProperty.call(body, 'gender')) {
                const gender = String(body.gender ?? '').trim();

                if (gender.length > 50) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Gender value is too long.',
                        code: 'INVALID_GENDER',
                    });
                }

                addField('gender', gender || null);
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'emergency_contact_name',
                )
            ) {
                const name = String(body.emergency_contact_name ?? '').trim();

                if (name.length > 150) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Emergency contact name is too long.',
                        code: 'INVALID_EMERGENCY_NAME',
                    });
                }

                addField('emergency_contact_name', name || null);
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'emergency_contact_phone',
                )
            ) {
                const phone = String(body.emergency_contact_phone ?? '').trim();

                if (phone.length > 30) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Emergency contact phone number is invalid.',
                        code: 'INVALID_EMERGENCY_PHONE',
                    });
                }

                addField('emergency_contact_phone', phone || null);
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'emergency_relationship',
                )
            ) {
                const relationship = String(
                    body.emergency_relationship ?? '',
                ).trim();

                if (relationship.length > 100) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Emergency relationship is too long.',
                        code: 'INVALID_EMERGENCY_RELATIONSHIP',
                    });
                }

                addField('emergency_relationship', relationship || null);
            }

            if (Object.prototype.hasOwnProperty.call(body, 'home_address')) {
                const address = String(body.home_address ?? '').trim();

                if (address.length > 255) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Home address is too long.',
                        code: 'INVALID_HOME_ADDRESS',
                    });
                }

                addField('home_address', address || null);
            }

            if (Object.prototype.hasOwnProperty.call(body, 'region')) {
                const region = String(body.region ?? '').trim();

                if (region.length > 100) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Region value is too long.',
                        code: 'INVALID_REGION',
                    });
                }

                addField('region', region || null);
            }

            if (Object.prototype.hasOwnProperty.call(body, 'district')) {
                const district = String(body.district ?? '').trim();

                if (district.length > 100) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'District value is too long.',
                        code: 'INVALID_DISTRICT',
                    });
                }

                addField('district', district || null);
            }

            if (Object.prototype.hasOwnProperty.call(body, 'town_city')) {
                const townCity = String(body.town_city ?? '').trim();

                if (townCity.length > 100) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Town/City value is too long.',
                        code: 'INVALID_TOWN_CITY',
                    });
                }

                addField('town_city', townCity || null);
            }

            if (
                Object.prototype.hasOwnProperty.call(body, 'saved_locations')
            ) {
                const savedLocations = body.saved_locations;

                if (!Array.isArray(savedLocations)) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'saved_locations must be an array.',
                        code: 'INVALID_SAVED_LOCATIONS',
                    });
                }

                values.push(JSON.stringify(savedLocations));
                updateParts.push(
                    `saved_locations = $${values.length}::jsonb`,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'preferred_payment_method',
                )
            ) {
                const paymentMethod = String(
                    body.preferred_payment_method ?? '',
                ).trim();

                if (paymentMethod.length > 100) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Preferred payment method is too long.',
                        code: 'INVALID_PAYMENT_METHOD',
                    });
                }

                addField('preferred_payment_method', paymentMethod || null);
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'mobile_money_number',
                )
            ) {
                const mobileMoney = String(
                    body.mobile_money_number ?? '',
                ).trim();

                if (mobileMoney.length > 30) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Mobile money number is invalid.',
                        code: 'INVALID_MOBILE_MONEY_NUMBER',
                    });
                }

                addField('mobile_money_number', mobileMoney || null);
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'language_preference',
                )
            ) {
                const language = String(
                    body.language_preference ?? '',
                ).trim();

                if (language.length > 50) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Language value is too long.',
                        code: 'INVALID_LANGUAGE',
                    });
                }

                addField('language_preference', language || null);
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'notification_enabled',
                )
            ) {
                const notificationValue = body.notification_enabled;

                if (typeof notificationValue !== 'boolean') {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'notification_enabled must be true or false.',
                        code: 'INVALID_NOTIFICATION_VALUE',
                    });
                }

                addField('notification_enabled', notificationValue);
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'privacy_enabled',
                )
            ) {
                const privacyValue = body.privacy_enabled;

                if (typeof privacyValue !== 'boolean') {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'privacy_enabled must be true or false.',
                        code: 'INVALID_PRIVACY_VALUE',
                    });
                }

                addField('privacy_enabled', privacyValue);
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'profile_photo_url',
                )
            ) {
                const photoUrl = String(body.profile_photo_url ?? '').trim();

                if (photoUrl.length > 1000) {
                    client.release();
                    return res.status(400).json({
                        success: false,
                        message: 'Profile photo URL is too long.',
                        code: 'INVALID_PROFILE_PHOTO_URL',
                    });
                }

                addField('profile_photo_url', photoUrl || null);
            }

            if (updateParts.length === 0) {
                client.release();
                return res.status(400).json({
                    success: false,
                    message: 'No valid profile fields were provided.',
                    code: 'NO_VALID_FIELDS',
                });
            }

            updateParts.push('updated_at = CURRENT_TIMESTAMP');

            await client.query('BEGIN');
            transactionStarted = true;

            const passengerResult = await client.query(
                `
                SELECT id, firebase_uid
                FROM public.passengers
                WHERE firebase_uid = $1
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                await client.query('ROLLBACK');
                transactionStarted = false;
                client.release();

                return res.status(404).json({
                    success: false,
                    message: 'Passenger profile not found.',
                    code: 'PASSENGER_NOT_FOUND',
                });
            }

            values.push(uid);
            const uidParameter = values.length;

            const updateResult = await client.query(
                `
                UPDATE public.passengers
                SET
                    ${updateParts.join(', ')}
                WHERE firebase_uid = $${uidParameter}
                RETURNING
                    id,
                    firebase_uid,
                    full_name,
                    phone,
                    email,
                    gender,
                    emergency_contact_name,
                    emergency_contact_phone,
                    emergency_relationship,
                    home_address,
                    region,
                    district,
                    town_city,
                    saved_locations,
                    preferred_payment_method,
                    mobile_money_number,
                    language_preference,
                    notification_enabled,
                    privacy_enabled,
                    created_at,
                    profile_photo_url,
                    account_status,
                    phone_verified,
                    email_verified,
                    updated_at,
                    is_online,
                    last_online_at,
                    current_latitude,
                    current_longitude,
                    last_location_update,
                    fcm_token
                `,
                values,
            );

            if (updateResult.rows.length === 0) {
                await client.query('ROLLBACK');
                transactionStarted = false;
                client.release();

                return res.status(404).json({
                    success: false,
                    message: 'Passenger profile could not be updated.',
                    code: 'PROFILE_UPDATE_FAILED',
                });
            }

            await client.query('COMMIT');
            transactionStarted = false;
            client.release();

            console.log(
                `✅ Passenger profile updated: ${uid}`,
                receivedFields,
            );

            return res.status(200).json({
                success: true,
                message: 'Profile updated successfully.',
                updatedFields: receivedFields,
                passenger: updateResult.rows[0],
            });
        } catch (error: unknown) {
            if (transactionStarted) {
                try {
                    await client.query('ROLLBACK');
                } catch (rollbackError) {
                    console.error('❌ Rollback error:', rollbackError);
                }
            }

            client.release();

            const e = error as {
                message?: string;
                code?: string;
                detail?: string;
                constraint?: string;
            };

            console.error('❌ Update passenger profile error:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to update passenger profile.',
                code: e.code || 'PROFILE_UPDATE_FAILED',
                error: e.message || 'Unknown database error',
                detail: e.detail || null,
                constraint: e.constraint || null,
            });
        }
    },
);

/* ==========================================================================
 * GET /api/passengers/alerts
 * ========================================================================== */

router.get(
    '/alerts',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const result = await pool.query(
                `
                SELECT
                    id,
                    user_id,
                    title,
                    body,
                    category,
                    priority,
                    is_read,
                    target_screen,
                    metadata,
                    created_at
                FROM public.alerts
                WHERE user_id = $1
                ORDER BY created_at DESC
                `,
                [uid],
            );

            const unreadResult = await pool.query(
                `
                SELECT
                    COUNT(*)::int AS unread_count
                FROM public.alerts
                WHERE user_id = $1
                  AND is_read = false
                `,
                [uid],
            );

            const unreadCount = Number(
                unreadResult.rows[0]?.unread_count ?? 0,
            );

            return res.status(200).json({
                success: true,
                count: result.rows.length,
                unreadCount,
                alerts: result.rows,
            });
        } catch (error: unknown) {
            const e = error as { message?: string };

            console.error('❌ Error fetching passenger alerts:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to load alerts.',
                code: 'ALERTS_FETCH_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * PATCH /api/passengers/alerts/:alertId/read
 * ========================================================================== */

router.patch(
    '/alerts/:alertId/read',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const alertId = Number(req.params.alertId);

            if (!Number.isInteger(alertId) || alertId <= 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid alert ID.',
                    code: 'INVALID_ALERT_ID',
                });
            }

            const result = await pool.query(
                `
                UPDATE public.alerts
                SET is_read = true
                WHERE id = $1
                  AND user_id = $2
                RETURNING
                    id,
                    user_id,
                    title,
                    body,
                    category,
                    priority,
                    is_read,
                    target_screen,
                    metadata,
                    created_at
                `,
                [alertId, uid],
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Alert not found.',
                    code: 'ALERT_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message: 'Alert marked as read.',
                alert: result.rows[0],
            });
        } catch (error: unknown) {
            const e = error as { message?: string };

            console.error('❌ Error marking alert as read:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to mark alert as read.',
                code: 'ALERT_READ_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * PATCH /api/passengers/alerts/read-all
 * ========================================================================== */

router.patch(
    '/alerts/read-all',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const result = await pool.query(
                `
                UPDATE public.alerts
                SET is_read = true
                WHERE user_id = $1
                  AND is_read = false
                RETURNING id
                `,
                [uid],
            );

            return res.status(200).json({
                success: true,
                message: 'All alerts marked as read.',
                updatedCount: result.rows.length,
            });
        } catch (error: unknown) {
            const e = error as { message?: string };

            console.error('❌ Error marking all alerts as read:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to mark all alerts as read.',
                code: 'ALERTS_READ_ALL_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * DELETE /api/passengers/alerts/:alertId
 * ========================================================================== */

router.delete(
    '/alerts/:alertId',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const alertId = Number(req.params.alertId);

            if (!Number.isInteger(alertId) || alertId <= 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid alert ID.',
                    code: 'INVALID_ALERT_ID',
                });
            }

            const result = await pool.query(
                `
                DELETE FROM public.alerts
                WHERE id = $1
                  AND user_id = $2
                RETURNING id
                `,
                [alertId, uid],
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Alert not found.',
                    code: 'ALERT_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message: 'Alert deleted successfully.',
                deletedId: alertId,
            });
        } catch (error: unknown) {
            const e = error as { message?: string };

            console.error('❌ Error deleting alert:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to delete alert.',
                code: 'ALERT_DELETE_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * DELETE /api/passengers/alerts
 * ========================================================================== */

router.delete(
    '/alerts',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const result = await pool.query(
                `
                DELETE FROM public.alerts
                WHERE user_id = $1
                RETURNING id
                `,
                [uid],
            );

            return res.status(200).json({
                success: true,
                message: 'All alerts cleared successfully.',
                deletedCount: result.rows.length,
            });
        } catch (error: unknown) {
            const e = error as { message?: string };

            console.error('❌ Error clearing passenger alerts:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to clear alerts.',
                code: 'ALERTS_CLEAR_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * POST /api/passengers/update-status
 * ========================================================================== */

router.post(
    '/update-status',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const { isOnline, latitude, longitude } = req.body ?? {};

            if (typeof isOnline !== 'boolean') {
                return res.status(400).json({
                    success: false,
                    message: 'isOnline must be a boolean.',
                    code: 'INVALID_STATUS',
                });
            }

            const hasCoords =
                latitude !== undefined &&
                longitude !== undefined &&
                Number.isFinite(Number(latitude)) &&
                Number.isFinite(Number(longitude));

            const result = hasCoords
                ? await pool.query(
                    `
                      UPDATE public.passengers
                      SET
                          is_online = $1,
                          current_latitude = $2::numeric,
                          current_longitude = $3::numeric,
                          last_location_update = NOW(),
                          last_online_at = NOW(),
                          updated_at = NOW()
                      WHERE firebase_uid = $4
                      RETURNING
                          id,
                          firebase_uid,
                          is_online,
                          current_latitude,
                          current_longitude,
                          last_online_at,
                          last_location_update
                      `,
                    [
                        isOnline,
                        Number(latitude),
                        Number(longitude),
                        uid,
                    ],
                )
                : await pool.query(
                    `
                      UPDATE public.passengers
                      SET
                          is_online = $1,
                          last_online_at = NOW(),
                          updated_at = NOW()
                      WHERE firebase_uid = $2
                      RETURNING
                          id,
                          firebase_uid,
                          is_online,
                          last_online_at
                      `,
                    [isOnline, uid],
                );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger not found.',
                    code: 'PASSENGER_NOT_FOUND',
                });
            }

            console.log('✅ PASSENGER STATUS UPDATED', result.rows[0]);

            return res.status(200).json({
                success: true,
                message: 'Passenger status updated.',
                passenger: result.rows[0],
            });
        } catch (error: unknown) {
            const e = error as { message?: string };

            console.error('❌ Error updating passenger status:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to update passenger status.',
                code: 'STATUS_UPDATE_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * GET /api/passengers/nearby
 * ========================================================================== */

router.get(
    '/nearby',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const { lat, lng, radius = 5000 } = req.query;

            if (lat === undefined || lng === undefined) {
                return res.status(400).json({
                    success: false,
                    message: 'Missing required query params: lat and lng.',
                    code: 'MISSING_PARAMETERS',
                });
            }

            const latitude = Number(lat);
            const longitude = Number(lng);
            const searchRadius = Number(radius);

            if (
                !Number.isFinite(latitude) ||
                !Number.isFinite(longitude) ||
                !Number.isFinite(searchRadius) ||
                searchRadius <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid numeric values for lat, lng, or radius.',
                    code: 'INVALID_PARAMETERS',
                });
            }

            const postgisQuery = `
                SELECT
                    id,
                    firebase_uid,
                    full_name,
                    phone,
                    profile_photo_url,
                    current_latitude,
                    current_longitude,
                    is_online,
                    last_online_at,
                    ROUND(
                        ST_Distance(
                            ST_SetSRID(
                                ST_MakePoint(
                                    current_longitude::double precision,
                                    current_latitude::double precision
                                ),
                                4326
                            )::geography,
                            ST_SetSRID(
                                ST_MakePoint(
                                    $1::double precision,
                                    $2::double precision
                                ),
                                4326
                            )::geography
                        )
                    )::int AS distance_meters
                FROM public.passengers
                WHERE is_online = true
                  AND account_status = 'active'
                  AND current_latitude IS NOT NULL
                  AND current_longitude IS NOT NULL
                  AND ST_DWithin(
                        ST_SetSRID(
                            ST_MakePoint(
                                current_longitude::double precision,
                                current_latitude::double precision
                            ),
                            4326
                        )::geography,
                        ST_SetSRID(
                            ST_MakePoint(
                                $1::double precision,
                                $2::double precision
                            ),
                            4326
                        )::geography,
                        $3::double precision
                    )
                ORDER BY distance_meters ASC
                LIMIT 50;
            `;

            const haversineQuery = `
                WITH candidates AS (
                    SELECT
                        id,
                        firebase_uid,
                        full_name,
                        phone,
                        profile_photo_url,
                        current_latitude,
                        current_longitude,
                        is_online,
                        last_online_at,
                        current_latitude::double precision AS lat_num,
                        current_longitude::double precision AS lng_num
                    FROM public.passengers
                    WHERE is_online = true
                      AND account_status = 'active'
                      AND current_latitude IS NOT NULL
                      AND current_longitude IS NOT NULL
                ),
                distances AS (
                    SELECT
                        *,
                        6371000 * 2 * ASIN(
                            SQRT(
                                POWER(
                                    SIN(
                                        RADIANS(
                                            lat_num -
                                            $2::double precision
                                        ) / 2
                                    ),
                                    2
                                ) +
                                COS(
                                    RADIANS(
                                        $2::double precision
                                    )
                                ) *
                                COS(
                                    RADIANS(lat_num)
                                ) *
                                POWER(
                                    SIN(
                                        RADIANS(
                                            lng_num -
                                            $1::double precision
                                        ) / 2
                                    ),
                                    2
                                )
                            )
                        ) AS distance_meters
                    FROM candidates
                )
                SELECT
                    id,
                    firebase_uid,
                    full_name,
                    phone,
                    profile_photo_url,
                    current_latitude,
                    current_longitude,
                    is_online,
                    last_online_at,
                    ROUND(distance_meters)::int AS distance_meters
                FROM distances
                WHERE distance_meters <= $3::double precision
                ORDER BY distance_meters ASC
                LIMIT 50;
            `;

            const params = [longitude, latitude, searchRadius];

            let result;

            try {
                result = await pool.query(postgisQuery, params);
            } catch (postgisErr: unknown) {
                const pe = postgisErr as { code?: string; message?: string };

                if (
                    pe.code === '42883' ||
                    pe.code === '42703' ||
                    pe.code === '42804'
                ) {
                    console.warn(
                        '⚠️ PostGIS unavailable. Falling back to Haversine.',
                        pe.message,
                    );

                    result = await pool.query(haversineQuery, params);
                } else {
                    throw postgisErr;
                }
            }

            return res.status(200).json({
                success: true,
                count: result.rows.length,
                passengers: result.rows,
            });
        } catch (error: unknown) {
            const e = error as { message?: string; code?: string };

            console.error('❌ Error fetching nearby passengers:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch nearby passengers.',
                code: 'NEARBY_PASSENGERS_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * GET /api/passengers/wallet
 * ========================================================================== */

router.get(
    '/wallet',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const passengerResult = await pool.query(
                `
                SELECT
                    id,
                    firebase_uid,
                    full_name,
                    phone,
                    email
                FROM public.passengers
                WHERE firebase_uid = $1
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger account not found.',
                    code: 'PASSENGER_NOT_FOUND',
                });
            }

            const passenger = passengerResult.rows[0];

            const walletResult = await pool.query(
                `
                SELECT
                    id,
                    passenger_id,
                    balance,
                    pending_balance,
                    total_spent,
                    last_transaction_at,
                    created_at,
                    updated_at
                FROM public.wallets
                WHERE passenger_id = $1
                LIMIT 1
                `,
                [passenger.id],
            );

            if (walletResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Wallet not found.',
                    code: 'WALLET_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                wallet: walletResult.rows[0],
            });
        } catch (error: unknown) {
            const e = error as { message?: string };

            console.error('❌ Error fetching passenger wallet:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch wallet.',
                code: 'WALLET_FETCH_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * POST /api/passengers/wallet
 * ========================================================================== */

router.post(
    '/wallet',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const passengerResult = await pool.query(
                `
                SELECT id
                FROM public.passengers
                WHERE firebase_uid = $1
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger account not found.',
                    code: 'PASSENGER_NOT_FOUND',
                });
            }

            const passengerId = passengerResult.rows[0].id;

            const existingWallet = await pool.query(
                `
                SELECT
                    id,
                    passenger_id,
                    balance,
                    pending_balance,
                    total_spent,
                    last_transaction_at,
                    created_at,
                    updated_at
                FROM public.wallets
                WHERE passenger_id = $1
                LIMIT 1
                `,
                [passengerId],
            );

            if (existingWallet.rows.length > 0) {
                return res.status(200).json({
                    success: true,
                    message: 'Wallet already exists.',
                    wallet: existingWallet.rows[0],
                    alreadyExists: true,
                });
            }

            const walletResult = await pool.query(
                `
                INSERT INTO public.wallets (
                    passenger_id,
                    balance,
                    pending_balance,
                    total_spent,
                    last_transaction_at,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1,
                    0.00,
                    0.00,
                    0.00,
                    NULL,
                    NOW(),
                    NOW()
                )
                RETURNING
                    id,
                    passenger_id,
                    balance,
                    pending_balance,
                    total_spent,
                    last_transaction_at,
                    created_at,
                    updated_at
                `,
                [passengerId],
            );

            return res.status(201).json({
                success: true,
                message: 'Wallet created successfully.',
                wallet: walletResult.rows[0],
                alreadyExists: false,
            });
        } catch (error: unknown) {
            const e = error as { message?: string; code?: string };

            console.error('❌ Error creating passenger wallet:', e);

            if (e.code === '23505') {
                return res.status(409).json({
                    success: false,
                    message: 'Wallet already exists.',
                    code: 'WALLET_ALREADY_EXISTS',
                });
            }

            return res.status(500).json({
                success: false,
                message: 'Failed to create wallet.',
                code: 'WALLET_CREATE_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * GET /api/passengers/transactions
 * ========================================================================== */

router.get(
    '/transactions',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const passengerResult = await pool.query(
                `
                SELECT id
                FROM public.passengers
                WHERE firebase_uid = $1
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger account not found.',
                    code: 'PASSENGER_NOT_FOUND',
                });
            }

            const passengerId = passengerResult.rows[0].id;

            let page = Number(req.query.page ?? 1);
            let limit = Number(req.query.limit ?? 20);

            if (!Number.isFinite(page) || page < 1) page = 1;
            if (!Number.isFinite(limit) || limit < 1) limit = 20;

            page = Math.floor(page);
            limit = Math.min(Math.floor(limit), 100);

            const offset = (page - 1) * limit;

            const type =
                typeof req.query.type === 'string'
                    ? req.query.type.trim()
                    : null;

            const status =
                typeof req.query.status === 'string'
                    ? req.query.status.trim()
                    : null;

            const conditions: string[] = ['t.passenger_id = $1'];
            const values: unknown[] = [passengerId];
            let parameterIndex = 2;

            if (type) {
                conditions.push(`t.type = $${parameterIndex}`);
                values.push(type);
                parameterIndex++;
            }

            if (status) {
                conditions.push(`t.status = $${parameterIndex}`);
                values.push(status);
                parameterIndex++;
            }

            const limitParameter = parameterIndex;
            const offsetParameter = parameterIndex + 1;

            values.push(limit);
            values.push(offset);

            const transactionQuery = `
                SELECT
                    t.id,
                    t.wallet_id,
                    t.passenger_id,
                    t.ride_id,
                    t.amount,
                    t.type,
                    t.status,
                    t.payment_method,
                    t.provider,
                    t.provider_reference,
                    t.balance_before,
                    t.balance_after,
                    t.description,
                    t.metadata,
                    t.created_at,
                    t.updated_at
                FROM public.transactions t
                WHERE ${conditions.join(' AND ')}
                ORDER BY t.created_at DESC
                LIMIT $${limitParameter}
                OFFSET $${offsetParameter}
            `;

            const result = await pool.query(transactionQuery, values);

            const countValues: unknown[] = [passengerId];
            const countConditions: string[] = ['passenger_id = $1'];
            let countParameterIndex = 2;

            if (type) {
                countConditions.push(`type = $${countParameterIndex}`);
                countValues.push(type);
                countParameterIndex++;
            }

            if (status) {
                countConditions.push(`status = $${countParameterIndex}`);
                countValues.push(status);
            }

            const countResult = await pool.query(
                `
                SELECT
                    COUNT(*)::int AS total
                FROM public.transactions
                WHERE ${countConditions.join(' AND ')}
                `,
                countValues,
            );

            const total = Number(countResult.rows[0]?.total ?? 0);

            return res.status(200).json({
                success: true,
                transactions: result.rows,
                count: result.rows.length,
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit),
            });
        } catch (error: unknown) {
            const e = error as { message?: string };

            console.error('❌ Error fetching wallet transactions:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch transactions.',
                code: 'TRANSACTIONS_FETCH_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * POST /api/passengers/wallet/topup
 *
 * DEVELOPMENT / TESTING VERSION
 * ========================================================================== */

router.post(
    '/wallet/topup',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const client = await pool.connect();
        let transactionStarted = false;

        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                client.release();
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const amount = Number(req.body?.amount);

            const paymentMethod =
                typeof req.body?.payment_method === 'string'
                    ? req.body.payment_method.trim()
                    : null;

            const provider =
                typeof req.body?.provider === 'string'
                    ? req.body.provider.trim()
                    : null;

            if (!Number.isFinite(amount) || amount <= 0) {
                client.release();
                return res.status(400).json({
                    success: false,
                    message: 'Top-up amount must be greater than zero.',
                    code: 'INVALID_AMOUNT',
                });
            }

            if (amount > 100000) {
                client.release();
                return res.status(400).json({
                    success: false,
                    message: 'Top-up amount is too large.',
                    code: 'AMOUNT_TOO_LARGE',
                });
            }

            await client.query('BEGIN');
            transactionStarted = true;

            const passengerResult = await client.query(
                `
                SELECT id
                FROM public.passengers
                WHERE firebase_uid = $1
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                await client.query('ROLLBACK');
                transactionStarted = false;
                client.release();

                return res.status(404).json({
                    success: false,
                    message: 'Passenger account not found.',
                    code: 'PASSENGER_NOT_FOUND',
                });
            }

            const passengerId = passengerResult.rows[0].id;

            const walletResult = await client.query(
                `
                SELECT
                    id,
                    passenger_id,
                    balance,
                    pending_balance,
                    total_spent,
                    last_transaction_at,
                    created_at,
                    updated_at
                FROM public.wallets
                WHERE passenger_id = $1
                FOR UPDATE
                `,
                [passengerId],
            );

            if (walletResult.rows.length === 0) {
                await client.query('ROLLBACK');
                transactionStarted = false;
                client.release();

                return res.status(404).json({
                    success: false,
                    message: 'Wallet not found.',
                    code: 'WALLET_NOT_FOUND',
                });
            }

            const wallet = walletResult.rows[0];
            const balanceBefore = Number(wallet.balance);
            const balanceAfter = balanceBefore + amount;

            const updatedWalletResult = await client.query(
                `
                UPDATE public.wallets
                SET
                    balance = $1,
                    last_transaction_at = NOW(),
                    updated_at = NOW()
                WHERE id = $2
                RETURNING
                    id,
                    passenger_id,
                    balance,
                    pending_balance,
                    total_spent,
                    last_transaction_at,
                    created_at,
                    updated_at
                `,
                [balanceAfter, wallet.id],
            );

            const transactionResult = await client.query(
                `
                INSERT INTO public.transactions (
                    wallet_id,
                    passenger_id,
                    ride_id,
                    amount,
                    type,
                    status,
                    payment_method,
                    provider,
                    provider_reference,
                    balance_before,
                    balance_after,
                    description,
                    metadata,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1,
                    $2,
                    NULL,
                    $3,
                    'topup',
                    'completed',
                    $4,
                    $5,
                    NULL,
                    $6,
                    $7,
                    $8,
                    $9::jsonb,
                    NOW(),
                    NOW()
                )
                RETURNING
                    id,
                    wallet_id,
                    passenger_id,
                    ride_id,
                    amount,
                    type,
                    status,
                    payment_method,
                    provider,
                    provider_reference,
                    balance_before,
                    balance_after,
                    description,
                    metadata,
                    created_at,
                    updated_at
                `,
                [
                    wallet.id,
                    passengerId,
                    amount,
                    paymentMethod,
                    provider,
                    balanceBefore,
                    balanceAfter,
                    'Wallet top-up',
                    JSON.stringify({ firebase_uid: uid }),
                ],
            );

            await client.query('COMMIT');
            transactionStarted = false;
            client.release();

            console.log(
                `💰 Wallet top-up: ` +
                `passenger=${passengerId}, ` +
                `amount=${amount}, ` +
                `balance=${balanceAfter}`,
            );

            return res.status(201).json({
                success: true,
                message: 'Wallet topped up successfully.',
                wallet: updatedWalletResult.rows[0],
                transaction: transactionResult.rows[0],
            });
        } catch (error: unknown) {
            if (transactionStarted) {
                try {
                    await client.query('ROLLBACK');
                } catch (rollbackError) {
                    console.error('❌ Rollback error:', rollbackError);
                }
            }

            client.release();

            const e = error as { message?: string; code?: string };

            console.error('❌ Error processing wallet top-up:', e);

            return res.status(500).json({
                success: false,
                message: 'Failed to process wallet top-up.',
                code: e.code ?? 'WALLET_TOPUP_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * POST /api/passengers/wallet/pay
 *
 * Debits the passenger wallet, marks the ride paid, and settles the
 * driver's pending earning into their withdrawable balance.
 *
 * The DB trigger `charge_driver_commission` runs on the `completed`
 * transition and does:
 *    driver_wallets.balance          -= tegaara_commission
 *    driver_wallets.pending_balance  += driver_earnings
 *    + inserts 'commission' and 'ride_earning' rows in driver_transactions
 *
 * This endpoint therefore only *settles* that pending earning into
 * withdrawable balance once the passenger actually pays.
 *
 * ★ The driver settlement block is wrapped in a SAVEPOINT so that any
 *   driver-side failure (trigger error, duplicate reference, missing
 *   wallet, etc.) can NEVER roll back the passenger's payment.
 * ========================================================================== */

router.post(
    '/wallet/pay',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const client = await pool.connect();
        let transactionStarted = false;

        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                client.release();
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const rideId = Number(req.body?.ride_id);
            const clientAmount = Number(req.body?.amount);

            if (!Number.isInteger(rideId) || rideId <= 0) {
                client.release();
                return res.status(400).json({
                    success: false,
                    message: 'Invalid ride ID.',
                    code: 'INVALID_RIDE_ID',
                });
            }

            if (!Number.isFinite(clientAmount) || clientAmount <= 0) {
                client.release();
                return res.status(400).json({
                    success: false,
                    message: 'Payment amount must be greater than zero.',
                    code: 'INVALID_AMOUNT',
                });
            }

            await client.query('BEGIN');
            transactionStarted = true;

            /* ------------------------------------------------------------
             * PASSENGER
             * ------------------------------------------------------------ */

            const passengerResult = await client.query(
                `
                SELECT id
                FROM public.passengers
                WHERE firebase_uid = $1
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                await client.query('ROLLBACK');
                transactionStarted = false;
                client.release();

                return res.status(404).json({
                    success: false,
                    message: 'Passenger account not found.',
                    code: 'PASSENGER_NOT_FOUND',
                });
            }

            const passengerId = passengerResult.rows[0].id;

            /* ------------------------------------------------------------
             * RIDE + LOCK
             * ------------------------------------------------------------ */

            const rideResult = await client.query(
                `
                SELECT
                    id,
                    passenger_id,
                    driver_id,
                    fare,
                    status,
                    payment_status,
                    driver_earnings,
                    tegaara_commission
                FROM public.rides
                WHERE id = $1
                  AND passenger_id = $2
                LIMIT 1
                FOR UPDATE
                `,
                [rideId, passengerId],
            );

            if (rideResult.rows.length === 0) {
                await client.query('ROLLBACK');
                transactionStarted = false;
                client.release();

                return res.status(404).json({
                    success: false,
                    message: 'Ride not found for this passenger.',
                    code: 'RIDE_NOT_FOUND',
                });
            }

            const ride = rideResult.rows[0];

            if (ride.status !== 'completed') {
                await client.query('ROLLBACK');
                transactionStarted = false;
                client.release();

                return res.status(409).json({
                    success: false,
                    message: 'Only completed rides can be paid for.',
                    code: 'RIDE_NOT_COMPLETED',
                    status: ride.status,
                });
            }

            if (ride.payment_status === 'paid') {
                await client.query('ROLLBACK');
                transactionStarted = false;
                client.release();

                return res.status(409).json({
                    success: false,
                    message: 'This ride has already been paid for.',
                    code: 'RIDE_ALREADY_PAID',
                    rideId,
                });
            }

            const amount = Number(ride.fare);

            if (!Number.isFinite(amount) || amount <= 0) {
                await client.query('ROLLBACK');
                transactionStarted = false;
                client.release();

                return res.status(400).json({
                    success: false,
                    message: 'Ride fare is invalid.',
                    code: 'INVALID_RIDE_FARE',
                });
            }

            if (Math.abs(amount - clientAmount) > 0.01) {
                console.warn(
                    `⚠️ Client amount (${clientAmount}) differs from DB ` +
                    `fare (${amount}) for ride ${rideId}. Using DB fare.`,
                );
            }

            /* ------------------------------------------------------------
             * PASSENGER WALLET
             * ------------------------------------------------------------ */

            const walletResult = await client.query(
                `
                SELECT
                    id,
                    passenger_id,
                    balance,
                    pending_balance,
                    total_spent,
                    last_transaction_at,
                    created_at,
                    updated_at
                FROM public.wallets
                WHERE passenger_id = $1
                FOR UPDATE
                `,
                [passengerId],
            );

            if (walletResult.rows.length === 0) {
                await client.query('ROLLBACK');
                transactionStarted = false;
                client.release();

                return res.status(404).json({
                    success: false,
                    message: 'Wallet not found.',
                    code: 'WALLET_NOT_FOUND',
                });
            }

            const wallet = walletResult.rows[0];
            const balanceBefore = Number(wallet.balance);

            if (balanceBefore < amount) {
                await client.query('ROLLBACK');
                transactionStarted = false;
                client.release();

                return res.status(400).json({
                    success: false,
                    message: 'Insufficient wallet balance.',
                    code: 'INSUFFICIENT_BALANCE',
                    balance: balanceBefore,
                    required: amount,
                });
            }

            const balanceAfter = balanceBefore - amount;
            const totalSpent = Number(wallet.total_spent) + amount;

            const updatedWalletResult = await client.query(
                `
                UPDATE public.wallets
                SET
                    balance = $1,
                    total_spent = $2,
                    last_transaction_at = NOW(),
                    updated_at = NOW()
                WHERE id = $3
                RETURNING
                    id,
                    passenger_id,
                    balance,
                    pending_balance,
                    total_spent,
                    last_transaction_at,
                    created_at,
                    updated_at
                `,
                [balanceAfter, totalSpent, wallet.id],
            );

            /* ------------------------------------------------------------
             * PASSENGER TRANSACTION
             * ------------------------------------------------------------ */

            const transactionResult = await client.query(
                `
                INSERT INTO public.transactions (
                    wallet_id,
                    passenger_id,
                    ride_id,
                    amount,
                    type,
                    status,
                    payment_method,
                    provider,
                    provider_reference,
                    balance_before,
                    balance_after,
                    description,
                    metadata,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1, $2, $3, $4,
                    'ride_payment', 'completed', 'wallet',
                    NULL, NULL,
                    $5, $6, $7, $8::jsonb,
                    NOW(), NOW()
                )
                RETURNING
                    id, wallet_id, passenger_id, ride_id,
                    amount, type, status, payment_method,
                    provider, provider_reference,
                    balance_before, balance_after,
                    description, metadata,
                    created_at, updated_at
                `,
                [
                    wallet.id,
                    passengerId,
                    rideId,
                    amount,
                    balanceBefore,
                    balanceAfter,
                    'Ride payment',
                    JSON.stringify({
                        firebase_uid: uid,
                        ride_id: rideId,
                        driver_id: ride.driver_id ?? null,
                    }),
                ],
            );

            /* ------------------------------------------------------------
             * ★ DRIVER SETTLEMENT  (isolated with SAVEPOINT)
             *
             * The completion trigger `charge_driver_commission` already
             * moved driver_earnings into driver_wallets.pending_balance.
             * We now release that pending amount into the driver's
             * withdrawable balance — but ONLY if it succeeds. A failure
             * here must never roll back the passenger's payment.
             * ------------------------------------------------------------ */

            const driverEarnings = Number(ride.driver_earnings) || 0;

            if (ride.driver_id && driverEarnings > 0) {
                await client.query('SAVEPOINT driver_settlement');

                try {
                    const driverResult = await client.query(
                        `
                        SELECT id
                        FROM public.drivers
                        WHERE uid = $1::text
                        LIMIT 1
                        `,
                        [ride.driver_id],
                    );

                    if (driverResult.rows.length === 0) {
                        throw new Error(
                            `Driver ${ride.driver_id} not found for settlement`,
                        );
                    }

                    const driverId = driverResult.rows[0].id;

                    const driverWalletResult = await client.query(
                        `
                        SELECT id, balance, pending_balance
                        FROM public.driver_wallets
                        WHERE driver_id = $1
                        FOR UPDATE
                        `,
                        [driverId],
                    );

                    if (driverWalletResult.rows.length === 0) {
                        throw new Error(
                            `Driver wallet not found for driver ${driverId}`,
                        );
                    }

                    const dw = driverWalletResult.rows[0];
                    const pendingBefore = Number(dw.pending_balance);
                    const settleAmount = Math.min(
                        pendingBefore,
                        driverEarnings,
                    );
                    const driverBalanceBefore = Number(dw.balance);
                    const driverBalanceAfter =
                        driverBalanceBefore + settleAmount;
                    const pendingAfter = pendingBefore - settleAmount;

                    await client.query(
                        `
                        UPDATE public.driver_wallets
                        SET
                            balance = $1,
                            pending_balance = $2,
                            last_transaction_at = NOW(),
                            updated_at = NOW()
                        WHERE id = $3
                        `,
                        [
                            driverBalanceAfter,
                            pendingAfter,
                            dw.id,
                        ],
                    );

                    await client.query(
                        `
                        INSERT INTO public.driver_transactions (
                            driver_id, wallet_id, ride_id,
                            amount, type, status,
                            balance_before, balance_after,
                            transaction_reference,
                            description, metadata,
                            created_at, updated_at
                        )
                        VALUES (
                            $1, $2, $3, $4,
                            'ride_earning', 'completed',
                            $5, $6,
                            'SETTLE-' || $3 || '-' ||
                                extract(epoch from now())::bigint,
                            $7, $8::jsonb,
                            NOW(), NOW()
                        )
                        `,
                        [
                            driverId,
                            dw.id,
                            rideId,
                            settleAmount,
                            driverBalanceBefore,
                            driverBalanceAfter,
                            `Ride payment settled for ride #${rideId}`,
                            JSON.stringify({
                                ride_id: rideId,
                                passenger_id: passengerId,
                                settled_amount: settleAmount,
                                pending_before: pendingBefore,
                                pending_after: pendingAfter,
                            }),
                        ],
                    );

                    await client.query('RELEASE SAVEPOINT driver_settlement');

                    console.log(
                        `💵 Driver ${ride.driver_id} settled ` +
                        `GH₵${settleAmount.toFixed(2)} ` +
                        `(balance ${driverBalanceBefore.toFixed(2)} → ` +
                        `${driverBalanceAfter.toFixed(2)}, ` +
                        `pending ${pendingBefore.toFixed(2)} → ` +
                        `${pendingAfter.toFixed(2)})`,
                    );
                } catch (driverSettlementError) {
                    // ★ Roll back only the driver settlement, NOT the
                    //   passenger payment. Log loudly and keep going.
                    await client.query(
                        'ROLLBACK TO SAVEPOINT driver_settlement',
                    );

                    const dse = driverSettlementError as {
                        message?: string;
                        code?: string;
                        detail?: string;
                        constraint?: string;
                    };

                    console.error(
                        '⚠️  Driver settlement failed (passenger payment ' +
                        'still processed):',
                        {
                            message: dse.message,
                            code: dse.code,
                            detail: dse.detail,
                            constraint: dse.constraint,
                        },
                    );
                }
            }

            /* ------------------------------------------------------------
             * MARK RIDE PAID
             * ------------------------------------------------------------ */

            await client.query(
                `
                UPDATE public.rides
                SET
                    payment_status = 'paid',
                    paid_at = NOW()
                WHERE id = $1
                `,
                [rideId],
            );

            await client.query('COMMIT');
            transactionStarted = false;
            client.release();

            console.log(
                `💳 Wallet payment: ` +
                `passenger=${passengerId}, ` +
                `ride=${rideId}, ` +
                `driver=${ride.driver_id ?? 'none'}, ` +
                `amount=${amount}, ` +
                `balance=${balanceAfter}`,
            );

            return res.status(201).json({
                success: true,
                message: 'Ride payment completed successfully.',
                wallet: updatedWalletResult.rows[0],
                transaction: transactionResult.rows[0],
                ride: {
                    id: rideId,
                    payment_status: 'paid',
                    status: ride.status,
                },
            });
        } catch (error: unknown) {
            if (transactionStarted) {
                try {
                    await client.query('ROLLBACK');
                } catch (rollbackError) {
                    console.error('❌ Rollback error:', rollbackError);
                }
            }

            client.release();

            // ★ Log the FULL Postgres error object so we can see
            //   exactly which constraint / trigger failed.
            const e = error as {
                message?: string;
                code?: string;
                detail?: string;
                constraint?: string;
                hint?: string;
                where?: string;
                table?: string;
                column?: string;
            };

            console.error('❌ Error processing wallet payment:');
            console.error('   code       :', e.code);
            console.error('   message    :', e.message);
            console.error('   detail     :', e.detail);
            console.error('   constraint :', e.constraint);
            console.error('   table      :', e.table);
            console.error('   column     :', e.column);
            console.error('   hint       :', e.hint);
            console.error('   where      :', e.where);

            return res.status(500).json({
                success: false,
                message: 'Failed to process wallet payment.',
                code: e.code ?? 'WALLET_PAYMENT_FAILED',
                error: e.message ?? 'Unknown database error',
                detail: e.detail ?? null,
                constraint: e.constraint ?? null,
                table: e.table ?? null,
                column: e.column ?? null,
            });
        }
    },
);

/* ==========================================================================
 * EXPORT ROUTER
 * ========================================================================== */

export default router;
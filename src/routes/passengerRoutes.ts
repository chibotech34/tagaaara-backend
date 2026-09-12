import express, {
    Request,
    Response,
    NextFunction,
} from 'express';

import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';

const router = express.Router();

// ============================================================
// TYPES
// ============================================================

interface DecodedFirebaseToken {
    uid: string;
    email?: string;
    name?: string;
    phone_number?: string;
}

interface AuthenticatedRequest extends Request {
    decodedToken?: DecodedFirebaseToken;
}

// ============================================================
// HELPERS
// ============================================================

function normalizePhone(
    phone: unknown,
): string | null {
    let value = String(phone || '')
        .trim()
        .replace(/[^0-9+]/g, '');

    // 0241234567 -> +233241234567
    if (value.startsWith('0')) {
        value = '+233' + value.substring(1);
    }

    // 233241234567 -> +233241234567
    else if (value.startsWith('233')) {
        value = '+' + value;
    }

    // 241234567 -> +233241234567
    else if (
        value.length === 9 &&
        /^[25]\d{8}$/.test(value)
    ) {
        value = '+233' + value;
    }

    // Correct Ghana phone validation
    if (!/^\+233\d{9}$/.test(value)) {
        return null;
    }

    return value;
}

function toFiniteNumber(
    value: unknown,
): number | null {
    if (
        value === null ||
        value === undefined ||
        value === ''
    ) {
        return null;
    }

    const number = Number(value);

    return Number.isFinite(number)
        ? number
        : null;
}

// ============================================================
// FIREBASE AUTH MIDDLEWARE
// ============================================================

async function verifyFirebaseToken(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
) {
    try {
        const authHeader =
            req.headers.authorization;

        // ----------------------------------------------------
        // AUTHORIZATION HEADER
        // ----------------------------------------------------

        if (!authHeader) {
            return res.status(401).json({
                success: false,
                code: 'MISSING_AUTHORIZATION',
                message:
                    'Authorization header is required.',
            });
        }

        // ----------------------------------------------------
        // BEARER TOKEN
        // ----------------------------------------------------

        if (
            !authHeader.startsWith('Bearer ')
        ) {
            return res.status(401).json({
                success: false,
                code: 'INVALID_AUTHORIZATION',
                message:
                    'Authorization header must use Bearer token.',
            });
        }

        const idToken =
            authHeader.substring(7).trim();

        if (!idToken) {
            return res.status(401).json({
                success: false,
                code: 'EMPTY_TOKEN',
                message:
                    'Firebase ID token is missing.',
            });
        }

        // ----------------------------------------------------
        // VERIFY FIREBASE TOKEN
        // ----------------------------------------------------

        const decoded =
            await firebaseAuth.verifyIdToken(
                idToken,
            );

        // ----------------------------------------------------
        // STORE DECODED USER
        // ----------------------------------------------------

        req.decodedToken = {
            uid: decoded.uid,
            email: decoded.email,
            name: decoded.name,
            phone_number:
                decoded.phone_number,
        };

        console.log(
            'Firebase token verified successfully.',
        );

        console.log(
            'Firebase UID:',
            decoded.uid,
        );

        console.log(
            'Firebase phone:',
            decoded.phone_number,
        );

        next();
    } catch (error: any) {
        console.error(
            'Firebase token verification error:',
            error,
        );

        return res.status(401).json({
            success: false,
            code: 'INVALID_FIREBASE_TOKEN',
            message:
                'Authentication token is invalid or expired.',
        });
    }
}

// ============================================================
// GET PASSENGER PROFILE
// ============================================================
//
// GET /api/passengers/profile
//
// ============================================================

router.get(
    '/profile',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        const uid =
            req.decodedToken?.uid;

        // ----------------------------------------------------
        // CHECK FIREBASE UID
        // ----------------------------------------------------

        if (!uid) {
            return res.status(401).json({
                success: false,
                code: 'MISSING_FIREBASE_UID',
                message:
                    'Authenticated Firebase UID is missing.',
            });
        }

        try {
            console.log(
                '============================================',
            );

            console.log(
                'PASSENGER PROFILE REQUEST',
            );

            console.log(
                'Firebase UID:',
                uid,
            );

            console.log(
                'Firebase phone:',
                req.decodedToken?.phone_number,
            );

            console.log(
                'Firebase email:',
                req.decodedToken?.email,
            );

            console.log(
                '============================================',
            );

            // ------------------------------------------------
            // FIND PASSENGER
            // ------------------------------------------------

            const result =
                await pool.query(
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
                    FROM passengers
                    WHERE firebase_uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            console.log(
                'Passenger database rows:',
                result.rows.length,
            );

            // ------------------------------------------------
            // PASSENGER NOT FOUND
            // ------------------------------------------------

            if (result.rows.length === 0) {
                console.log(
                    'PASSENGER NOT FOUND',
                );

                return res.status(404).json({
                    success: false,
                    code: 'PASSENGER_NOT_FOUND',
                    message:
                        'Passenger account was not found.',
                });
            }

            const passenger =
                result.rows[0];

            // ------------------------------------------------
            // ACCOUNT STATUS
            // ------------------------------------------------

            if (
                passenger.account_status &&
                passenger.account_status !== 'active'
            ) {
                return res.status(403).json({
                    success: false,
                    code: 'ACCOUNT_NOT_ACTIVE',
                    message:
                        `Passenger account is ${passenger.account_status}.`,
                    accountStatus:
                        passenger.account_status,
                });
            }

            // ------------------------------------------------
            // SUCCESS
            // ------------------------------------------------

            return res.status(200).json({
                success: true,
                message:
                    'Passenger profile retrieved successfully.',
                passenger,
            });
        } catch (error) {
            console.error(
                'Passenger profile database error:',
                error,
            );

            return res.status(500).json({
                success: false,
                code: 'SERVER_ERROR',
                message:
                    'Failed to retrieve passenger profile.',
            });
        }
    },
);

// ============================================================
// UPDATE PASSENGER ONLINE STATUS + LOCATION
// ============================================================
//
// POST /api/passengers/update-status
//
// Body:
//
// {
//     "isOnline": true,
//     "latitude": 10.0605,
//     "longitude": -2.5072
// }
//
// ============================================================

router.post(
    '/update-status',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        const uid =
            req.decodedToken?.uid;

        // ----------------------------------------------------
        // CHECK FIREBASE UID
        // ----------------------------------------------------

        if (!uid) {
            return res.status(401).json({
                success: false,
                code: 'MISSING_FIREBASE_UID',
                message:
                    'Authenticated Firebase UID is missing.',
            });
        }

        try {
            const {
                isOnline,
                latitude,
                longitude,
            } = req.body || {};

            // ------------------------------------------------
            // ONLINE STATUS
            // ------------------------------------------------

            const online =
                typeof isOnline === 'boolean'
                    ? isOnline
                    : true;

            // ------------------------------------------------
            // CONVERT COORDINATES
            // ------------------------------------------------

            const lat =
                toFiniteNumber(latitude);

            const lng =
                toFiniteNumber(longitude);

            // ------------------------------------------------
            // COORDINATES MUST COME TOGETHER
            // ------------------------------------------------

            if (
                (lat !== null &&
                    lng === null) ||
                (lat === null &&
                    lng !== null)
            ) {
                return res.status(400).json({
                    success: false,
                    code: 'INVALID_LOCATION',
                    message:
                        'Latitude and longitude must be supplied together.',
                });
            }

            // ------------------------------------------------
            // LATITUDE VALIDATION
            // ------------------------------------------------

            if (
                lat !== null &&
                (lat < -90 || lat > 90)
            ) {
                return res.status(400).json({
                    success: false,
                    code: 'INVALID_LATITUDE',
                    message:
                        'Latitude must be between -90 and 90.',
                });
            }

            // ------------------------------------------------
            // LONGITUDE VALIDATION
            // ------------------------------------------------

            if (
                lng !== null &&
                (lng < -180 || lng > 180)
            ) {
                return res.status(400).json({
                    success: false,
                    code: 'INVALID_LONGITUDE',
                    message:
                        'Longitude must be between -180 and 180.',
                });
            }

            console.log(
                '============================================',
            );

            console.log(
                'PASSENGER STATUS / LOCATION UPDATE',
            );

            console.log(
                'Firebase UID:',
                uid,
            );

            console.log(
                'Online:',
                online,
            );

            console.log(
                'Latitude:',
                lat,
            );

            console.log(
                'Longitude:',
                lng,
            );

            console.log(
                '============================================',
            );

            // ------------------------------------------------
            // UPDATE DATABASE
            // ------------------------------------------------

            const result =
                await pool.query(
                    `
                    UPDATE passengers
                    SET
                        is_online = $1,

                        last_online_at =
                            CASE
                                WHEN $1 = TRUE
                                THEN NOW()
                                ELSE last_online_at
                            END,

                        current_latitude =
                            CASE
                                WHEN $2 IS NOT NULL
                                THEN $2
                                ELSE current_latitude
                            END,

                        current_longitude =
                            CASE
                                WHEN $3 IS NOT NULL
                                THEN $3
                                ELSE current_longitude
                            END,

                        last_location_update =
                            CASE
                                WHEN $2 IS NOT NULL
                                 AND $3 IS NOT NULL
                                THEN NOW()
                                ELSE last_location_update
                            END,

                        updated_at = NOW()

                    WHERE firebase_uid = $4

                    RETURNING
                        id,
                        firebase_uid,
                        full_name,
                        phone,
                        email,
                        account_status,
                        is_online,
                        last_online_at,
                        current_latitude,
                        current_longitude,
                        last_location_update,
                        updated_at
                    `,
                    [
                        online,
                        lat,
                        lng,
                        uid,
                    ],
                );

            // ------------------------------------------------
            // PASSENGER NOT FOUND
            // ------------------------------------------------

            if (result.rows.length === 0) {
                console.log(
                    'PASSENGER NOT FOUND FOR LOCATION UPDATE',
                );

                console.log(
                    'Firebase UID:',
                    uid,
                );

                return res.status(404).json({
                    success: false,
                    code: 'PASSENGER_NOT_FOUND',
                    message:
                        'Passenger account was not found.',
                });
            }

            // ------------------------------------------------
            // UPDATED PASSENGER
            // ------------------------------------------------

            const passenger =
                result.rows[0];

            console.log(
                'PASSENGER LOCATION UPDATED SUCCESSFULLY',
            );

            console.log(
                'Passenger ID:',
                passenger.id,
            );

            console.log(
                'Firebase UID:',
                passenger.firebase_uid,
            );

            console.log(
                'Latitude:',
                passenger.current_latitude,
            );

            console.log(
                'Longitude:',
                passenger.current_longitude,
            );

            console.log(
                'Last location update:',
                passenger.last_location_update,
            );

            // ------------------------------------------------
            // SUCCESS
            // ------------------------------------------------

            return res.status(200).json({
                success: true,
                message: online
                    ? 'Passenger is now online and location updated.'
                    : 'Passenger is now offline.',
                passenger,
            });
        } catch (error) {
            console.error(
                'Passenger update-status error:',
                error,
            );

            return res.status(500).json({
                success: false,
                code: 'SERVER_ERROR',
                message:
                    'Failed to update passenger status and location.',
            });
        }
    },
);

// ============================================================
// EXPORT
// ============================================================

export default router;
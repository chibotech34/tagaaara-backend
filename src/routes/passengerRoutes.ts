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

function normalizePhone(phone: unknown): string | null {
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

        if (!authHeader) {
            return res.status(401).json({
                success: false,
                code: 'MISSING_AUTHORIZATION',
                message: 'Authorization header is required.',
            });
        }

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
                message: 'Firebase ID token is missing.',
            });
        }

        const decoded =
            await firebaseAuth.verifyIdToken(
                idToken,
            );

        req.decodedToken = {
            uid: decoded.uid,
            email: decoded.email,
            name: decoded.name,
            phone_number: decoded.phone_number,
        };

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
// UPDATE PASSENGER ONLINE STATUS + LOCATION
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

            // --------------------------------------------------------
            // ONLINE STATUS
            // --------------------------------------------------------

            const online =
                typeof isOnline === 'boolean'
                    ? isOnline
                    : true;

            // --------------------------------------------------------
            // LOCATION
            // --------------------------------------------------------

            const lat =
                toFiniteNumber(latitude);

            const lng =
                toFiniteNumber(longitude);

            // If one coordinate is supplied,
            // the other must also be supplied.
            if (
                (lat !== null && lng === null) ||
                (lat === null && lng !== null)
            ) {
                return res.status(400).json({
                    success: false,
                    code: 'INVALID_LOCATION',
                    message:
                        'Latitude and longitude must be supplied together.',
                });
            }

            // Latitude range
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

            // Longitude range
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

            // --------------------------------------------------------
            // UPDATE DATABASE
            // --------------------------------------------------------

            const result = await pool.query(
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
            COALESCE($2, current_latitude),

          current_longitude =
            COALESCE($3, current_longitude),

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

            // --------------------------------------------------------
            // PASSENGER NOT FOUND
            // --------------------------------------------------------

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    code: 'PASSENGER_NOT_FOUND',
                    message:
                        'Passenger account was not found.',
                });
            }

            // --------------------------------------------------------
            // SUCCESS
            // --------------------------------------------------------

            return res.status(200).json({
                success: true,

                message: online
                    ? 'Passenger is now online.'
                    : 'Passenger is now offline.',

                passenger: result.rows[0],
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
                    'Failed to update passenger status.',
            });
        }
    },
);

export default router;
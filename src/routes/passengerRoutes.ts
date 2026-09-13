// src/routes/passengerRoutes.ts
import { Router, Request, Response, NextFunction } from 'express';
import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';

const router = Router();

/* ==========================================================================
 * Types
 * ========================================================================== */

interface DecodedFirebaseToken {
    uid: string;
    email?: string;
    name?: string;
}

interface AuthenticatedRequest extends Request {
    decodedToken?: DecodedFirebaseToken;
}

/* ==========================================================================
 * Firebase ID‑token middleware
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

const getAuthenticatedUid = (req: AuthenticatedRequest): string | null =>
    req.decodedToken?.uid ?? null;

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
                    profile_photo_url,
                    account_status,
                    phone_verified,
                    email_verified,
                    is_online,
                    last_online_at,
                    current_latitude,
                    current_longitude,
                    last_location_update,
                    created_at,
                    updated_at
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
            const e = error as { message?: string };
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
 * POST /api/passengers/update-status
 * --------------------------------------------------------------------------
 * Body: { isOnline: boolean, latitude?: number, longitude?: number }
 * Updates online flag and (optionally) the passenger's last known location.
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
                          is_online              = $1,
                          current_latitude       = $2::text,
                          current_longitude      = $3::text,
                          last_location_update   = NOW(),
                          last_online_at         = NOW(),
                          updated_at             = NOW()
                      WHERE firebase_uid = $4
                      RETURNING id, firebase_uid, is_online,
                                current_latitude, current_longitude,
                                last_online_at
                      `,
                    [
                        isOnline,
                        String(latitude),
                        String(longitude),
                        uid,
                    ],
                )
                : await pool.query(
                    `
                      UPDATE public.passengers
                      SET
                          is_online       = $1,
                          last_online_at  = NOW(),
                          updated_at      = NOW()
                      WHERE firebase_uid = $2
                      RETURNING id, firebase_uid, is_online, last_online_at
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
 * --------------------------------------------------------------------------
 * Query params:
 *   lat, lng    (required) – driver's current position
 *   radius      (optional, metres, default 5000)
 *
 * Response:
 *   {
 *     success: true,
 *     count: <number>,
 *     passengers: [ { id, firebase_uid, full_name, …, distance_meters } ]
 *   }
 *
 * Notes
 * -----
 *  • `passengers.current_latitude` / `current_longitude` are stored as TEXT.
 *  • There is no PostGIS `location` column on the passengers table.
 *  • We therefore build the geography point on the fly AND cast the text
 *    columns to double precision.
 *  • A pure‑SQL Haversine fallback is used if PostGIS is unavailable.
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
                    message: 'Missing required query params: lat and lng',
                    code: 'MISSING_PARAMETERS',
                });
            }

            const latitude = Number(lat);
            const longitude = Number(lng);
            const searchRadius = Number(radius);

            if (
                !Number.isFinite(latitude) ||
                !Number.isFinite(longitude) ||
                !Number.isFinite(searchRadius)
            ) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid numeric values for lat, lng, or radius',
                    code: 'INVALID_PARAMETERS',
                });
            }

            // ---------------------------------------------------------------
            // Try PostGIS first.
            // ---------------------------------------------------------------
            const postgisQuery = `
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
                        NULLIF(TRIM(current_latitude),  '')::double precision AS lat_num,
                        NULLIF(TRIM(current_longitude), '')::double precision AS lng_num
                    FROM public.passengers
                    WHERE is_online = true
                      AND account_status = 'active'
                      AND current_latitude  IS NOT NULL
                      AND current_longitude IS NOT NULL
                      AND TRIM(current_latitude)  <> ''
                      AND TRIM(current_longitude) <> ''
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
                    ROUND(
                        ST_Distance(
                            ST_SetSRID(ST_MakePoint(lng_num, lat_num), 4326)::geography,
                            ST_SetSRID(ST_MakePoint($1::double precision, $2::double precision), 4326)::geography
                        )
                    )::int AS distance_meters
                FROM candidates
                WHERE lat_num IS NOT NULL
                  AND lng_num IS NOT NULL
                  AND ST_DWithin(
                        ST_SetSRID(ST_MakePoint(lng_num, lat_num), 4326)::geography,
                        ST_SetSRID(ST_MakePoint($1::double precision, $2::double precision), 4326)::geography,
                        $3::double precision
                  )
                ORDER BY distance_meters ASC
                LIMIT 50;
            `;

            // ---------------------------------------------------------------
            // Haversine fallback (no PostGIS required).
            // ---------------------------------------------------------------
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
                        NULLIF(TRIM(current_latitude),  '')::double precision AS lat_num,
                        NULLIF(TRIM(current_longitude), '')::double precision AS lng_num
                    FROM public.passengers
                    WHERE is_online = true
                      AND account_status = 'active'
                      AND current_latitude  IS NOT NULL
                      AND current_longitude IS NOT NULL
                      AND TRIM(current_latitude)  <> ''
                      AND TRIM(current_longitude) <> ''
                ),
                distances AS (
                    SELECT
                        *,
                        6371000 * 2 * ASIN(
                            SQRT(
                                POWER(SIN(RADIANS(lat_num - $2::double precision) / 2), 2) +
                                COS(RADIANS($2::double precision)) *
                                COS(RADIANS(lat_num)) *
                                POWER(SIN(RADIANS(lng_num - $1::double precision) / 2), 2)
                            )
                        ) AS distance_meters
                    FROM candidates
                    WHERE lat_num IS NOT NULL
                      AND lng_num IS NOT NULL
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

                // 42883 = undefined_function (PostGIS missing)
                // 42703 = undefined_column (ST_* referenced a missing column)
                if (pe.code === '42883' || pe.code === '42703') {
                    console.warn(
                        '⚠️ PostGIS unavailable, falling back to Haversine.',
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
                message: 'Failed to fetch nearby passengers',
                code: 'NEARBY_PASSENGERS_FAILED',
                error: e.message,
            });
        }
    },
);

export default router;
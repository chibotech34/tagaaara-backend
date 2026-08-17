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

interface AuthenticatedRequest extends Request {
    decodedToken?: DecodedFirebaseToken;
}

/*
|--------------------------------------------------------------------------
| Firebase ID Token Middleware
|--------------------------------------------------------------------------
|
| Every protected driver endpoint uses this middleware.
| Firebase Admin itself is initialized only once in:
|
| src/config/firebase.ts
|
|--------------------------------------------------------------------------
*/

const verifyFirebaseToken = async (
    req: AuthenticatedRequest,
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
            message:
                'Firebase ID token is missing.',
            code: 'AUTH_TOKEN_MISSING',
        });

        return;
    }

    try {
        const decodedToken =
            await firebaseAuth.verifyIdToken(token);

        req.decodedToken = {
            uid: decodedToken.uid,
            email: decodedToken.email,
            name: decodedToken.name,
        };

        next();
    } catch (error: unknown) {
        console.error(
            '❌ Firebase token verification failed:',
            error,
        );

        const firebaseError =
            error as {
                code?: string;
                message?: string;
            };

        if (
            firebaseError.code ===
            'auth/id-token-expired'
        ) {
            res.status(401).json({
                success: false,
                message:
                    'Firebase ID token expired. Please refresh authentication and try again.',
                code: 'AUTH_TOKEN_EXPIRED',
            });

            return;
        }

        if (
            firebaseError.code ===
            'auth/id-token-revoked'
        ) {
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
            message:
                'Firebase authentication failed.',
            code: 'AUTH_TOKEN_INVALID',
        });
    }
};

/*
|--------------------------------------------------------------------------
| Helper: Get authenticated Firebase UID
|--------------------------------------------------------------------------
*/

const getAuthenticatedUid = (
    req: AuthenticatedRequest,
): string | null => {
    return req.decodedToken?.uid || null;
};

/*
|--------------------------------------------------------------------------
| POST /api/drivers/register
|--------------------------------------------------------------------------
|
| Register a driver in PostgreSQL.
|
| Driver must already be authenticated with Firebase.
|
|--------------------------------------------------------------------------
*/

router.post(
    '/register',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const {
                uid,
                full_name,
                phone,
                email,
                profile_photo_url,
                date_of_birth,
                gender,
                national_id,
                license_number,
                license_expiry_date,
                vehicle_type,
                registration_number,
                vehicle_color,
                vehicle_model,
                vehicle_year,
                vehicle_photo_url,
                region,
                district,
                town_city,
                home_address,
                preferred_payment_method,
                mobile_money_provider,
                mobile_money_number,
            } = req.body;

            const decodedUid =
                getAuthenticatedUid(req);

            if (!decodedUid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Authenticated Firebase user was not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            /*
            |--------------------------------------------------------------------------
            | Required fields
            |--------------------------------------------------------------------------
            */

            if (
                !uid ||
                !full_name ||
                !phone ||
                !registration_number
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Missing required fields: uid, full_name, phone, registration_number.',
                    code: 'REQUIRED_FIELDS_MISSING',
                });
            }

            /*
            |--------------------------------------------------------------------------
            | Security: request UID must equal Firebase UID
            |--------------------------------------------------------------------------
            */

            if (uid !== decodedUid) {
                return res.status(403).json({
                    success: false,
                    message:
                        'UID in request does not match authenticated Firebase user.',
                    code: 'UID_MISMATCH',
                });
            }

            /*
            |--------------------------------------------------------------------------
            | Check for existing driver
            |--------------------------------------------------------------------------
            */

            const existing =
                await pool.query(
                    `
                    SELECT
                        id,
                        uid,
                        phone,
                        registration_number
                    FROM public.drivers
                    WHERE
                        uid = $1
                        OR phone = $2
                        OR registration_number = $3
                    LIMIT 1
                    `,
                    [
                        uid,
                        phone,
                        registration_number,
                    ],
                );

            if (existing.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    message:
                        'An account with this UID, phone, or registration number already exists. Please log in.',
                    code:
                        'DRIVER_ALREADY_EXISTS',
                    existingId:
                        existing.rows[0].id,
                });
            }

            /*
            |--------------------------------------------------------------------------
            | Insert driver
            |--------------------------------------------------------------------------
            */

            const result =
                await pool.query(
                    `
                    INSERT INTO public.drivers (
                        uid,
                        full_name,
                        phone,
                        email,
                        profile_photo_url,

                        date_of_birth,
                        gender,
                        national_id,
                        license_number,
                        license_expiry_date,

                        vehicle_type,
                        registration_number,
                        vehicle_color,
                        vehicle_model,
                        vehicle_year,

                        vehicle_photo_url,
                        region,
                        district,
                        town_city,
                        home_address,

                        preferred_payment_method,
                        mobile_money_provider,
                        mobile_money_number,

                        is_online,
                        is_available,
                        status,

                        rating,
                        total_rides,
                        completed_rides,
                        cancelled_rides,

                        created_at,
                        updated_at
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,

                        $6,
                        $7,
                        $8,
                        $9,
                        $10,

                        $11,
                        $12,
                        $13,
                        $14,
                        $15,

                        $16,
                        $17,
                        $18,
                        $19,
                        $20,

                        $21,
                        $22,
                        $23,

                        false,
                        false,
                        'pending',

                        5.0,
                        0,
                        0,
                        0,

                        NOW(),
                        NOW()
                    )
                    RETURNING id, uid, status
                    `,
                    [
                        uid,
                        full_name,
                        phone,

                        email ||
                        req.decodedToken?.email ||
                        null,

                        profile_photo_url ||
                        null,

                        date_of_birth ||
                        null,

                        gender ||
                        null,

                        national_id ||
                        null,

                        license_number ||
                        null,

                        license_expiry_date ||
                        null,

                        vehicle_type ||
                        'rickshaw',

                        registration_number,

                        vehicle_color ||
                        null,

                        vehicle_model ||
                        null,

                        vehicle_year ||
                        null,

                        vehicle_photo_url ||
                        null,

                        region ||
                        null,

                        district ||
                        null,

                        town_city ||
                        null,

                        home_address ||
                        null,

                        preferred_payment_method ||
                        null,

                        mobile_money_provider ||
                        null,

                        mobile_money_number ||
                        null,
                    ],
                );

            return res.status(201).json({
                success: true,
                message:
                    'Driver registered successfully.',
                driverId:
                    result.rows[0].id,
                uid:
                    result.rows[0].uid,
                status:
                    result.rows[0].status,
            });
        } catch (error: unknown) {
            console.error(
                '❌ Driver registration error:',
                error,
            );

            const dbError =
                error as {
                    code?: string;
                    message?: string;
                    detail?: string;
                };

            /*
            |--------------------------------------------------------------------------
            | PostgreSQL duplicate key
            |--------------------------------------------------------------------------
            */

            if (dbError.code === '23505') {
                return res.status(409).json({
                    success: false,
                    message:
                        'A driver with this UID, phone number, or vehicle registration already exists.',
                    code:
                        'DRIVER_DUPLICATE',
                });
            }

            return res.status(500).json({
                success: false,
                message:
                    'Registration failed due to a server error.',
                code:
                    'DB_INSERT_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /api/drivers/uid/:uid
|--------------------------------------------------------------------------
|
| Get the authenticated driver's complete profile.
|
|--------------------------------------------------------------------------
*/

router.get(
    '/uid/:uid',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        const { uid } = req.params;

        const authenticatedUid =
            getAuthenticatedUid(req);

        if (
            !authenticatedUid ||
            uid !== authenticatedUid
        ) {
            return res.status(403).json({
                success: false,
                message:
                    'Forbidden: UID does not match authenticated Firebase user.',
                code: 'UID_MISMATCH',
            });
        }

        try {
            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        uid,
                        full_name,
                        phone,
                        email,
                        profile_photo_url,

                        date_of_birth,
                        gender,
                        national_id,
                        license_number,
                        license_expiry_date,

                        vehicle_type,
                        registration_number,
                        vehicle_color,
                        vehicle_model,
                        vehicle_year,

                        vehicle_photo_url,

                        region,
                        district,
                        town_city,
                        home_address,

                        is_online,
                        is_available,
                        status,

                        current_latitude,
                        current_longitude,
                        last_location_update,

                        rating,
                        total_rides,
                        completed_rides,
                        cancelled_rides,

                        preferred_payment_method,
                        mobile_money_provider,
                        mobile_money_number,

                        created_at,
                        updated_at

                    FROM public.drivers
                    WHERE uid = $1
                    `,
                    [uid],
                );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Driver not found.',
                    code:
                        'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                driver:
                    result.rows[0],
            });
        } catch (error: unknown) {
            console.error(
                '❌ Error fetching driver by UID:',
                error,
            );

            const dbError =
                error as {
                    message?: string;
                };

            return res.status(500).json({
                success: false,
                message:
                    'Failed to fetch driver data.',
                code:
                    'DRIVER_FETCH_FAILED',
                error:
                    dbError.message,
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /api/drivers/:uid/status
|--------------------------------------------------------------------------
*/

router.get(
    '/:uid/status',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        const { uid } = req.params;

        const authenticatedUid =
            getAuthenticatedUid(req);

        if (
            !authenticatedUid ||
            uid !== authenticatedUid
        ) {
            return res.status(403).json({
                success: false,
                message:
                    'Forbidden: UID does not match authenticated Firebase user.',
                code: 'UID_MISMATCH',
            });
        }

        try {
            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        uid,
                        status,
                        is_online,
                        is_available
                    FROM public.drivers
                    WHERE uid = $1
                    `,
                    [uid],
                );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Driver not found.',
                    code:
                        'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                status:
                    result.rows[0].status,
                isOnline:
                    result.rows[0].is_online,
                isAvailable:
                    result.rows[0].is_available,
            });
        } catch (error: unknown) {
            console.error(
                '❌ Error fetching driver status:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to fetch driver status.',
                code:
                    'STATUS_FETCH_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| POST /api/drivers/update-location
|--------------------------------------------------------------------------
|
| Updates:
|   current_latitude
|   current_longitude
|   location (PostGIS geography)
|   last_location_update
|
|--------------------------------------------------------------------------
*/

router.post(
    '/update-location',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const {
                latitude,
                longitude,
            } = req.body;

            /*
            |--------------------------------------------------------------------------
            | Validate coordinates
            |--------------------------------------------------------------------------
            */

            if (
                latitude === undefined ||
                longitude === undefined
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Missing latitude or longitude.',
                    code:
                        'MISSING_LOCATION',
                });
            }

            const lat =
                Number(latitude);

            const lng =
                Number(longitude);

            if (
                !Number.isFinite(lat) ||
                !Number.isFinite(lng)
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid latitude or longitude.',
                    code:
                        'INVALID_LOCATION',
                });
            }

            /*
            |--------------------------------------------------------------------------
            | Validate latitude/longitude ranges
            |--------------------------------------------------------------------------
            */

            if (
                lat < -90 ||
                lat > 90
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Latitude must be between -90 and 90.',
                    code:
                        'INVALID_LATITUDE',
                });
            }

            if (
                lng < -180 ||
                lng > 180
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Longitude must be between -180 and 180.',
                    code:
                        'INVALID_LONGITUDE',
                });
            }

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            /*
            |--------------------------------------------------------------------------
            | Update driver location
            |--------------------------------------------------------------------------
            */

            const result =
                await pool.query(
                    `
                    UPDATE public.drivers

                    SET
                        current_latitude =
                            $1::numeric,

                        current_longitude =
                            $2::numeric,

                        location =
                            ST_SetSRID(
                                ST_MakePoint(
                                    $2::double precision,
                                    $1::double precision
                                ),
                                4326
                            )::geography,

                        last_location_update =
                            NOW(),

                        updated_at =
                            NOW()

                    WHERE uid = $3

                    RETURNING
                        id,
                        uid,
                        current_latitude,
                        current_longitude,
                        last_location_update
                    `,
                    [
                        lat,
                        lng,
                        uid,
                    ],
                );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Driver not found.',
                    code:
                        'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message:
                    'Location updated successfully.',
                location: {
                    latitude:
                        result.rows[0]
                            .current_latitude,
                    longitude:
                        result.rows[0]
                            .current_longitude,
                    updatedAt:
                        result.rows[0]
                            .last_location_update,
                },
            });
        } catch (error: unknown) {
            console.error(
                '❌ Update location error:',
                error,
            );

            const dbError =
                error as {
                    code?: string;
                    message?: string;
                    detail?: string;
                };

            console.error(
                'Database error:',
                dbError.message,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to update location.',
                code:
                    'LOCATION_UPDATE_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| POST /api/drivers/update-status
|--------------------------------------------------------------------------
|
| Driver can:
|
|   online = true
|   available = true
|
| ONLY when:
|
|   status = approved
|
|--------------------------------------------------------------------------
*/

router.post(
    '/update-status',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const {
                isOnline,
                isAvailable,
            } = req.body;

            if (
                typeof isOnline !==
                'boolean' ||
                typeof isAvailable !==
                'boolean'
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'isOnline and isAvailable must both be boolean values.',
                    code:
                        'INVALID_STATUS',
                });
            }

            const online =
                isOnline;

            const available =
                isAvailable;

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            /*
            |--------------------------------------------------------------------------
            | Get driver
            |--------------------------------------------------------------------------
            */

            const driverResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        uid,
                        status,
                        is_online,
                        is_available
                    FROM public.drivers
                    WHERE uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                driverResult.rows.length ===
                0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Driver not found.',
                    code:
                        'DRIVER_NOT_FOUND',
                });
            }

            const driver =
                driverResult.rows[0];

            /*
            |--------------------------------------------------------------------------
            | Driver cannot go online unless approved
            |--------------------------------------------------------------------------
            */

            if (
                online &&
                driver.status !==
                'approved'
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        'Cannot go online. Driver account is not approved.',
                    code:
                        'NOT_APPROVED',
                    status:
                        driver.status,
                });
            }

            /*
            |--------------------------------------------------------------------------
            | If offline, driver cannot remain available
            |--------------------------------------------------------------------------
            */

            const finalAvailable =
                online
                    ? available
                    : false;

            /*
            |--------------------------------------------------------------------------
            | Update status
            |--------------------------------------------------------------------------
            */

            const result =
                await pool.query(
                    `
                    UPDATE public.drivers

                    SET
                        is_online = $1,
                        is_available = $2,
                        updated_at = NOW()

                    WHERE uid = $3

                    RETURNING
                        id,
                        uid,
                        status,
                        is_online,
                        is_available,
                        updated_at
                    `,
                    [
                        online,
                        finalAvailable,
                        uid,
                    ],
                );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Driver not found.',
                    code:
                        'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message:
                    'Driver status updated successfully.',
                driver: {
                    id:
                        result.rows[0]
                            .id,
                    uid:
                        result.rows[0]
                            .uid,
                    status:
                        result.rows[0]
                            .status,
                    isOnline:
                        result.rows[0]
                            .is_online,
                    isAvailable:
                        result.rows[0]
                            .is_available,
                },
            });
        } catch (error: unknown) {
            console.error(
                '❌ Update driver status error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to update driver status.',
                code:
                    'STATUS_UPDATE_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /api/drivers/me
|--------------------------------------------------------------------------
|
| Convenient endpoint for the currently authenticated driver.
|
|--------------------------------------------------------------------------
*/

router.get(
    '/me',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        uid,
                        full_name,
                        phone,
                        email,
                        profile_photo_url,

                        date_of_birth,
                        gender,
                        national_id,
                        license_number,
                        license_expiry_date,

                        vehicle_type,
                        registration_number,
                        vehicle_color,
                        vehicle_model,
                        vehicle_year,

                        vehicle_photo_url,

                        region,
                        district,
                        town_city,
                        home_address,

                        is_online,
                        is_available,
                        status,

                        current_latitude,
                        current_longitude,
                        last_location_update,

                        rating,
                        total_rides,
                        completed_rides,
                        cancelled_rides,

                        preferred_payment_method,
                        mobile_money_provider,
                        mobile_money_number,

                        created_at,
                        updated_at

                    FROM public.drivers
                    WHERE uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Driver profile not found.',
                    code:
                        'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                driver:
                    result.rows[0],
            });
        } catch (error: unknown) {
            console.error(
                '❌ Error fetching current driver:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to fetch driver profile.',
                code:
                    'DRIVER_FETCH_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| EXPORT ROUTER
|--------------------------------------------------------------------------
|
| This is required because server.ts uses:
|
| import driverRoutes from './routes/driverRoutes';
|
|--------------------------------------------------------------------------
*/

export default router;
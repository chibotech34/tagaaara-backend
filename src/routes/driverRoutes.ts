import {
    Router,
    Request,
    Response,
    NextFunction,
} from 'express';

import multer from 'multer';
import { createClient } from '@supabase/supabase-js';

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
*/

const verifyFirebaseToken = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
            success: false,
            message:
                'Missing or invalid Authorization header. Expected Bearer token.',
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
        const decodedToken = await firebaseAuth.verifyIdToken(token);

        req.decodedToken = {
            uid: decodedToken.uid,
            email: decodedToken.email,
            name: decodedToken.name,
        };

        next();
    } catch (error: unknown) {
        console.error('❌ Firebase token verification failed:', error);

        const firebaseError = error as { code?: string; message?: string };

        if (firebaseError.code === 'auth/id-token-expired') {
            res.status(401).json({
                success: false,
                message:
                    'Firebase ID token expired. Please refresh authentication and try again.',
                code: 'AUTH_TOKEN_EXPIRED',
            });
            return;
        }

        if (firebaseError.code === 'auth/id-token-revoked') {
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
| Helpers
|--------------------------------------------------------------------------
*/

const getAuthenticatedUid = (req: AuthenticatedRequest): string | null => {
    return req.decodedToken?.uid || null;
};

const normaliseParam = (value: string | string[] | undefined): string => {
    if (value === undefined) return '';
    return Array.isArray(value) ? value[0] ?? '' : value;
};

/*
|--------------------------------------------------------------------------
| Supabase Storage (lazy — a missing env var won't crash boot)
|--------------------------------------------------------------------------
*/

const SUPABASE_DRIVER_BUCKET =
    process.env.SUPABASE_DRIVER_BUCKET || 'driver-assets';

let _supabaseAdmin: ReturnType<typeof createClient> | null = null;

function getSupabaseAdmin() {
    if (_supabaseAdmin) return _supabaseAdmin;

    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!url || !key) {
        throw new Error(
            'Supabase Storage is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY on the server.',
        );
    }

    console.log('✅ Supabase Storage client initialised');
    _supabaseAdmin = createClient(url, key, {
        auth: { persistSession: false },
    });
    return _supabaseAdmin;
}

/*
|--------------------------------------------------------------------------
| Multer + allowed image fields
|--------------------------------------------------------------------------
*/

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
    fileFilter: (_req, file, cb) => {
        const ok = /^image\/(jpeg|jpg|png|webp)$/i.test(file.mimetype);
        if (!ok) {
            cb(new Error('Only JPEG, PNG or WebP images are allowed.'));
            return;
        }
        cb(null, true);
    },
});

const ALLOWED_IMAGE_FIELDS = new Set([
    'profile_photo_url',
    'vehicle_photo_url',
    'license_photo_url',
    'registration_doc_url',
    'insurance_doc_url',
    'inspection_doc_url',
]);

/*
|--------------------------------------------------------------------------
| POST /api/drivers/register
|--------------------------------------------------------------------------
*/

router.post(
    '/register',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
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

            const decodedUid = getAuthenticatedUid(req);

            if (!decodedUid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated Firebase user was not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            if (!uid || !full_name || !phone || !registration_number) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Missing required fields: uid, full_name, phone, registration_number.',
                    code: 'REQUIRED_FIELDS_MISSING',
                });
            }

            if (uid !== decodedUid) {
                return res.status(403).json({
                    success: false,
                    message:
                        'UID in request does not match authenticated Firebase user.',
                    code: 'UID_MISMATCH',
                });
            }

            const existing = await pool.query(
                `
                SELECT id, uid, phone, registration_number
                FROM public.drivers
                WHERE uid = $1 OR phone = $2 OR registration_number = $3
                LIMIT 1
                `,
                [uid, phone, registration_number],
            );

            if (existing.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    message:
                        'An account with this UID, phone, or registration number already exists. Please log in.',
                    code: 'DRIVER_ALREADY_EXISTS',
                    existingId: existing.rows[0].id,
                });
            }

            const result = await pool.query(
                `
                INSERT INTO public.drivers (
                    uid, full_name, phone, email, profile_photo_url,
                    date_of_birth, gender, national_id, license_number,
                    license_expiry_date,
                    vehicle_type, registration_number, vehicle_color,
                    vehicle_model, vehicle_year,
                    vehicle_photo_url, region, district, town_city, home_address,
                    preferred_payment_method, mobile_money_provider,
                    mobile_money_number,
                    is_online, is_available, status,
                    rating, total_rides, completed_rides, cancelled_rides,
                    created_at, updated_at
                )
                VALUES (
                    $1, $2, $3, $4, $5,
                    $6, $7, $8, $9, $10,
                    $11, $12, $13, $14, $15,
                    $16, $17, $18, $19, $20,
                    $21, $22, $23,
                    false, false, 'pending',
                    5.0, 0, 0, 0,
                    NOW(), NOW()
                )
                RETURNING id, uid, status
                `,
                [
                    uid,
                    full_name,
                    phone,
                    email || req.decodedToken?.email || null,
                    profile_photo_url || null,
                    date_of_birth || null,
                    gender || null,
                    national_id || null,
                    license_number || null,
                    license_expiry_date || null,
                    vehicle_type || 'rickshaw',
                    registration_number,
                    vehicle_color || null,
                    vehicle_model || null,
                    vehicle_year || null,
                    vehicle_photo_url || null,
                    region || null,
                    district || null,
                    town_city || null,
                    home_address || null,
                    preferred_payment_method || null,
                    mobile_money_provider || null,
                    mobile_money_number || null,
                ],
            );

            return res.status(201).json({
                success: true,
                message: 'Driver registered successfully.',
                driverId: result.rows[0].id,
                uid: result.rows[0].uid,
                status: result.rows[0].status,
            });
        } catch (error: unknown) {
            console.error('❌ Driver registration error:', error);

            const dbError = error as {
                code?: string;
                message?: string;
                detail?: string;
            };

            if (dbError.code === '23505') {
                return res.status(409).json({
                    success: false,
                    message:
                        'A driver with this UID, phone number, or vehicle registration already exists.',
                    code: 'DRIVER_DUPLICATE',
                });
            }

            return res.status(500).json({
                success: false,
                message: 'Registration failed due to a server error.',
                code: 'DB_INSERT_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| POST /api/drivers/upload-image
|--------------------------------------------------------------------------
|
| Multipart body:
|   field_name = profile_photo_url | vehicle_photo_url | license_photo_url |
|                registration_doc_url | insurance_doc_url | inspection_doc_url
|   file       = <binary>
|
| Stores the file in Supabase Storage and updates the driver row with the
| public URL. Returns the refreshed driver row.
|
|--------------------------------------------------------------------------
*/

router.post(
    '/upload-image',
    verifyFirebaseToken,
    upload.single('file'),
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

            const fieldName = String(
                (req.body?.field_name ?? '').toString().trim(),
            );

            if (!fieldName || !ALLOWED_IMAGE_FIELDS.has(fieldName)) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid or missing field_name. Allowed: ' +
                        Array.from(ALLOWED_IMAGE_FIELDS).join(', '),
                    code: 'INVALID_FIELD_NAME',
                });
            }

            const file = req.file;

            if (!file) {
                return res.status(400).json({
                    success: false,
                    message:
                        'No file uploaded. Expected multipart field "file".',
                    code: 'FILE_MISSING',
                });
            }

            const driverLookup = await pool.query(
                `SELECT id FROM public.drivers WHERE uid = $1 LIMIT 1`,
                [uid],
            );

            if (driverLookup.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            const driverId: number = driverLookup.rows[0].id;

            const ext = (() => {
                const original = file.originalname || '';
                const dot = original.lastIndexOf('.');
                if (dot >= 0) return original.slice(dot + 1).toLowerCase();
                if (file.mimetype === 'image/png') return 'png';
                if (file.mimetype === 'image/webp') return 'webp';
                return 'jpg';
            })();

            const objectPath = `drivers/${driverId}/${fieldName}-${Date.now()}.${ext}`;

            const supabase = getSupabaseAdmin();

            const { error: uploadError } = await supabase.storage
                .from(SUPABASE_DRIVER_BUCKET)
                .upload(objectPath, file.buffer, {
                    contentType: file.mimetype,
                    upsert: true,
                });

            if (uploadError) {
                console.error('❌ Supabase upload error:', uploadError);
                return res.status(500).json({
                    success: false,
                    message: 'Image upload failed.',
                    code: 'STORAGE_UPLOAD_FAILED',
                    error: uploadError.message,
                });
            }

            const { data: urlData } = supabase.storage
                .from(SUPABASE_DRIVER_BUCKET)
                .getPublicUrl(objectPath);

            const publicUrl = urlData?.publicUrl;

            if (!publicUrl) {
                return res.status(500).json({
                    success: false,
                    message:
                        'Failed to resolve public URL for uploaded image.',
                    code: 'STORAGE_URL_FAILED',
                });
            }

            // fieldName is whitelisted above, so interpolation is safe.
            const updated = await pool.query(
                `
                UPDATE public.drivers
                SET ${fieldName} = $1, updated_at = NOW()
                WHERE uid = $2
                RETURNING *
                `,
                [publicUrl, uid],
            );

            if (updated.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found after update.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message: 'Image uploaded successfully.',
                url: publicUrl,
                driver: updated.rows[0],
            });
        } catch (error: unknown) {
            console.error('❌ Upload driver image error:', error);

            const err = error as { message?: string; code?: string };

            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(413).json({
                    success: false,
                    message: 'File too large. Maximum size is 10 MB.',
                    code: 'FILE_TOO_LARGE',
                });
            }

            if (
                typeof err.message === 'string' &&
                err.message.includes('Supabase Storage is not configured')
            ) {
                return res.status(500).json({
                    success: false,
                    message:
                        'Server misconfigured: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set.',
                    code: 'SUPABASE_NOT_CONFIGURED',
                });
            }

            return res.status(500).json({
                success: false,
                message: err.message || 'Failed to upload image.',
                code: 'IMAGE_UPLOAD_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /api/drivers/uid/:uid
|--------------------------------------------------------------------------
*/

router.get(
    '/uid/:uid',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = normaliseParam(req.params.uid);
        const authenticatedUid = getAuthenticatedUid(req);

        if (!authenticatedUid || uid !== authenticatedUid) {
            return res.status(403).json({
                success: false,
                message:
                    'Forbidden: UID does not match authenticated Firebase user.',
                code: 'UID_MISMATCH',
            });
        }

        try {
            const result = await pool.query(
                `
                SELECT
                    id, uid, full_name, phone, email, profile_photo_url,
                    date_of_birth, gender, national_id, license_number,
                    license_expiry_date,
                    vehicle_type, registration_number, vehicle_color,
                    vehicle_model, vehicle_year,
                    vehicle_photo_url,
                    license_photo_url, registration_doc_url,
                    insurance_doc_url, inspection_doc_url,
                    region, district, town_city, home_address,
                    is_online, is_available, status,
                    current_latitude, current_longitude, last_location_update,
                    rating, total_rides, completed_rides, cancelled_rides,
                    preferred_payment_method, mobile_money_provider,
                    mobile_money_number,
                    reviewer_comment, correction_message,
                    created_at, updated_at
                FROM public.drivers
                WHERE uid = $1
                `,
                [uid],
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                driver: result.rows[0],
            });
        } catch (error: unknown) {
            console.error('❌ Error fetching driver by UID:', error);

            const dbError = error as { message?: string };

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch driver data.',
                code: 'DRIVER_FETCH_FAILED',
                error: dbError.message,
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /api/drivers/me
|--------------------------------------------------------------------------
*/

router.get(
    '/me',
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
                SELECT *
                FROM public.drivers
                WHERE uid = $1
                LIMIT 1
                `,
                [uid],
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver profile not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                driver: result.rows[0],
            });
        } catch (error: unknown) {
            console.error('❌ Error fetching current driver:', error);

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch driver profile.',
                code: 'DRIVER_FETCH_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /api/drivers/nearby
|--------------------------------------------------------------------------
*/

router.get(
    '/nearby',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const {
                lat,
                lng,
                radius = 5000,
                onlyOnline = 'true',
                onlyAvailable = 'true',
            } = req.query;

            if (!lat || !lng) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Missing required query parameters: lat and lng',
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
                    message:
                        'Invalid numeric values for lat, lng, or radius',
                    code: 'INVALID_PARAMETERS',
                });
            }

            const conditions: string[] = ["status = 'approved'"];
            const values: any[] = [longitude, latitude, searchRadius];
            let paramIndex = 4;

            if (onlyOnline === 'true') {
                conditions.push(`is_online = $${paramIndex++}`);
                values.push(true);
            }

            if (onlyAvailable === 'true') {
                conditions.push(`is_available = $${paramIndex++}`);
                values.push(true);
            }

            const whereClause = `WHERE ${conditions.join(' AND ')}`;

            const query = `
                SELECT
                    id, uid, full_name, phone, email, profile_photo_url,
                    vehicle_type, registration_number, vehicle_color,
                    vehicle_model, is_online, is_available, rating,
                    current_latitude, current_longitude,
                    ROUND(
                        ST_Distance(
                            location,
                            ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography
                        )
                    ) AS distance_meters
                FROM public.drivers
                ${whereClause}
                AND ST_DWithin(
                    location,
                    ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography,
                    $3
                )
                ORDER BY distance_meters ASC
                LIMIT 50;
            `;

            const result = await pool.query(query, values);

            return res.status(200).json({
                success: true,
                drivers: result.rows,
            });
        } catch (error: unknown) {
            console.error('❌ Error fetching nearby drivers:', error);

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch nearby drivers',
                code: 'NEARBY_DRIVERS_FAILED',
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
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = normaliseParam(req.params.uid);
        const authenticatedUid = getAuthenticatedUid(req);

        if (!authenticatedUid || uid !== authenticatedUid) {
            return res.status(403).json({
                success: false,
                message:
                    'Forbidden: UID does not match authenticated Firebase user.',
                code: 'UID_MISMATCH',
            });
        }

        try {
            const result = await pool.query(
                `
                SELECT id, uid, status, is_online, is_available
                FROM public.drivers
                WHERE uid = $1
                `,
                [uid],
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                status: result.rows[0].status,
                isOnline: result.rows[0].is_online,
                isAvailable: result.rows[0].is_available,
            });
        } catch (error: unknown) {
            console.error('❌ Error fetching driver status:', error);

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch driver status.',
                code: 'STATUS_FETCH_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /api/drivers/:id/stats
|--------------------------------------------------------------------------
*/

router.get(
    '/:id/stats',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const id = normaliseParam(req.params.id);
        const authenticatedUid = getAuthenticatedUid(req);

        if (!authenticatedUid) {
            return res.status(401).json({
                success: false,
                message: 'Authenticated user not found.',
                code: 'AUTH_USER_MISSING',
            });
        }

        if (!id || !/^\d+$/.test(id)) {
            return res.status(400).json({
                success: false,
                message: 'Driver id must be a numeric value.',
                code: 'INVALID_DRIVER_ID',
            });
        }

        try {
            const driverCheck = await pool.query(
                `
                SELECT id, uid
                FROM public.drivers
                WHERE id = $1 AND uid = $2
                LIMIT 1
                `,
                [id, authenticatedUid],
            );

            if (driverCheck.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Driver not found or does not belong to authenticated user.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            const driverUid = driverCheck.rows[0].uid as string;

            const stats = await pool.query(
                `
                SELECT
                    COALESCE(
                        SUM(
                            CASE
                                WHEN status = 'completed'
                                 AND completed_at >= CURRENT_DATE
                                THEN driver_earnings
                                ELSE 0
                            END
                        ),
                        0
                    )::numeric AS today_earnings,
                    COUNT(*)::int AS total_trips,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END)::int
                        AS completed_trips,
                    COALESCE(
                        SUM(
                            CASE
                                WHEN status = 'completed'
                                 AND completed_at >= CURRENT_DATE
                                THEN distance
                                ELSE 0
                            END
                        ),
                        0
                    )::numeric AS distance_today
                FROM public.rides
                WHERE driver_id = $1
                `,
                [driverUid],
            );

            const row = stats.rows[0] || {};

            return res.status(200).json({
                success: true,
                today_earnings: Number(row.today_earnings ?? 0),
                total_trips: Number(row.total_trips ?? 0),
                completed_trips: Number(row.completed_trips ?? 0),
                distance_today: Number(row.distance_today ?? 0),
            });
        } catch (error: unknown) {
            console.error('❌ Error fetching driver stats:', error);

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch driver stats.',
                code: 'STATS_FETCH_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /api/drivers/:uid/current-request
|--------------------------------------------------------------------------
*/

router.get(
    '/:uid/current-request',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = normaliseParam(req.params.uid);
        const authenticatedUid = getAuthenticatedUid(req);

        if (!uid || !authenticatedUid || uid !== authenticatedUid) {
            return res.status(403).json({
                success: false,
                message:
                    'Forbidden: UID does not match authenticated Firebase user.',
                code: 'UID_MISMATCH',
            });
        }

        try {
            const driverResult = await pool.query(
                `SELECT id FROM public.drivers WHERE uid = $1 LIMIT 1`,
                [uid],
            );

            if (driverResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            const activeRide = await pool.query(
                `
                SELECT
                    r.id, r.driver_id, r.passenger_id, r.status,
                    r.pickup_address,
                    ST_Y(r.pickup::geometry)      AS pickup_lat,
                    ST_X(r.pickup::geometry)      AS pickup_lng,
                    r.destination_address,
                    ST_Y(r.destination::geometry) AS dest_lat,
                    ST_X(r.destination::geometry) AS dest_lng,
                    r.ride_type,
                    r.distance,
                    r.duration,
                    r.fare,
                    r.driver_earnings,
                    r.tegaara_commission,
                    r.payment_method,
                    r.payment_status,
                    r.requested_at,
                    p.full_name AS passenger_name,
                    p.profile_photo_url AS passenger_photo_url,
                    p.rating AS passenger_rating,
                    p.total_rides AS passenger_rides
                FROM public.rides r
                LEFT JOIN public.passengers p ON p.id = r.passenger_id
                WHERE r.driver_id = $1
                  AND r.status IN ('accepted', 'arrived', 'started')
                ORDER BY r.requested_at DESC
                LIMIT 1
                `,
                [uid],
            );

            if (activeRide.rows.length === 0) {
                return res.status(200).json({ success: true, ride: null });
            }

            return res.status(200).json({
                success: true,
                ride: activeRide.rows[0],
            });
        } catch (error: unknown) {
            console.error('❌ Error fetching current ride:', error);

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch current ride.',
                code: 'CURRENT_RIDE_FETCH_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| POST /api/drivers/update-location
|--------------------------------------------------------------------------
*/

router.post(
    '/update-location',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const { latitude, longitude } = req.body;

            if (latitude === undefined || longitude === undefined) {
                return res.status(400).json({
                    success: false,
                    message: 'Missing latitude or longitude.',
                    code: 'MISSING_LOCATION',
                });
            }

            const lat = Number(latitude);
            const lng = Number(longitude);

            if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid latitude or longitude.',
                    code: 'INVALID_LOCATION',
                });
            }

            if (lat < -90 || lat > 90) {
                return res.status(400).json({
                    success: false,
                    message: 'Latitude must be between -90 and 90.',
                    code: 'INVALID_LATITUDE',
                });
            }

            if (lng < -180 || lng > 180) {
                return res.status(400).json({
                    success: false,
                    message: 'Longitude must be between -180 and 180.',
                    code: 'INVALID_LONGITUDE',
                });
            }

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
                UPDATE public.drivers
                SET
                    current_latitude = $1::numeric,
                    current_longitude = $2::numeric,
                    location = ST_SetSRID(
                        ST_MakePoint($2::double precision, $1::double precision),
                        4326
                    )::geography,
                    last_location_update = NOW(),
                    updated_at = NOW()
                WHERE uid = $3
                RETURNING id, uid, current_latitude, current_longitude,
                          last_location_update
                `,
                [lat, lng, uid],
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message: 'Location updated successfully.',
                location: {
                    latitude: result.rows[0].current_latitude,
                    longitude: result.rows[0].current_longitude,
                    updatedAt: result.rows[0].last_location_update,
                },
            });
        } catch (error: unknown) {
            console.error('❌ Update location error:', error);

            return res.status(500).json({
                success: false,
                message: 'Failed to update location.',
                code: 'LOCATION_UPDATE_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| POST /api/drivers/update-status
|--------------------------------------------------------------------------
*/

router.post(
    '/update-status',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const { isOnline, isAvailable } = req.body;

            if (
                typeof isOnline !== 'boolean' ||
                typeof isAvailable !== 'boolean'
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'isOnline and isAvailable must both be boolean values.',
                    code: 'INVALID_STATUS',
                });
            }

            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const driverResult = await pool.query(
                `
                SELECT id, uid, status, is_online, is_available
                FROM public.drivers
                WHERE uid = $1
                LIMIT 1
                `,
                [uid],
            );

            if (driverResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            const driver = driverResult.rows[0];

            if (isOnline && driver.status !== 'approved') {
                return res.status(403).json({
                    success: false,
                    message:
                        'Cannot go online. Driver account is not approved.',
                    code: 'NOT_APPROVED',
                    status: driver.status,
                });
            }

            const finalAvailable = isOnline ? isAvailable : false;

            const result = await pool.query(
                `
                UPDATE public.drivers
                SET is_online = $1, is_available = $2, updated_at = NOW()
                WHERE uid = $3
                RETURNING id, uid, status, is_online, is_available, updated_at
                `,
                [isOnline, finalAvailable, uid],
            );

            return res.status(200).json({
                success: true,
                message: 'Driver status updated successfully.',
                driver: {
                    id: result.rows[0].id,
                    uid: result.rows[0].uid,
                    status: result.rows[0].status,
                    isOnline: result.rows[0].is_online,
                    isAvailable: result.rows[0].is_available,
                },
            });
        } catch (error: unknown) {
            console.error('❌ Update driver status error:', error);

            return res.status(500).json({
                success: false,
                message: 'Failed to update driver status.',
                code: 'STATUS_UPDATE_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| PATCH /api/drivers/:uid
|--------------------------------------------------------------------------
*/

router.patch(
    '/:uid',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = normaliseParam(req.params.uid);
        const authenticatedUid = getAuthenticatedUid(req);

        if (!uid || !authenticatedUid || uid !== authenticatedUid) {
            return res.status(403).json({
                success: false,
                message:
                    'Forbidden: UID does not match authenticated Firebase user.',
                code: 'UID_MISMATCH',
            });
        }

        const EDITABLE_FIELDS = [
            'full_name',
            'phone',
            'email',
            'gender',
            'date_of_birth',
            'national_id',
            'license_number',
            'license_expiry_date',
            'home_address',
            'region',
            'district',
            'town_city',
            'vehicle_type',
            'vehicle_model',
            'vehicle_color',
            'vehicle_year',
            'registration_number',
            'profile_photo_url',
            'vehicle_photo_url',
            'license_photo_url',
            'registration_doc_url',
            'insurance_doc_url',
            'inspection_doc_url',
            'is_online',
            'is_available',
        ] as const;

        const body = (req.body ?? {}) as Record<string, unknown>;

        const update: Record<string, unknown> = {};
        for (const key of EDITABLE_FIELDS) {
            if (Object.prototype.hasOwnProperty.call(body, key)) {
                update[key] = body[key];
            }
        }

        if (Object.keys(update).length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No editable fields provided.',
                code: 'NO_EDITABLE_FIELDS',
            });
        }

        try {
            if (update.is_online === true) {
                const check = await pool.query(
                    `SELECT status FROM public.drivers WHERE uid = $1 LIMIT 1`,
                    [uid],
                );

                if (check.rows.length === 0) {
                    return res.status(404).json({
                        success: false,
                        message: 'Driver not found.',
                        code: 'DRIVER_NOT_FOUND',
                    });
                }

                if (check.rows[0].status !== 'approved') {
                    return res.status(403).json({
                        success: false,
                        message:
                            'Cannot go online. Driver account is not approved.',
                        code: 'NOT_APPROVED',
                        status: check.rows[0].status,
                    });
                }
            }

            if (update.is_online === false) {
                update.is_available = false;
            }

            const entries = Object.entries(update);
            const setSql = entries
                .map(([k], i) => `${k} = $${i + 1}`)
                .join(', ');
            const values: unknown[] = entries.map(([, v]) => v);

            const result = await pool.query(
                `
                UPDATE public.drivers
                SET ${setSql}, updated_at = NOW()
                WHERE uid = $${entries.length + 1}
                RETURNING *
                `,
                [...values, uid],
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message: 'Driver profile updated successfully.',
                driver: result.rows[0],
            });
        } catch (error: unknown) {
            console.error('❌ Update driver profile error:', error);

            const dbError = error as { code?: string; message?: string };

            if (dbError.code === '23505') {
                return res.status(409).json({
                    success: false,
                    message:
                        'A driver with this phone number or registration number already exists.',
                    code: 'DRIVER_DUPLICATE',
                });
            }

            return res.status(500).json({
                success: false,
                message: 'Failed to update driver profile.',
                code: 'PROFILE_UPDATE_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| DELETE /api/drivers/account
|--------------------------------------------------------------------------
*/

router.delete(
    '/account',
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
                `DELETE FROM public.drivers WHERE uid = $1 RETURNING id`,
                [uid],
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message: 'Driver account deleted successfully.',
            });
        } catch (error: unknown) {
            console.error('❌ Delete driver account error:', error);

            return res.status(500).json({
                success: false,
                message: 'Failed to delete driver account.',
                code: 'ACCOUNT_DELETE_FAILED',
            });
        }
    },
);

export default router;
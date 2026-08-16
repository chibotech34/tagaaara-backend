import { Router, Request, Response, NextFunction } from 'express';
import pool from '../config/database';
import { getAuth } from 'firebase-admin/auth';
import { getApps, initializeApp, cert } from 'firebase-admin/app';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

dotenv.config();

// -----------------------------------------------------------------------------
// Firebase Admin initialization
// -----------------------------------------------------------------------------
if (getApps().length === 0) {
    const serviceAccountPath = process.env.FIREBASE_ADMIN_SDK_PATH;

    if (!serviceAccountPath) {
        throw new Error('Missing FIREBASE_ADMIN_SDK_PATH in environment');
    }

    const firebaseDatabaseUrl = process.env.FIREBASE_DATABASE_URL;

    if (!firebaseDatabaseUrl) {
        throw new Error('Missing FIREBASE_DATABASE_URL in environment');
    }

    const resolvedPath = path.resolve(process.cwd(), serviceAccountPath);

    if (!fs.existsSync(resolvedPath)) {
        throw new Error(`Service account file not found: ${resolvedPath}`);
    }

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const serviceAccount = require(resolvedPath);

    initializeApp({
        credential: cert(serviceAccount),
        databaseURL: firebaseDatabaseUrl,
    });

    console.log('✅ Firebase Admin initialized in driverRoutes');
}

const router = Router();

// -----------------------------------------------------------------------------
// Firebase ID-token middleware
// -----------------------------------------------------------------------------
const verifyFirebaseToken = async (
    req: Request,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
            success: false,
            message: 'Missing or invalid Authorization header. Expected Bearer token.',
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
        const decodedToken = await getAuth().verifyIdToken(token);

        (req as Request & { decodedToken?: typeof decodedToken }).decodedToken = decodedToken;

        next();
    } catch (error: unknown) {
        console.error('❌ Firebase token verification failed:', error);

        const firebaseError = error as { code?: string; message?: string };

        if (firebaseError.code === 'auth/id-token-expired') {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token expired. Please refresh authentication and try again.',
                code: 'AUTH_TOKEN_EXPIRED',
            });
            return;
        }

        if (firebaseError.code === 'auth/id-token-revoked') {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token has been revoked. Please sign in again.',
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

// -----------------------------------------------------------------------------
// POST /api/drivers/register
// -----------------------------------------------------------------------------
router.post('/register', verifyFirebaseToken, async (req: Request, res: Response) => {
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

        const decodedToken = (req as Request & {
            decodedToken?: { uid: string; email?: string };
        }).decodedToken;

        if (!decodedToken) {
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
                    'Missing required fields: uid, full_name, phone, registration_number',
                code: 'REQUIRED_FIELDS_MISSING',
            });
        }

        if (uid !== decodedToken.uid) {
            return res.status(403).json({
                success: false,
                message: 'UID in request does not match authenticated Firebase user.',
                code: 'UID_MISMATCH',
            });
        }

        const existing = await pool.query(
            `SELECT id, uid, phone, registration_number
             FROM drivers
             WHERE uid = $1 OR phone = $2 OR registration_number = $3
             LIMIT 1`,
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
            INSERT INTO drivers (
                uid, full_name, phone, email, profile_photo_url,
                date_of_birth, gender, national_id, license_number, license_expiry_date,
                vehicle_type, registration_number, vehicle_color, vehicle_model, vehicle_year,
                vehicle_photo_url, region, district, town_city, home_address,
                preferred_payment_method, mobile_money_provider, mobile_money_number,
                is_online, is_available, status, rating, total_rides, completed_rides, cancelled_rides,
                created_at, updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15,
                $16, $17, $18, $19, $20,
                $21, $22, $23,
                false, false, 'pending', 5.0, 0, 0, 0,
                NOW(), NOW()
            )
            RETURNING id
            `,
            [
                uid,
                full_name,
                phone,
                email || decodedToken.email || null,
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
            message: 'Driver registered successfully',
            driverId: result.rows[0].id,
        });
    } catch (error: unknown) {
        console.error('❌ Driver registration error:', error);

        const dbError = error as { code?: string; message?: string; detail?: string };

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
});

// -----------------------------------------------------------------------------
// GET /api/drivers/uid/:uid
// -----------------------------------------------------------------------------
router.get('/uid/:uid', verifyFirebaseToken, async (req: Request, res: Response) => {
    const { uid } = req.params;

    const decodedToken = (req as Request & {
        decodedToken?: { uid: string };
    }).decodedToken;

    if (!decodedToken || uid !== decodedToken.uid) {
        return res.status(403).json({
            success: false,
            message: 'Forbidden: UID does not match authenticated Firebase user.',
            code: 'UID_MISMATCH',
        });
    }

    try {
        const result = await pool.query(
            `SELECT
                id, uid, full_name, phone, email, profile_photo_url,
                date_of_birth, gender, national_id, license_number, license_expiry_date,
                vehicle_type, registration_number, vehicle_color, vehicle_model, vehicle_year,
                vehicle_photo_url, region, district, town_city, home_address,
                is_online, is_available, status,
                current_latitude, current_longitude,
                last_location_update, rating, total_rides, completed_rides, cancelled_rides,
                preferred_payment_method, mobile_money_provider, mobile_money_number,
                created_at, updated_at
             FROM drivers
             WHERE uid = $1`,
            [uid],
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Driver not found.',
                code: 'DRIVER_NOT_FOUND',
            });
        }

        return res.status(200).json(result.rows[0]);
    } catch (error: unknown) {
        console.error('❌ Error fetching driver by UID:', error);

        const dbError = error as { message?: string };

        return res.status(500).json({
            success: false,
            message: 'Failed to fetch driver data.',
            error: dbError.message,
        });
    }
});

// -----------------------------------------------------------------------------
// GET /api/drivers/:uid/status
// -----------------------------------------------------------------------------
router.get('/:uid/status', verifyFirebaseToken, async (req: Request, res: Response) => {
    const { uid } = req.params;

    const decodedToken = (req as Request & {
        decodedToken?: { uid: string };
    }).decodedToken;

    if (!decodedToken || uid !== decodedToken.uid) {
        return res.status(403).json({
            success: false,
            message: 'Forbidden: UID does not match authenticated Firebase user.',
            code: 'UID_MISMATCH',
        });
    }

    try {
        const result = await pool.query(
            'SELECT status FROM drivers WHERE uid = $1',
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
        });
    } catch (error: unknown) {
        console.error('❌ Error fetching driver status:', error);

        const dbError = error as { message?: string };

        return res.status(500).json({
            success: false,
            message: 'Failed to fetch driver status.',
            error: dbError.message,
        });
    }
});

// -----------------------------------------------------------------------------
// POST /api/drivers/update-location
// (Uses PostGIS to update the geography column)
// FIX: Explicit casts to resolve PostgreSQL 42P08 type inference error
// -----------------------------------------------------------------------------
router.post('/update-location', verifyFirebaseToken, async (req: Request, res: Response) => {
    try {
        const { latitude, longitude } = req.body;

        if (latitude === undefined || longitude === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Missing latitude or longitude.',
                code: 'MISSING_LOCATION',
            });
        }

        const lat = parseFloat(latitude);
        const lng = parseFloat(longitude);

        if (isNaN(lat) || isNaN(lng)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid latitude or longitude.',
                code: 'INVALID_LOCATION',
            });
        }

        const decodedToken = (req as Request & { decodedToken?: { uid: string } }).decodedToken;
        if (!decodedToken) {
            return res.status(401).json({
                success: false,
                message: 'Authenticated user not found.',
                code: 'AUTH_USER_MISSING',
            });
        }

        const uid = decodedToken.uid;

        // ✅ FIXED: explicit casts for both numeric columns and ST_MakePoint parameters
        const result = await pool.query(
            `UPDATE drivers
             SET current_latitude = $1::numeric,
                 current_longitude = $2::numeric,
                 location = ST_SetSRID(ST_MakePoint($2::double precision, $1::double precision), 4326)::geography,
                 last_location_update = NOW()
             WHERE uid = $3
             RETURNING id`,
            [lat, lng, uid]
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
        });
    } catch (error: unknown) {
        console.error('❌ Update location error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to update location.',
            code: 'LOCATION_UPDATE_FAILED',
        });
    }
});

// -----------------------------------------------------------------------------
// POST /api/drivers/update-status
// (Only allows going online if driver.status = 'approved')
// -----------------------------------------------------------------------------
router.post('/update-status', verifyFirebaseToken, async (req: Request, res: Response) => {
    try {
        const { isOnline, isAvailable } = req.body;

        if (isOnline === undefined || isAvailable === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Missing isOnline or isAvailable.',
                code: 'MISSING_STATUS',
            });
        }

        const online = !!isOnline;
        const available = !!isAvailable;

        const decodedToken = (req as Request & { decodedToken?: { uid: string } }).decodedToken;
        if (!decodedToken) {
            return res.status(401).json({
                success: false,
                message: 'Authenticated user not found.',
                code: 'AUTH_USER_MISSING',
            });
        }

        const uid = decodedToken.uid;

        // If the driver wants to go online, ensure the account is approved.
        if (online) {
            const statusCheck = await pool.query(
                'SELECT status FROM drivers WHERE uid = $1',
                [uid]
            );
            if (statusCheck.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                    code: 'DRIVER_NOT_FOUND',
                });
            }
            const currentStatus = statusCheck.rows[0].status;
            if (currentStatus !== 'approved') {
                return res.status(403).json({
                    success: false,
                    message: 'Cannot go online. Driver account is not approved.',
                    code: 'NOT_APPROVED',
                });
            }
        }

        const result = await pool.query(
            `UPDATE drivers
             SET is_online = $1,
                 is_available = $2,
                 updated_at = NOW()
             WHERE uid = $3
             RETURNING id`,
            [online, available, uid]
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
            message: 'Driver status updated successfully.',
        });
    } catch (error: unknown) {
        console.error('❌ Update driver status error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to update driver status.',
            code: 'STATUS_UPDATE_FAILED',
        });
    }
});

export default router;
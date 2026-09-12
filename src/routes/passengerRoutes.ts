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
    else if (/^\d{9}$/.test(value)) {
        value = '+233' + value;
    }

    // Ghana number must be +233 followed by 9 digits
    if (!/^\+233\d{9}$/.test(value)) {
        return null;
    }

    return value;
}

function toFiniteNumber(input: unknown): number | null {
    if (typeof input === 'number' && Number.isFinite(input)) {
        return input;
    }
    if (typeof input === 'string' && input.trim() !== '') {
        const n = Number(input);
        return Number.isFinite(n) ? n : null;
    }
    return null;
}

// ============================================================
// FIREBASE AUTHENTICATION MIDDLEWARE
// ============================================================

const verifyFirebaseToken = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
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

    const token = authHeader.substring(7).trim();

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
            phone_number: decodedToken.phone_number,
        };

        next();
    } catch (error: any) {
        console.error('❌ Firebase token verification failed:', error);

        if (error?.code === 'auth/id-token-expired') {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token expired.',
                code: 'AUTH_TOKEN_EXPIRED',
            });
            return;
        }

        if (error?.code === 'auth/id-token-revoked') {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token revoked.',
                code: 'AUTH_TOKEN_REVOKED',
            });
            return;
        }

        console.error('Firebase error code:', error?.code);
        console.error('Firebase error message:', error?.message);

        res.status(401).json({
            success: false,
            message: 'Firebase authentication failed.',
            code: 'AUTH_TOKEN_INVALID',
        });
    }
};

// ============================================================
// GET VERIFIED PHONE FROM FIREBASE TOKEN
// ============================================================

function getVerifiedPhoneFromToken(
    decodedToken?: DecodedFirebaseToken
): string | null {
    if (!decodedToken || !decodedToken.phone_number) {
        return null;
    }
    return normalizePhone(decodedToken.phone_number);
}

// ============================================================
// CHECK PHONE
// ============================================================

/**
 * POST /api/passengers/check-phone
 *
 * Checks whether a phone number already exists.
 * Firebase Phone Authentication handles OTP; this endpoint
 * only checks whether the passenger is registered.
 */
router.post(
    '/check-phone',
    async (req: Request, res: Response) => {
        try {
            const phone = normalizePhone(
                req.body?.phoneNumber || req.body?.phone
            );

            const purpose =
                req.body?.purpose === 'login' ? 'login' : 'register';

            if (!phone) {
                res.status(400).json({
                    success: false,
                    message: 'Enter a valid Ghana mobile number.',
                    code: 'INVALID_PHONE',
                });
                return;
            }

            const existing = await pool.query(
                `
                SELECT id
                FROM passengers
                WHERE phone = $1
                LIMIT 1
                `,
                [phone]
            );

            if (
                purpose === 'register' &&
                existing.rows.length > 0
            ) {
                res.status(409).json({
                    success: false,
                    message:
                        'This phone number is already registered. Please log in.',
                    code: 'PHONE_ALREADY_REGISTERED',
                });
                return;
            }

            if (
                purpose === 'login' &&
                existing.rows.length === 0
            ) {
                res.status(404).json({
                    success: false,
                    message:
                        'This phone number is not registered on Tegaara.',
                    code: 'PASSENGER_NOT_FOUND',
                });
                return;
            }

            res.status(200).json({
                success: true,
                phoneNumber: phone,
                exists: existing.rows.length > 0,
                purpose,
            });
        } catch (error) {
            console.error('❌ Check phone error:', error);

            res.status(500).json({
                success: false,
                message: 'Unable to check phone number right now.',
                code: 'PHONE_CHECK_FAILED',
            });
        }
    }
);

// ============================================================
// VERIFY PHONE
// ============================================================

/**
 * POST /api/passengers/verify-phone
 *
 * Flutter completes Firebase Phone Auth and sends the ID token.
 */
router.post(
    '/verify-phone',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const decoded = req.decodedToken;

            if (!decoded) {
                res.status(401).json({
                    success: false,
                    message: 'Authentication information is missing.',
                    code: 'AUTH_TOKEN_INVALID',
                });
                return;
            }

            const phoneFromToken = getVerifiedPhoneFromToken(decoded);

            if (!phoneFromToken) {
                res.status(400).json({
                    success: false,
                    message:
                        'Firebase token does not contain a verified phone number.',
                    code: 'PHONE_NOT_VERIFIED',
                });
                return;
            }

            const existing = await pool.query(
                `
                SELECT
                    id,
                    firebase_uid,
                    full_name,
                    phone,
                    email
                FROM passengers
                WHERE firebase_uid = $1
                   OR phone = $2
                LIMIT 1
                `,
                [decoded.uid, phoneFromToken]
            );

            res.status(200).json({
                success: true,
                verified: true,
                phoneNumber: phoneFromToken,
                firebaseUid: decoded.uid,
                isRegistered: existing.rows.length > 0,
                passenger: existing.rows[0] || null,
            });
        } catch (error) {
            console.error('❌ Verify phone error:', error);

            res.status(500).json({
                success: false,
                message:
                    'Phone verification failed. Please try again.',
                code: 'PHONE_VERIFY_FAILED',
            });
        }
    }
);

// ============================================================
// PROFILE
// ============================================================

/**
 * GET /api/passengers/profile
 */
router.get(
    '/profile',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = req.decodedToken!.uid;

        try {
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
                    is_online,
                    last_online_at,
                    current_latitude,
                    current_longitude,
                    last_location_update,
                    account_status,
                    created_at,
                    updated_at
                FROM passengers
                WHERE firebase_uid = $1
                `,
                [uid]
            );

            if (result.rows.length === 0) {
                res.status(404).json({
                    success: false,
                    message: 'Passenger not found',
                });
                return;
            }

            res.status(200).json({
                success: true,
                passenger: result.rows[0],
            });
        } catch (error) {
            console.error(
                '❌ Error fetching passenger profile:',
                error
            );

            res.status(500).json({
                success: false,
                message: 'Server error while fetching profile',
            });
        }
    }
);

// ============================================================
// CREATE PASSENGER
// ============================================================

/**
 * POST /api/passengers/create
 *
 * Creates a basic passenger account.
 */
router.post(
    '/create',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const { uid, email, displayName } = req.body;

            if (!uid || uid !== req.decodedToken!.uid) {
                res.status(403).json({
                    success: false,
                    message: 'UID mismatch or missing',
                    code: 'UID_MISMATCH',
                });
                return;
            }

            const phone = getVerifiedPhoneFromToken(req.decodedToken);

            if (!phone) {
                res.status(400).json({
                    success: false,
                    message:
                        'Firebase token does not contain a verified phone number.',
                    code: 'PHONE_NOT_VERIFIED',
                });
                return;
            }

            const existing = await pool.query(
                `
                SELECT id
                FROM passengers
                WHERE firebase_uid = $1
                   OR phone = $2
                `,
                [uid, phone]
            );

            if (existing.rows.length > 0) {
                res.status(200).json({
                    success: true,
                    message: 'Passenger already exists',
                    passengerId: existing.rows[0].id,
                });
                return;
            }

            const result = await pool.query(
                `
                INSERT INTO passengers (
                    firebase_uid,
                    full_name,
                    phone,
                    email,
                    created_at
                )
                VALUES ($1, $2, $3, $4, NOW())
                RETURNING id
                `,
                [
                    uid,
                    displayName ||
                    req.decodedToken!.name ||
                    'Passenger',
                    phone,
                    email || req.decodedToken!.email || null,
                ]
            );

            res.status(201).json({
                success: true,
                message: 'Passenger created successfully',
                passengerId: result.rows[0].id,
            });
        } catch (error) {
            console.error('❌ Error creating passenger:', error);

            res.status(500).json({
                success: false,
                message: 'Server error while creating passenger',
            });
        }
    }
);

// ============================================================
// REGISTER PASSENGER
// ============================================================

/**
 * POST /api/passengers/register
 *
 * Phone number MUST come from the verified Firebase token.
 * Phone number from req.body is NOT trusted.
 *
 * Marks the passenger as online and stores their initial location
 * (if provided) so drivers can immediately see them.
 */
router.post(
    '/register',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const {
                uid,
                fullName,
                email,
                gender,
                emergencyContactName,
                emergencyContactPhone,
                emergencyRelationship,
                homeAddress,
                region,
                district,
                townCity,
                savedLocations,
                preferredPaymentMethod,
                mobileMoneyNumber,
                languagePreference,
                notificationEnabled,
                privacyEnabled,
                // NEW: online status + location
                isOnline,
                latitude,
                longitude,
            } = req.body;

            // ------------------------------------------------
            // REQUIRED FIELDS
            // ------------------------------------------------
            if (!uid || !fullName) {
                res.status(400).json({
                    success: false,
                    message:
                        'Missing required fields: uid, fullName',
                    code: 'REQUIRED_FIELDS_MISSING',
                });
                return;
            }

            // ------------------------------------------------
            // VERIFY UID
            // ------------------------------------------------
            if (uid !== req.decodedToken!.uid) {
                res.status(403).json({
                    success: false,
                    message:
                        'UID in request does not match authenticated user.',
                    code: 'UID_MISMATCH',
                });
                return;
            }

            // ------------------------------------------------
            // GET VERIFIED FIREBASE PHONE
            // ------------------------------------------------
            const phone = getVerifiedPhoneFromToken(req.decodedToken);

            if (!phone) {
                res.status(403).json({
                    success: false,
                    message:
                        'Phone number has not been verified via Firebase Phone Auth.',
                    code: 'PHONE_NOT_VERIFIED',
                });
                return;
            }

            // ------------------------------------------------
            // CHECK EXISTING ACCOUNT
            // ------------------------------------------------
            const existing = await pool.query(
                `
                SELECT id
                FROM passengers
                WHERE firebase_uid = $1
                   OR phone = $2
                `,
                [uid, phone]
            );

            if (existing.rows.length > 0) {
                res.status(409).json({
                    success: false,
                    message:
                        'An account with this UID or phone already exists. Please log in.',
                    code: 'PASSENGER_ALREADY_EXISTS',
                    existingId: existing.rows[0].id,
                });
                return;
            }

            // ------------------------------------------------
            // NORMALIZE STATUS + LOCATION
            // ------------------------------------------------
            const locations = Array.isArray(savedLocations)
                ? savedLocations
                : [];

            const online =
                typeof isOnline === 'boolean' ? isOnline : true;

            const lat = toFiniteNumber(latitude);
            const lng = toFiniteNumber(longitude);

            // ------------------------------------------------
            // INSERT PASSENGER
            // ------------------------------------------------
            const result = await pool.query(
                `
                INSERT INTO passengers (
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
                    is_online,
                    last_online_at,
                    current_latitude,
                    current_longitude,
                    last_location_update,
                    created_at
                )
                VALUES (
                    $1,  $2,  $3,  $4,  $5,
                    $6,  $7,  $8,  $9,  $10,
                    $11, $12, $13, $14, $15,
                    $16, $17, $18,
                    $19,                 -- is_online
                    NOW(),               -- last_online_at
                    $20,                 -- current_latitude
                    $21,                 -- current_longitude
                    NOW(),               -- last_location_update
                    NOW()
                )
                RETURNING id
                `,
                [
                    uid,
                    fullName,
                    phone,
                    email || req.decodedToken!.email || null,
                    gender || null,
                    emergencyContactName || null,
                    emergencyContactPhone || null,
                    emergencyRelationship || null,
                    homeAddress || null,
                    region || null,
                    district || null,
                    townCity || null,
                    JSON.stringify(locations),
                    preferredPaymentMethod || null,
                    mobileMoneyNumber || null,
                    languagePreference || null,
                    notificationEnabled ?? true,
                    privacyEnabled ?? true,
                    online,   // $19
                    lat,      // $20
                    lng,      // $21
                ]
            );

            res.status(201).json({
                success: true,
                message: 'Passenger registered successfully',
                passengerId: result.rows[0].id,
                phoneNumber: phone,
            });
        } catch (error: any) {
            console.error('❌ Passenger registration error:', error);
            console.error('PostgreSQL error code:', error?.code);
            console.error('PostgreSQL error message:', error?.message);
            console.error('PostgreSQL detail:', error?.detail);
            console.error('PostgreSQL constraint:', error?.constraint);
            console.error('PostgreSQL column:', error?.column);

            res.status(500).json({
                success: false,
                message:
                    'Registration failed due to a server error.',
                code: 'DB_INSERT_FAILED',
            });
        }
    }
);

// ============================================================
// UPDATE ONLINE STATUS + LOCATION
// ============================================================

/**
 * POST /api/passengers/update-status
 *
 * Called:
 *   - right after passenger login
 *   - when the passenger toggles online / offline
 *   - periodically (or on app resume) to refresh location
 *
 * Drivers read is_online / current_latitude / current_longitude /
 * last_location_update to see passengers nearby.
 */
router.post(
    '/update-status',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = req.decodedToken!.uid;

        const { isOnline, latitude, longitude } = req.body || {};

        const online =
            typeof isOnline === 'boolean' ? isOnline : true;

        const lat = toFiniteNumber(latitude);
        const lng = toFiniteNumber(longitude);

        try {
            const result = await pool.query(
                `
                UPDATE passengers
                SET
                    is_online            = $1,
                    last_online_at       = NOW(),
                    current_latitude     = COALESCE($2, current_latitude),
                    current_longitude    = COALESCE($3, current_longitude),
                    last_location_update = CASE
                        WHEN $2 IS NOT NULL AND $3 IS NOT NULL
                        THEN NOW()
                        ELSE last_location_update
                    END,
                    updated_at           = NOW()
                WHERE firebase_uid = $4
                RETURNING
                    id,
                    is_online,
                    last_online_at,
                    current_latitude,
                    current_longitude,
                    last_location_update
                `,
                [online, lat, lng, uid]
            );

            if (result.rows.length === 0) {
                res.status(404).json({
                    success: false,
                    message:
                        'Passenger not found. Please complete registration first.',
                    code: 'PASSENGER_NOT_FOUND',
                });
                return;
            }

            res.status(200).json({
                success: true,
                status: result.rows[0],
            });
        } catch (error) {
            console.error(
                '❌ Error updating passenger status:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Unable to update passenger status right now.',
                code: 'STATUS_UPDATE_FAILED',
            });
        }
    }
);

// ============================================================
// GET WALLET
// ============================================================

/**
 * GET /api/passengers/wallet
 */
router.get(
    '/wallet',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = req.decodedToken!.uid;

        try {
            const passengerResult = await pool.query(
                `
                SELECT id
                FROM passengers
                WHERE firebase_uid = $1
                `,
                [uid]
            );

            if (passengerResult.rows.length === 0) {
                res.status(404).json({
                    success: false,
                    message:
                        'Passenger not found. Please complete registration first.',
                });
                return;
            }

            const passengerId = passengerResult.rows[0].id;

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
                FROM wallets
                WHERE passenger_id = $1
                `,
                [passengerId]
            );

            if (walletResult.rows.length === 0) {
                res.status(404).json({
                    success: false,
                    message: 'Wallet not found. Please create one.',
                });
                return;
            }

            res.status(200).json({
                success: true,
                wallet: walletResult.rows[0],
            });
        } catch (error) {
            console.error('❌ Error fetching wallet:', error);

            res.status(500).json({
                success: false,
                message: 'Server error while fetching wallet',
            });
        }
    }
);

// ============================================================
// CREATE WALLET
// ============================================================

/**
 * POST /api/passengers/wallet
 */
router.post(
    '/wallet',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = req.decodedToken!.uid;
        const { full_name, email } = req.body;

        try {
            let passengerId: number;

            // ------------------------------------------------
            // FIND PASSENGER
            // ------------------------------------------------
            const existingPassenger = await pool.query(
                `
                SELECT id
                FROM passengers
                WHERE firebase_uid = $1
                `,
                [uid]
            );

            if (existingPassenger.rows.length === 0) {
                const phoneNumber =
                    getVerifiedPhoneFromToken(req.decodedToken);

                if (!phoneNumber) {
                    res.status(400).json({
                        success: false,
                        message:
                            'Firebase account does not have a verified phone number.',
                        code: 'PHONE_NOT_VERIFIED',
                    });
                    return;
                }

                const displayName =
                    full_name || req.decodedToken!.name || 'Passenger';

                const emailAddress =
                    email || req.decodedToken!.email || null;

                const insertPassenger = await pool.query(
                    `
                    INSERT INTO passengers (
                        firebase_uid,
                        full_name,
                        email,
                        phone,
                        is_online,
                        last_online_at,
                        last_location_update,
                        created_at
                    )
                    VALUES ($1, $2, $3, $4, FALSE, NOW(), NOW(), NOW())
                    RETURNING id
                    `,
                    [uid, displayName, emailAddress, phoneNumber]
                );

                passengerId = insertPassenger.rows[0].id;
            } else {
                passengerId = existingPassenger.rows[0].id;
            }

            // ------------------------------------------------
            // CHECK EXISTING WALLET
            // ------------------------------------------------
            const existingWallet = await pool.query(
                `
                SELECT id
                FROM wallets
                WHERE passenger_id = $1
                `,
                [passengerId]
            );

            if (existingWallet.rows.length > 0) {
                const wallet = await pool.query(
                    `
                    SELECT *
                    FROM wallets
                    WHERE passenger_id = $1
                    `,
                    [passengerId]
                );

                res.status(200).json({
                    success: true,
                    message: 'Wallet already exists',
                    wallet: wallet.rows[0],
                });
                return;
            }

            // ------------------------------------------------
            // CREATE WALLET
            // ------------------------------------------------
            const newWallet = await pool.query(
                `
                INSERT INTO wallets (
                    passenger_id,
                    balance,
                    pending_balance,
                    total_spent,
                    created_at
                )
                VALUES ($1, 0, 0, 0, NOW())
                RETURNING *
                `,
                [passengerId]
            );

            res.status(201).json({
                success: true,
                message: 'Wallet created successfully',
                wallet: newWallet.rows[0],
            });
        } catch (error) {
            console.error('❌ Error creating wallet:', error);

            res.status(500).json({
                success: false,
                message: 'Server error while creating wallet',
            });
        }
    }
);

// ============================================================
// WALLET TRANSACTIONS
// ============================================================

/**
 * GET /api/passengers/wallet/transactions
 */
router.get(
    '/wallet/transactions',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = req.decodedToken!.uid;

        try {
            const passengerResult = await pool.query(
                `
                SELECT id
                FROM passengers
                WHERE firebase_uid = $1
                `,
                [uid]
            );

            if (passengerResult.rows.length === 0) {
                res.status(404).json({
                    success: false,
                    message: 'Passenger not found',
                });
                return;
            }

            const passengerId = passengerResult.rows[0].id;

            const walletResult = await pool.query(
                `
                SELECT id
                FROM wallets
                WHERE passenger_id = $1
                `,
                [passengerId]
            );

            if (walletResult.rows.length === 0) {
                res.status(404).json({
                    success: false,
                    message: 'Wallet not found',
                });
                return;
            }

            const walletId = walletResult.rows[0].id;

            const transactions = await pool.query(
                `
                SELECT
                    id,
                    wallet_id,
                    type,
                    amount,
                    balance_before,
                    balance_after,
                    status,
                    payment_method,
                    provider,
                    ride_id,
                    description,
                    created_at
                FROM transactions
                WHERE wallet_id = $1
                ORDER BY created_at DESC
                LIMIT 50
                `,
                [walletId]
            );

            res.status(200).json({
                success: true,
                transactions: transactions.rows,
            });
        } catch (error) {
            console.error(
                '❌ Error fetching transactions:',
                error
            );

            res.status(500).json({
                success: false,
                message: 'Server error while fetching transactions',
            });
        }
    }
);

// ============================================================
// EXPORT
// ============================================================

export default router;
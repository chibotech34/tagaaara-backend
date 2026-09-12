const express = require('express');
const pool = require('../config/database');
const { firebaseAuth } = require('../config/firebase');

const router = express.Router();

// ============================================================
// HELPERS
// ============================================================

function normalizePhone(phone) {
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

// ============================================================
// FIREBASE AUTHENTICATION MIDDLEWARE
// ============================================================

const verifyFirebaseToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            message:
                'Missing or invalid Authorization header. Expected Bearer token.',
            code: 'AUTH_HEADER_MISSING'
        });
    }

    const token = authHeader.substring(7).trim();

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Firebase ID token is missing.',
            code: 'AUTH_TOKEN_MISSING'
        });
    }

    try {
        // IMPORTANT:
        // Do NOT use admin.auth() here.
        // Use the shared Firebase Auth instance.
        const decodedToken =
            await firebaseAuth.verifyIdToken(token);

        req.decodedToken = {
            uid: decodedToken.uid,
            email: decodedToken.email,
            name: decodedToken.name,
            phone_number: decodedToken.phone_number
        };

        next();
    } catch (error) {
        console.error(
            '❌ Firebase token verification failed:',
            error
        );

        const firebaseError = error || {};

        if (
            firebaseError.code ===
            'auth/id-token-expired'
        ) {
            return res.status(401).json({
                success: false,
                message: 'Firebase ID token expired.',
                code: 'AUTH_TOKEN_EXPIRED'
            });
        }

        if (
            firebaseError.code ===
            'auth/id-token-revoked'
        ) {
            return res.status(401).json({
                success: false,
                message: 'Firebase ID token revoked.',
                code: 'AUTH_TOKEN_REVOKED'
            });
        }

        console.error(
            'Firebase error code:',
            firebaseError.code
        );

        console.error(
            'Firebase error message:',
            firebaseError.message
        );

        return res.status(401).json({
            success: false,
            message: 'Firebase authentication failed.',
            code: 'AUTH_TOKEN_INVALID'
        });
    }
};

// ============================================================
// GET VERIFIED PHONE FROM FIREBASE TOKEN
// ============================================================

function getVerifiedPhoneFromToken(decodedToken) {
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
 *
 * This route DOES NOT send OTP.
 * Firebase Phone Authentication handles OTP.
 */

router.post('/check-phone', async (req, res) => {
    try {
        const phone = normalizePhone(
            req.body?.phoneNumber ||
            req.body?.phone
        );

        const purpose =
            req.body?.purpose === 'login'
                ? 'login'
                : 'register';

        if (!phone) {
            return res.status(400).json({
                success: false,
                message:
                    'Enter a valid Ghana mobile number.',
                code: 'INVALID_PHONE'
            });
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
            return res.status(409).json({
                success: false,
                message:
                    'This phone number is already registered. Please log in.',
                code: 'PHONE_ALREADY_REGISTERED'
            });
        }

        if (
            purpose === 'login' &&
            existing.rows.length === 0
        ) {
            return res.status(404).json({
                success: false,
                message:
                    'This phone number is not registered on Tegaara.',
                code: 'PASSENGER_NOT_FOUND'
            });
        }

        return res.status(200).json({
            success: true,
            phoneNumber: phone,
            exists: existing.rows.length > 0,
            purpose
        });
    } catch (error) {
        console.error(
            '❌ Check phone error:',
            error
        );

        return res.status(500).json({
            success: false,
            message:
                'Unable to check phone number right now.',
            code: 'PHONE_CHECK_FAILED'
        });
    }
});

// ============================================================
// VERIFY PHONE
// ============================================================

/**
 * POST /api/passengers/verify-phone
 *
 * Flutter completes Firebase Phone Auth.
 * Flutter then sends the Firebase ID token here.
 */

router.post(
    '/verify-phone',
    verifyFirebaseToken,
    async (req, res) => {
        try {
            const decoded = req.decodedToken;

            if (!decoded) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Authentication information is missing.',
                    code: 'AUTH_TOKEN_INVALID'
                });
            }

            const phoneFromToken =
                getVerifiedPhoneFromToken(decoded);

            if (!phoneFromToken) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Firebase token does not contain a verified phone number.',
                    code: 'PHONE_NOT_VERIFIED'
                });
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
                [
                    decoded.uid,
                    phoneFromToken
                ]
            );

            return res.status(200).json({
                success: true,
                verified: true,
                phoneNumber: phoneFromToken,
                firebaseUid: decoded.uid,
                isRegistered:
                    existing.rows.length > 0,
                passenger:
                    existing.rows[0] || null
            });
        } catch (error) {
            console.error(
                '❌ Verify phone error:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Phone verification failed. Please try again.',
                code: 'PHONE_VERIFY_FAILED'
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
    async (req, res) => {
        const uid = req.decodedToken.uid;

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
                    created_at,
                    updated_at
                FROM passengers
                WHERE firebase_uid = $1
                `,
                [uid]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger not found'
                });
            }

            return res.status(200).json({
                success: true,
                passenger: result.rows[0]
            });
        } catch (error) {
            console.error(
                '❌ Error fetching passenger profile:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while fetching profile'
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
    async (req, res) => {
        try {
            const {
                uid,
                email,
                displayName
            } = req.body;

            if (
                !uid ||
                uid !== req.decodedToken.uid
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        'UID mismatch or missing',
                    code: 'UID_MISMATCH'
                });
            }

            const phone =
                getVerifiedPhoneFromToken(
                    req.decodedToken
                );

            if (!phone) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Firebase token does not contain a verified phone number.',
                    code: 'PHONE_NOT_VERIFIED'
                });
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
                return res.status(200).json({
                    success: true,
                    message:
                        'Passenger already exists',
                    passengerId:
                        existing.rows[0].id
                });
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
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    NOW()
                )
                RETURNING id
                `,
                [
                    uid,
                    displayName ||
                    req.decodedToken.name ||
                    'Passenger',
                    phone,
                    email ||
                    req.decodedToken.email ||
                    null
                ]
            );

            return res.status(201).json({
                success: true,
                message:
                    'Passenger created successfully',
                passengerId:
                    result.rows[0].id
            });
        } catch (error) {
            console.error(
                '❌ Error creating passenger:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while creating passenger'
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
 * Phone number MUST come from the
 * verified Firebase token.
 *
 * Phone number from req.body is NOT trusted.
 */

router.post(
    '/register',
    verifyFirebaseToken,
    async (req, res) => {
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
                privacyEnabled
            } = req.body;

            // ------------------------------------------------
            // REQUIRED FIELDS
            // ------------------------------------------------

            if (!uid || !fullName) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Missing required fields: uid, fullName',
                    code: 'REQUIRED_FIELDS_MISSING'
                });
            }

            // ------------------------------------------------
            // VERIFY UID
            // ------------------------------------------------

            if (
                uid !== req.decodedToken.uid
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        'UID in request does not match authenticated user.',
                    code: 'UID_MISMATCH'
                });
            }

            // ------------------------------------------------
            // GET VERIFIED FIREBASE PHONE
            // ------------------------------------------------

            const phone =
                getVerifiedPhoneFromToken(
                    req.decodedToken
                );

            if (!phone) {
                return res.status(403).json({
                    success: false,
                    message:
                        'Phone number has not been verified via Firebase Phone Auth.',
                    code: 'PHONE_NOT_VERIFIED'
                });
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
                [
                    uid,
                    phone
                ]
            );

            if (existing.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    message:
                        'An account with this UID or phone already exists. Please log in.',
                    code: 'PASSENGER_ALREADY_EXISTS',
                    existingId:
                        existing.rows[0].id
                });
            }

            // ------------------------------------------------
            // SAVED LOCATIONS
            // ------------------------------------------------

            const locations =
                Array.isArray(savedLocations)
                    ? savedLocations
                    : [];

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
                    created_at
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
                    NOW()
                )
                RETURNING id
                `,
                [
                    uid,
                    fullName,
                    phone,
                    email ||
                    req.decodedToken.email ||
                    null,
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
                    privacyEnabled ?? true
                ]
            );

            return res.status(201).json({
                success: true,
                message:
                    'Passenger registered successfully',
                passengerId:
                    result.rows[0].id,
                phoneNumber: phone
            });
        } catch (error) {
            console.error(
                '❌ Passenger registration error:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Registration failed due to a server error.',
                code: 'DB_INSERT_FAILED'
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
    async (req, res) => {
        const uid = req.decodedToken.uid;

        try {
            const passengerResult =
                await pool.query(
                    `
                    SELECT id
                    FROM passengers
                    WHERE firebase_uid = $1
                    `,
                    [uid]
                );

            if (
                passengerResult.rows.length === 0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger not found. Please complete registration first.'
                });
            }

            const passengerId =
                passengerResult.rows[0].id;

            const walletResult =
                await pool.query(
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

            if (
                walletResult.rows.length === 0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Wallet not found. Please create one.'
                });
            }

            return res.status(200).json({
                success: true,
                wallet:
                    walletResult.rows[0]
            });
        } catch (error) {
            console.error(
                '❌ Error fetching wallet:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while fetching wallet'
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
    async (req, res) => {
        const uid = req.decodedToken.uid;

        const {
            full_name,
            email
        } = req.body;

        try {
            let passengerId;

            // ------------------------------------------------
            // FIND PASSENGER
            // ------------------------------------------------

            const existingPassenger =
                await pool.query(
                    `
                    SELECT id
                    FROM passengers
                    WHERE firebase_uid = $1
                    `,
                    [uid]
                );

            if (
                existingPassenger.rows.length === 0
            ) {
                const phoneNumber =
                    getVerifiedPhoneFromToken(
                        req.decodedToken
                    );

                if (!phoneNumber) {
                    return res.status(400).json({
                        success: false,
                        message:
                            'Firebase account does not have a verified phone number.',
                        code: 'PHONE_NOT_VERIFIED'
                    });
                }

                const displayName =
                    full_name ||
                    req.decodedToken.name ||
                    'Passenger';

                const emailAddress =
                    email ||
                    req.decodedToken.email ||
                    null;

                const insertPassenger =
                    await pool.query(
                        `
                        INSERT INTO passengers (
                            firebase_uid,
                            full_name,
                            email,
                            phone,
                            created_at
                        )
                        VALUES (
                            $1,
                            $2,
                            $3,
                            $4,
                            NOW()
                        )
                        RETURNING id
                        `,
                        [
                            uid,
                            displayName,
                            emailAddress,
                            phoneNumber
                        ]
                    );

                passengerId =
                    insertPassenger.rows[0].id;
            } else {
                passengerId =
                    existingPassenger.rows[0].id;
            }

            // ------------------------------------------------
            // CHECK EXISTING WALLET
            // ------------------------------------------------

            const existingWallet =
                await pool.query(
                    `
                    SELECT id
                    FROM wallets
                    WHERE passenger_id = $1
                    `,
                    [passengerId]
                );

            if (
                existingWallet.rows.length > 0
            ) {
                const wallet =
                    await pool.query(
                        `
                        SELECT *
                        FROM wallets
                        WHERE passenger_id = $1
                        `,
                        [passengerId]
                    );

                return res.status(200).json({
                    success: true,
                    message:
                        'Wallet already exists',
                    wallet:
                        wallet.rows[0]
                });
            }

            // ------------------------------------------------
            // CREATE WALLET
            // ------------------------------------------------

            const newWallet =
                await pool.query(
                    `
                    INSERT INTO wallets (
                        passenger_id,
                        balance,
                        pending_balance,
                        total_spent,
                        created_at
                    )
                    VALUES (
                        $1,
                        0,
                        0,
                        0,
                        NOW()
                    )
                    RETURNING *
                    `,
                    [passengerId]
                );

            return res.status(201).json({
                success: true,
                message:
                    'Wallet created successfully',
                wallet:
                    newWallet.rows[0]
            });
        } catch (error) {
            console.error(
                '❌ Error creating wallet:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while creating wallet'
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
    async (req, res) => {
        const uid = req.decodedToken.uid;

        try {
            // ------------------------------------------------
            // FIND PASSENGER
            // ------------------------------------------------

            const passengerResult =
                await pool.query(
                    `
                    SELECT id
                    FROM passengers
                    WHERE firebase_uid = $1
                    `,
                    [uid]
                );

            if (
                passengerResult.rows.length === 0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger not found'
                });
            }

            const passengerId =
                passengerResult.rows[0].id;

            // ------------------------------------------------
            // FIND WALLET
            // ------------------------------------------------

            const walletResult =
                await pool.query(
                    `
                    SELECT id
                    FROM wallets
                    WHERE passenger_id = $1
                    `,
                    [passengerId]
                );

            if (
                walletResult.rows.length === 0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Wallet not found'
                });
            }

            const walletId =
                walletResult.rows[0].id;

            // ------------------------------------------------
            // GET TRANSACTIONS
            // ------------------------------------------------

            const transactions =
                await pool.query(
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

            return res.status(200).json({
                success: true,
                transactions:
                    transactions.rows
            });
        } catch (error) {
            console.error(
                '❌ Error fetching transactions:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while fetching transactions'
            });
        }
    }
);

// ============================================================
// EXPORT
// ============================================================

module.exports = router;
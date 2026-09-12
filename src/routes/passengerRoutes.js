// routes/passengerRoutes.js
const express = require('express');
const router = express.Router();
const pool = require('../config/database');
const admin = require('firebase-admin');

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function normalizePhone(phone) {
    let value = String(phone || '').trim().replace(/[^0-9+]/g, '');

    if (value.startsWith('0')) value = '+233' + value.substring(1);
    else if (value.startsWith('233')) value = '+' + value;
    else if (/^\d{9}$/.test(value)) value = '+233' + value;

    if (!/^\+233\d{9}$/.test(value)) return null;
    return value;
}

/*
|--------------------------------------------------------------------------
| Middleware: verify Firebase ID token (no admin check)
|--------------------------------------------------------------------------
*/

const verifyFirebaseToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            message:
                'Missing or invalid Authorization header. Expected Bearer token.',
        });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.decodedToken = decodedToken;
        next();
    } catch (error) {
        console.error('Token verification failed:', error);
        return res.status(401).json({
            success: false,
            message: 'Invalid Firebase token.',
        });
    }
};

/*
|--------------------------------------------------------------------------
| Helper: extract verified phone from Firebase ID token
|--------------------------------------------------------------------------
*/

function getVerifiedPhoneFromToken(decodedToken) {
    if (!decodedToken || !decodedToken.phone_number) return null;
    return normalizePhone(decodedToken.phone_number);
}

// ============================================================
// PUBLIC FIREBASE PHONE AUTH ROUTES
// OTP sending / verification is handled entirely by Firebase
// Phone Authentication on the client. No Zavu. No server OTPs.
// ============================================================

/**
 * POST /api/passengers/check-phone
 *
 * Optional helper the client can call BEFORE starting Firebase Phone Auth,
 * so it can decide whether to run the "register" or "login" flow.
 * This does not send any OTP — Firebase does that on the client.
 */
router.post('/check-phone', async (req, res) => {
    try {
        const phone = normalizePhone(
            req.body?.phoneNumber || req.body?.phone,
        );
        const purpose = req.body?.purpose === 'login' ? 'login' : 'register';

        if (!phone) {
            return res.status(400).json({
                success: false,
                message: 'Enter a valid Ghana mobile number.',
                code: 'INVALID_PHONE',
            });
        }

        const existing = await pool.query(
            `SELECT id FROM passengers WHERE phone = $1 LIMIT 1`,
            [phone],
        );

        if (purpose === 'register' && existing.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message:
                    'This phone number is already registered. Please log in.',
                code: 'PHONE_ALREADY_REGISTERED',
            });
        }

        if (purpose === 'login' && existing.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'This phone number is not registered on Tegaara.',
                code: 'PASSENGER_NOT_FOUND',
            });
        }

        return res.status(200).json({
            success: true,
            phoneNumber: phone,
            exists: existing.rows.length > 0,
            purpose,
        });
    } catch (error) {
        console.error('❌ Check phone error:', error);
        return res.status(500).json({
            success: false,
            message: 'Unable to check phone number right now.',
            code: 'PHONE_CHECK_FAILED',
        });
    }
});

/**
 * POST /api/passengers/verify-phone
 *
 * Called AFTER the client has completed Firebase Phone Auth
 * (signInWithPhoneNumber -> confirm(code)). The client sends its
 * Firebase ID token. Backend verifies it and extracts the verified
 * phone_number from the decoded token.
 */
router.post('/verify-phone', verifyFirebaseToken, async (req, res) => {
    try {
        const decoded = req.decodedToken;
        const phoneFromToken = getVerifiedPhoneFromToken(decoded);

        if (!phoneFromToken) {
            return res.status(400).json({
                success: false,
                message:
                    'Firebase token does not contain a verified phone number.',
                code: 'PHONE_NOT_VERIFIED',
            });
        }

        const existing = await pool.query(
            `SELECT id, firebase_uid, full_name, phone, email
             FROM passengers
             WHERE firebase_uid = $1 OR phone = $2
             LIMIT 1`,
            [decoded.uid, phoneFromToken],
        );

        return res.status(200).json({
            success: true,
            verified: true,
            phoneNumber: phoneFromToken,
            firebaseUid: decoded.uid,
            isRegistered: existing.rows.length > 0,
            passenger: existing.rows[0] || null,
        });
    } catch (error) {
        console.error('❌ Verify phone error:', error);
        return res.status(500).json({
            success: false,
            message: 'Phone verification failed. Please try again.',
            code: 'PHONE_VERIFY_FAILED',
        });
    }
});

// ============================================================
// PROFILE
// ============================================================

router.get('/profile', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    try {
        const result = await pool.query(
            `SELECT 
                id, firebase_uid, full_name, phone, email, gender,
                emergency_contact_name, emergency_contact_phone, emergency_relationship,
                home_address, region, district, town_city,
                saved_locations, preferred_payment_method, mobile_money_number,
                language_preference, notification_enabled, privacy_enabled,
                created_at, updated_at
             FROM passengers
             WHERE firebase_uid = $1`,
            [uid],
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Passenger not found',
            });
        }

        res.json({
            success: true,
            passenger: result.rows[0],
        });
    } catch (error) {
        console.error('❌ Error fetching passenger profile:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching profile',
        });
    }
});

// ============================================================
// CREATE (used when no passenger exists yet)
// Uses the VERIFIED phone from the Firebase ID token, not the body.
// ============================================================

router.post('/create', verifyFirebaseToken, async (req, res) => {
    try {
        const { uid, email, displayName } = req.body;

        // Ensure the UID matches the authenticated user
        if (!uid || uid !== req.decodedToken.uid) {
            return res.status(403).json({
                success: false,
                message: 'UID mismatch or missing',
            });
        }

        // Trust only the verified phone from Firebase
        const phone = getVerifiedPhoneFromToken(req.decodedToken);
        if (!phone) {
            return res.status(400).json({
                success: false,
                message:
                    'Firebase token does not contain a verified phone number.',
                code: 'PHONE_NOT_VERIFIED',
            });
        }

        const existing = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1 OR phone = $2`,
            [uid, phone],
        );

        if (existing.rows.length > 0) {
            return res.status(200).json({
                success: true,
                message: 'Passenger already exists',
                passengerId: existing.rows[0].id,
            });
        }

        const result = await pool.query(
            `INSERT INTO passengers (
                firebase_uid, full_name, phone, email, created_at
            ) VALUES ($1, $2, $3, $4, NOW())
            RETURNING id`,
            [
                uid,
                displayName || req.decodedToken.name || 'Passenger',
                phone,
                email || req.decodedToken.email || null,
            ],
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
});

// ============================================================
// REGISTER (full registration)
// Phone is now taken from the verified Firebase ID token.
// The `phone_otps` check is gone.
// ============================================================

router.post('/register', verifyFirebaseToken, async (req, res) => {
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
        } = req.body;

        if (!uid || !fullName) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: uid, fullName',
            });
        }

        if (uid !== req.decodedToken.uid) {
            return res.status(403).json({
                success: false,
                message: 'UID in request does not match authenticated user.',
            });
        }

        // Firebase is the source of truth for the verified phone number.
        const phone = getVerifiedPhoneFromToken(req.decodedToken);
        if (!phone) {
            return res.status(403).json({
                success: false,
                message:
                    'Phone number has not been verified via Firebase Phone Auth.',
                code: 'PHONE_NOT_VERIFIED',
            });
        }

        const existing = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1 OR phone = $2`,
            [uid, phone],
        );

        if (existing.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message:
                    'An account with this UID or phone already exists. Please log in.',
                existingId: existing.rows[0].id,
            });
        }

        const locations = Array.isArray(savedLocations) ? savedLocations : [];

        const result = await pool.query(
            `
            INSERT INTO passengers (
                firebase_uid, full_name, phone, email, gender,
                emergency_contact_name, emergency_contact_phone, emergency_relationship,
                home_address, region, district, town_city,
                saved_locations, preferred_payment_method, mobile_money_number,
                language_preference, notification_enabled, privacy_enabled,
                created_at
            )
            VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9, $10,
                $11, $12, $13, $14, $15,
                $16, $17, $18,
                NOW()
            )
            RETURNING id
            `,
            [
                uid,
                fullName,
                phone,
                email || req.decodedToken.email || null,
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
            ],
        );

        res.status(201).json({
            success: true,
            message: 'Passenger registered successfully',
            passengerId: result.rows[0].id,
        });
    } catch (error) {
        console.error('❌ Passenger registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Registration failed due to a server error.',
            code: 'DB_INSERT_FAILED',
        });
    }
});

// ============================================================
// WALLET ROUTES (unchanged)
// ============================================================

/**
 * GET /api/passenger/wallet
 */
router.get('/wallet', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    try {
        const passengerResult = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1`,
            [uid],
        );
        if (passengerResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message:
                    'Passenger not found. Please complete registration first.',
            });
        }
        const passengerId = passengerResult.rows[0].id;

        const walletResult = await pool.query(
            `SELECT id, passenger_id, balance, pending_balance, total_spent, 
                    last_transaction_at, created_at, updated_at
             FROM wallets
             WHERE passenger_id = $1`,
            [passengerId],
        );
        if (walletResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Wallet not found. Please create one.',
            });
        }
        res.json({
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
});

/**
 * POST /api/passenger/wallet
 */
router.post('/wallet', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    const { full_name, email, phone } = req.body;

    try {
        let passengerId;
        const existingPassenger = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1`,
            [uid],
        );

        if (existingPassenger.rows.length === 0) {
            const displayName =
                full_name || req.decodedToken.name || 'Passenger';
            const emailAddress =
                email || req.decodedToken.email || null;
            const phoneNumber =
                phone || getVerifiedPhoneFromToken(req.decodedToken) || null;

            const insertPassenger = await pool.query(
                `INSERT INTO passengers (firebase_uid, full_name, email, phone, created_at)
                 VALUES ($1, $2, $3, $4, NOW())
                 RETURNING id`,
                [uid, displayName, emailAddress, phoneNumber],
            );
            passengerId = insertPassenger.rows[0].id;
        } else {
            passengerId = existingPassenger.rows[0].id;
        }

        const existingWallet = await pool.query(
            `SELECT id FROM wallets WHERE passenger_id = $1`,
            [passengerId],
        );
        if (existingWallet.rows.length > 0) {
            const wallet = await pool.query(
                `SELECT * FROM wallets WHERE passenger_id = $1`,
                [passengerId],
            );
            return res.status(200).json({
                success: true,
                message: 'Wallet already exists',
                wallet: wallet.rows[0],
            });
        }

        const newWallet = await pool.query(
            `INSERT INTO wallets (passenger_id, balance, pending_balance, total_spent, created_at)
             VALUES ($1, 0, 0, 0, NOW())
             RETURNING *`,
            [passengerId],
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
});

/**
 * GET /api/passenger/wallet/transactions
 */
router.get(
    '/wallet/transactions',
    verifyFirebaseToken,
    async (req, res) => {
        const uid = req.decodedToken.uid;
        try {
            const passengerResult = await pool.query(
                `SELECT id FROM passengers WHERE firebase_uid = $1`,
                [uid],
            );
            if (passengerResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger not found',
                });
            }
            const passengerId = passengerResult.rows[0].id;

            const walletResult = await pool.query(
                `SELECT id FROM wallets WHERE passenger_id = $1`,
                [passengerId],
            );
            if (walletResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Wallet not found',
                });
            }
            const walletId = walletResult.rows[0].id;

            const transactions = await pool.query(
                `SELECT id, wallet_id, type, amount, balance_before, balance_after,
                        status, payment_method, provider, ride_id, description,
                        created_at
                 FROM transactions
                 WHERE wallet_id = $1
                 ORDER BY created_at DESC
                 LIMIT 50`,
                [walletId],
            );

            res.json({
                success: true,
                transactions: transactions.rows,
            });
        } catch (error) {
            console.error('❌ Error fetching transactions:', error);
            res.status(500).json({
                success: false,
                message: 'Server error while fetching transactions',
            });
        }
    },
);

module.exports = router;
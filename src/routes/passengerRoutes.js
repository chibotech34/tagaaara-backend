// routes/passengerRoutes.js
const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const pool = require('../config/database');
const admin = require('firebase-admin');

const ZAVU_API_URL = 'https://api.zavu.dev/v1/messages';
const OTP_EXPIRY_MINUTES = 5;
const OTP_RESEND_SECONDS = 60;
const MAX_OTP_ATTEMPTS = 5;

function normalizePhone(phone) {
    let value = String(phone || '').trim().replace(/[^0-9+]/g, '');

    if (value.startsWith('0')) value = '+233' + value.substring(1);
    else if (value.startsWith('233')) value = '+' + value;
    else if (/^\d{9}$/.test(value)) value = '+233' + value;

    if (!/^\+233\d{9}$/.test(value)) return null;
    return value;
}

function hashOtp(otp) {
    return crypto.createHash('sha256').update(String(otp)).digest('hex');
}

function generateOtp() {
    return crypto.randomInt(100000, 1000000).toString();
}

async function sendZavuSms(to, text) {
    const apiKey = process.env.ZAVU_API_KEY;
    if (!apiKey) throw new Error('ZAVU_API_KEY is not configured.');

    const headers = {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    };

    if (process.env.ZAVU_SENDER_ID) {
        headers['Zavu-Sender'] = process.env.ZAVU_SENDER_ID;
    }

    const response = await fetch(ZAVU_API_URL, {
        method: 'POST',
        headers,
        body: JSON.stringify({
            to,
            channel: 'sms',
            messageType: 'text',
            text,
        }),
    });

    const bodyText = await response.text();
    let body;
    try {
        body = JSON.parse(bodyText);
    } catch (_) {
        body = { raw: bodyText };
    }

    if (!response.ok) {
        console.error('❌ Zavu API error:', response.status, body);
        const error = new Error(body?.message || body?.error || `Zavu returned HTTP ${response.status}`);
        error.status = response.status;
        throw error;
    }

    return body;
}

// ============================================================
// PUBLIC ZAVU OTP ROUTES
// These routes do NOT use Firebase authentication.
// ============================================================

router.post('/send-otp', async (req, res) => {
    try {
        const phone = normalizePhone(req.body?.phoneNumber || req.body?.phone);
        const purpose = req.body?.purpose === 'login' ? 'login' : 'register';

        if (!phone) {
            return res.status(400).json({
                success: false,
                message: 'Enter a valid Ghana mobile number.',
                code: 'INVALID_PHONE',
            });
        }

        // Registration must not start for an existing number.
        const existing = await pool.query(
            `SELECT id, firebase_uid FROM passengers WHERE phone = $1 LIMIT 1`,
            [phone],
        );

        if (purpose === 'register' && existing.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'This phone number is already registered. Please log in.',
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

        // Anti-spam: one OTP per number/purpose every 60 seconds.
        const recent = await pool.query(
            `SELECT created_at
             FROM phone_otps
             WHERE phone_number = $1 AND purpose = $2
             ORDER BY created_at DESC
             LIMIT 1`,
            [phone, purpose],
        );

        if (recent.rows.length > 0) {
            const ageSeconds = (Date.now() - new Date(recent.rows[0].created_at).getTime()) / 1000;
            if (ageSeconds < OTP_RESEND_SECONDS) {
                const retryAfter = Math.ceil(OTP_RESEND_SECONDS - ageSeconds);
                return res.status(429).json({
                    success: false,
                    message: `Please wait ${retryAfter} seconds before requesting another OTP.`,
                    retryAfter,
                    code: 'OTP_RATE_LIMITED',
                });
            }
        }

        const otp = generateOtp();
        const otpHash = hashOtp(otp);
        const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

        await pool.query(
            `DELETE FROM phone_otps WHERE phone_number = $1 AND purpose = $2 AND verified_at IS NULL`,
            [phone, purpose],
        );

        await pool.query(
            `INSERT INTO phone_otps
                (phone_number, purpose, otp_hash, expires_at, attempts, created_at)
             VALUES ($1, $2, $3, $4, 0, NOW())`,
            [phone, purpose, otpHash, expiresAt],
        );

        await sendZavuSms(
            phone,
            `TEGAARA: Your verification code is ${otp}. It expires in 5 minutes. Do not share this code.`,
        );

        return res.status(200).json({
            success: true,
            message: 'OTP sent successfully.',
            phoneNumber: phone,
            expiresIn: OTP_EXPIRY_MINUTES * 60,
        });
    } catch (error) {
        console.error('❌ SEND ZAVU OTP ERROR:', error);
        return res.status(error.status || 500).json({
            success: false,
            message: error.status === 402
                ? 'Tegaara SMS service has insufficient balance.'
                : 'Unable to send OTP right now. Please try again.',
            code: 'OTP_SEND_FAILED',
        });
    }
});

router.post('/verify-otp', async (req, res) => {
    try {
        const phone = normalizePhone(req.body?.phoneNumber || req.body?.phone);
        const otp = String(req.body?.otp || '').trim();
        const purpose = req.body?.purpose === 'login' ? 'login' : 'register';

        if (!phone || !/^\d{6}$/.test(otp)) {
            return res.status(400).json({
                success: false,
                message: 'Phone number and a 6-digit OTP are required.',
                code: 'INVALID_OTP_REQUEST',
            });
        }

        const result = await pool.query(
            `SELECT * FROM phone_otps
             WHERE phone_number = $1 AND purpose = $2 AND verified_at IS NULL
             ORDER BY created_at DESC
             LIMIT 1`,
            [phone, purpose],
        );

        if (result.rows.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'OTP not found. Please request a new code.',
                code: 'OTP_NOT_FOUND',
            });
        }

        const record = result.rows[0];

        if (record.attempts >= MAX_OTP_ATTEMPTS) {
            return res.status(429).json({
                success: false,
                message: 'Too many incorrect OTP attempts. Request a new code.',
                code: 'OTP_ATTEMPTS_EXCEEDED',
            });
        }

        if (new Date(record.expires_at).getTime() < Date.now()) {
            return res.status(400).json({
                success: false,
                message: 'OTP has expired. Please request a new code.',
                code: 'OTP_EXPIRED',
            });
        }

        const suppliedHash = hashOtp(otp);
        if (suppliedHash !== record.otp_hash) {
            await pool.query(
                `UPDATE phone_otps SET attempts = attempts + 1 WHERE id = $1`,
                [record.id],
            );

            return res.status(400).json({
                success: false,
                message: 'Incorrect OTP. Please check the code and try again.',
                code: 'OTP_INVALID',
            });
        }

        await pool.query(
            `UPDATE phone_otps SET verified_at = NOW() WHERE id = $1`,
            [record.id],
        );

        // Login flow: convert the verified phone number into a Firebase custom token.
        if (purpose === 'login') {
            const passenger = await pool.query(
                `SELECT id, firebase_uid, full_name, phone, email
                 FROM passengers
                 WHERE phone = $1
                 LIMIT 1`,
                [phone],
            );

            if (passenger.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger account was not found.',
                    code: 'PASSENGER_NOT_FOUND',
                });
            }

            const row = passenger.rows[0];
            const customToken = await admin.auth().createCustomToken(row.firebase_uid, {
                role: 'passenger',
                phone,
            });

            return res.status(200).json({
                success: true,
                verified: true,
                customToken,
                passenger: row,
            });
        }

        return res.status(200).json({
            success: true,
            verified: true,
            phoneNumber: phone,
        });
    } catch (error) {
        console.error('❌ VERIFY ZAVU OTP ERROR:', error);
        return res.status(500).json({
            success: false,
            message: 'OTP verification failed. Please try again.',
            code: 'OTP_VERIFY_FAILED',
        });
    }
});

// ------------------------------------------------------------
// Middleware: verify Firebase ID token (no admin check)
// ------------------------------------------------------------
const verifyFirebaseToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            message: 'Missing or invalid Authorization header. Expected Bearer token.'
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

// ------------------------------------------------------------
// GET /api/passenger/profile
// ------------------------------------------------------------
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
            [uid]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Passenger not found'
            });
        }

        res.json({
            success: true,
            passenger: result.rows[0]
        });
    } catch (error) {
        console.error('❌ Error fetching passenger profile:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching profile'
        });
    }
});

// ------------------------------------------------------------
// POST /api/passenger/create
// (Used when no passenger exists yet; creates a new record)
// ------------------------------------------------------------
router.post('/create', verifyFirebaseToken, async (req, res) => {
    try {
        const {
            uid,
            email,
            phone,
            displayName,
            // optional extra fields can be added later
        } = req.body;

        // Ensure the UID matches the authenticated user
        if (!uid || uid !== req.decodedToken.uid) {
            return res.status(403).json({
                success: false,
                message: 'UID mismatch or missing'
            });
        }

        // Check if passenger already exists (by firebase_uid or phone)
        const existing = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1 OR phone = $2`,
            [uid, phone]
        );
        if (existing.rows.length > 0) {
            // If already exists, just return success (frontend can treat as logged in)
            return res.status(200).json({
                success: true,
                message: 'Passenger already exists',
                passengerId: existing.rows[0].id
            });
        }

        // Insert new passenger
        const result = await pool.query(
            `INSERT INTO passengers (
                firebase_uid, full_name, phone, email, created_at
            ) VALUES ($1, $2, $3, $4, NOW())
            RETURNING id`,
            [
                uid,
                displayName || 'Passenger',
                phone,
                email || null
            ]
        );

        res.status(201).json({
            success: true,
            message: 'Passenger created successfully',
            passengerId: result.rows[0].id
        });

    } catch (error) {
        console.error('❌ Error creating passenger:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while creating passenger'
        });
    }
});

// ------------------------------------------------------------
// POST /api/passenger/register (full registration – kept for compatibility)
// ------------------------------------------------------------
router.post('/register', verifyFirebaseToken, async (req, res) => {
    try {
        const {
            uid,
            fullName,
            phone,
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

        if (!uid || !fullName || !phone) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: uid, fullName, phone'
            });
        }

        if (uid !== req.decodedToken.uid) {
            return res.status(403).json({
                success: false,
                message: 'UID in request does not match authenticated user.'
            });
        }

        const existing = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1 OR phone = $2`,
            [uid, phone]
        );

        if (existing.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'An account with this UID or phone already exists. Please log in.',
                existingId: existing.rows[0].id
            });
        }

        // Registration is allowed only after a successful Zavu OTP verification.
        const verification = await pool.query(
            `SELECT id
             FROM phone_otps
             WHERE phone_number = $1
               AND purpose = 'register'
               AND verified_at IS NOT NULL
               AND verified_at >= NOW() - INTERVAL '10 minutes'
             ORDER BY verified_at DESC
             LIMIT 1`,
            [phone]
        );

        if (verification.rows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Phone number has not been verified. Please verify the OTP first.',
                code: 'PHONE_NOT_VERIFIED'
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
                email || null,
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

        await pool.query(
            `UPDATE phone_otps
             SET consumed_at = NOW()
             WHERE phone_number = $1
               AND purpose = 'register'
               AND verified_at IS NOT NULL
               AND consumed_at IS NULL`,
            [phone]
        );

        res.status(201).json({
            success: true,
            message: 'Passenger registered successfully',
            passengerId: result.rows[0].id
        });

    } catch (error) {
        console.error('❌ Passenger registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Registration failed due to a server error.',
            code: 'DB_INSERT_FAILED'
        });
    }
});

// ============================================================
// WALLET ROUTES (NEW)
// ============================================================

/**
 * GET /api/passenger/wallet
 * Get the current passenger's wallet
 */
router.get('/wallet', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    try {
        const passengerResult = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1`,
            [uid]
        );
        if (passengerResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Passenger not found. Please complete registration first.'
            });
        }
        const passengerId = passengerResult.rows[0].id;

        const walletResult = await pool.query(
            `SELECT id, passenger_id, balance, pending_balance, total_spent, 
                    last_transaction_at, created_at, updated_at
             FROM wallets
             WHERE passenger_id = $1`,
            [passengerId]
        );
        if (walletResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Wallet not found. Please create one.'
            });
        }
        res.json({
            success: true,
            wallet: walletResult.rows[0]
        });
    } catch (error) {
        console.error('❌ Error fetching wallet:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching wallet'
        });
    }
});

/**
 * POST /api/passenger/wallet
 * Create a wallet for the passenger (if one doesn't exist)
 */
router.post('/wallet', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    const { full_name, email, phone } = req.body;

    try {
        // 1. Ensure passenger exists
        let passengerId;
        const existingPassenger = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1`,
            [uid]
        );
        if (existingPassenger.rows.length === 0) {
            const displayName = full_name || req.decodedToken.name || 'Passenger';
            const emailAddress = email || req.decodedToken.email || null;
            const phoneNumber = phone || null;

            const insertPassenger = await pool.query(
                `INSERT INTO passengers (firebase_uid, full_name, email, phone, created_at)
                 VALUES ($1, $2, $3, $4, NOW())
                 RETURNING id`,
                [uid, displayName, emailAddress, phoneNumber]
            );
            passengerId = insertPassenger.rows[0].id;
        } else {
            passengerId = existingPassenger.rows[0].id;
        }

        // 2. Check if wallet already exists
        const existingWallet = await pool.query(
            `SELECT id FROM wallets WHERE passenger_id = $1`,
            [passengerId]
        );
        if (existingWallet.rows.length > 0) {
            const wallet = await pool.query(
                `SELECT * FROM wallets WHERE passenger_id = $1`,
                [passengerId]
            );
            return res.status(200).json({
                success: true,
                message: 'Wallet already exists',
                wallet: wallet.rows[0]
            });
        }

        // 3. Create new wallet with zero balance
        const newWallet = await pool.query(
            `INSERT INTO wallets (passenger_id, balance, pending_balance, total_spent, created_at)
             VALUES ($1, 0, 0, 0, NOW())
             RETURNING *`,
            [passengerId]
        );

        res.status(201).json({
            success: true,
            message: 'Wallet created successfully',
            wallet: newWallet.rows[0]
        });
    } catch (error) {
        console.error('❌ Error creating wallet:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while creating wallet'
        });
    }
});

/**
 * GET /api/passenger/wallet/transactions
 * Get transaction history for the passenger's wallet
 */
router.get('/wallet/transactions', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    try {
        const passengerResult = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1`,
            [uid]
        );
        if (passengerResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Passenger not found'
            });
        }
        const passengerId = passengerResult.rows[0].id;

        const walletResult = await pool.query(
            `SELECT id FROM wallets WHERE passenger_id = $1`,
            [passengerId]
        );
        if (walletResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Wallet not found'
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
            [walletId]
        );

        res.json({
            success: true,
            transactions: transactions.rows
        });
    } catch (error) {
        console.error('❌ Error fetching transactions:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching transactions'
        });
    }
});

module.exports = router;
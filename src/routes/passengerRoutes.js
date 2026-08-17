// routes/passengerRoutes.js
const express = require('express');
const router = express.Router();
// 🔥 Import the default export from database.ts correctly
const pool = require('../config/database').default;
const { getAuth } = require('firebase-admin/auth');

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
        const decodedToken = await getAuth().verifyIdToken(token);
        req.decodedToken = decodedToken;
        next();
    } catch (error) {
        console.error('Token verification failed:', error);
        return res.status(401).json({
            success: false,
            message: 'Invalid Firebase token.',
            details: error.message
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
// ------------------------------------------------------------
router.post('/create', verifyFirebaseToken, async (req, res) => {
    try {
        const {
            uid,
            email,
            phone,
            displayName,
        } = req.body;

        if (!uid || uid !== req.decodedToken.uid) {
            return res.status(403).json({
                success: false,
                message: 'UID mismatch or missing'
            });
        }

        const existing = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1 OR phone = $2`,
            [uid, phone]
        );
        if (existing.rows.length > 0) {
            return res.status(200).json({
                success: true,
                message: 'Passenger already exists',
                passengerId: existing.rows[0].id
            });
        }

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
// POST /api/passenger/register (full registration)
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
// WALLET ROUTES
// ============================================================

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

router.post('/wallet', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    const { full_name, email, phone } = req.body;

    try {
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
    // ============================================================
    // ALERTS ROUTES
    // ============================================================

    // GET /api/passenger/alerts
    router.get('/alerts', verifyFirebaseToken, async (req, res) => {
        const uid = req.decodedToken.uid;
        try {
            // Query alerts for this passenger from your alerts table.
            // Adapt the column names to match your actual schema.
            const result = await pool.query(
                `SELECT 
                id,
                title,
                description,
                created_at AS timestamp,
                is_read AS "isRead",
                priority,
                category,
                target_screen AS "targetScreen",
                metadata
             FROM alerts
             WHERE passenger_uid = $1
             ORDER BY created_at DESC`,
                [uid]
            );

            res.status(200).json({
                success: true,
                alerts: result.rows
            });
        } catch (error) {
            console.error('❌ Error fetching passenger alerts:', error);
            res.status(500).json({
                success: false,
                message: 'Server error while fetching alerts'
            });
        }
    });

    // POST /api/passenger/alerts/:id/read
    router.patch('/alerts/:id/read', verifyFirebaseToken, async (req, res) => {
        const uid = req.decodedToken.uid;
        const alertId = req.params.id;
        try {
            // Only mark as read if this alert belongs to this passenger
            const result = await pool.query(
                `UPDATE alerts
             SET is_read = TRUE
             WHERE id = $1 AND passenger_uid = $2
             RETURNING id`,
                [alertId, uid]
            );
            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Alert not found or not owned by this user'
                });
            }
            res.status(200).json({ success: true });
        } catch (error) {
            console.error('❌ Error marking alert as read:', error);
            res.status(500).json({
                success: false,
                message: 'Server error'
            });
        }
    });

    // POST /api/passenger/alerts/read-all
    router.patch('/alerts/read-all', verifyFirebaseToken, async (req, res) => {
        const uid = req.decodedToken.uid;
        try {
            await pool.query(
                `UPDATE alerts
             SET is_read = TRUE
             WHERE passenger_uid = $1 AND is_read = FALSE`,
                [uid]
            );
            res.status(200).json({ success: true });
        } catch (error) {
            console.error('❌ Error marking all alerts as read:', error);
            res.status(500).json({
                success: false,
                message: 'Server error'
            });
        }
    });

    // DELETE /api/passenger/alerts/:id
    router.delete('/alerts/:id', verifyFirebaseToken, async (req, res) => {
        const uid = req.decodedToken.uid;
        const alertId = req.params.id;
        try {
            const result = await pool.query(
                `DELETE FROM alerts
             WHERE id = $1 AND passenger_uid = $2
             RETURNING id`,
                [alertId, uid]
            );
            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Alert not found or not owned by this user'
                });
            }
            res.status(200).json({ success: true });
        } catch (error) {
            console.error('❌ Error deleting alert:', error);
            res.status(500).json({
                success: false,
                message: 'Server error'
            });
        }
    });
});

module.exports = router;
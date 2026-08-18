// routes/passengerRoutes.js

const express = require('express');
const router = express.Router();

const pool = require('../config/database').default;
const { getAuth } = require('firebase-admin/auth');

// ============================================================
// FIREBASE AUTHENTICATION MIDDLEWARE
// ============================================================

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
        console.log('✅ Firebase user authenticated:', decodedToken.uid);
        next();
    } catch (error) {
        console.error('❌ Firebase token verification failed:', error);
        return res.status(401).json({
            success: false,
            message: 'Invalid Firebase token.',
            details: error.message
        });
    }
};

// ============================================================
// PROFILE (GET & PATCH)
// ============================================================

// GET /api/passengers/profile
router.get('/profile', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;

    try {
        const result = await pool.query(
            `SELECT
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
             WHERE firebase_uid = $1`,
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
        console.error('❌ Error fetching passenger profile:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while fetching profile'
        });
    }
});

// PATCH /api/passengers/profile
router.patch('/profile', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    const updates = req.body;

    // Allowed fields that can be updated (whitelist)
    const allowedFields = [
        'full_name', 'phone', 'email', 'gender',
        'emergency_contact_name', 'emergency_contact_phone', 'emergency_relationship',
        'home_address', 'region', 'district', 'town_city',
        'saved_locations', 'preferred_payment_method', 'mobile_money_number',
        'language_preference', 'notification_enabled', 'privacy_enabled'
    ];

    // Build dynamic SET clause
    const setClauses = [];
    const values = [];
    let paramIndex = 1;

    for (const field of allowedFields) {
        if (updates.hasOwnProperty(field)) {
            // Handle JSONB field separately
            if (field === 'saved_locations') {
                // Ensure it's a valid JSON array
                const locations = Array.isArray(updates[field]) ? updates[field] : [];
                setClauses.push(`saved_locations = $${paramIndex}::jsonb`);
                values.push(JSON.stringify(locations));
            } else {
                setClauses.push(`${field} = $${paramIndex}`);
                values.push(updates[field]);
            }
            paramIndex++;
        }
    }

    if (setClauses.length === 0) {
        return res.status(400).json({
            success: false,
            message: 'No valid fields provided to update'
        });
    }

    // Add updated_at
    setClauses.push(`updated_at = NOW()`);

    const query = `
        UPDATE passengers
        SET ${setClauses.join(', ')}
        WHERE firebase_uid = $${paramIndex}
        RETURNING *
    `;
    values.push(uid);

    try {
        const result = await pool.query(query, values);

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
        console.error('❌ Error updating passenger profile:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while updating profile'
        });
    }
});

// ============================================================
// CREATE PASSENGER (used for initial creation)
// ============================================================

// POST /api/passengers/create
router.post('/create', verifyFirebaseToken, async (req, res) => {
    try {
        const { uid, email, phone, displayName } = req.body;

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
                firebase_uid,
                full_name,
                phone,
                email,
                created_at
             )
             VALUES ($1, $2, $3, $4, NOW())
             RETURNING id`,
            [uid, displayName || 'Passenger', phone, email || null]
        );

        return res.status(201).json({
            success: true,
            message: 'Passenger created successfully',
            passengerId: result.rows[0].id
        });

    } catch (error) {
        console.error('❌ Error creating passenger:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while creating passenger'
        });
    }
});

// ============================================================
// FULL REGISTRATION (extended details)
// ============================================================

// POST /api/passengers/register
router.post('/register', verifyFirebaseToken, async (req, res) => {
    try {
        const {
            uid, fullName, phone, email, gender,
            emergencyContactName, emergencyContactPhone, emergencyRelationship,
            homeAddress, region, district, townCity,
            savedLocations, preferredPaymentMethod, mobileMoneyNumber,
            languagePreference, notificationEnabled, privacyEnabled
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
            `INSERT INTO passengers (
                firebase_uid, full_name, phone, email, gender,
                emergency_contact_name, emergency_contact_phone, emergency_relationship,
                home_address, region, district, town_city,
                saved_locations, preferred_payment_method, mobile_money_number,
                language_preference, notification_enabled, privacy_enabled,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, NOW())
            RETURNING id`,
            [
                uid, fullName, phone, email || null, gender || null,
                emergencyContactName || null, emergencyContactPhone || null, emergencyRelationship || null,
                homeAddress || null, region || null, district || null, townCity || null,
                JSON.stringify(locations), preferredPaymentMethod || null, mobileMoneyNumber || null,
                languagePreference || null, notificationEnabled ?? true, privacyEnabled ?? true
            ]
        );

        return res.status(201).json({
            success: true,
            message: 'Passenger registered successfully',
            passengerId: result.rows[0].id
        });

    } catch (error) {
        console.error('❌ Passenger registration error:', error);
        return res.status(500).json({
            success: false,
            message: 'Registration failed due to a server error.',
            code: 'DB_INSERT_FAILED'
        });
    }
});

// ============================================================
// WALLET (GET and POST)
// ============================================================

// GET /api/passengers/wallet
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
            `SELECT
                id, passenger_id, balance, pending_balance,
                total_spent, last_transaction_at, created_at, updated_at
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

        return res.status(200).json({
            success: true,
            wallet: walletResult.rows[0]
        });

    } catch (error) {
        console.error('❌ Error fetching wallet:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while fetching wallet'
        });
    }
});

// POST /api/passengers/wallet (create wallet if not exists)
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

        return res.status(201).json({
            success: true,
            message: 'Wallet created successfully',
            wallet: newWallet.rows[0]
        });

    } catch (error) {
        console.error('❌ Error creating wallet:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while creating wallet'
        });
    }
});

// ============================================================
// TRANSACTIONS (GET)
// ============================================================

// GET /api/passengers/transactions
router.get('/transactions', verifyFirebaseToken, async (req, res) => {
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

        // Optional limit from query param
        const limit = parseInt(req.query.limit) || 50;

        const transactions = await pool.query(
            `SELECT
                id, wallet_id, type, amount,
                balance_before, balance_after, status,
                payment_method, provider, ride_id,
                description, created_at
             FROM transactions
             WHERE wallet_id = $1
             ORDER BY created_at DESC
             LIMIT $2`,
            [walletId, limit]
        );

        return res.status(200).json({
            success: true,
            transactions: transactions.rows
        });

    } catch (error) {
        console.error('❌ Error fetching transactions:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while fetching transactions'
        });
    }
});

// ============================================================
// RIDE HISTORY (GET)
// ============================================================

// GET /api/passengers/rides
router.get('/rides', verifyFirebaseToken, async (req, res) => {
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

        const limit = parseInt(req.query.limit) || 20;

        const rides = await pool.query(
            `SELECT
                id, passenger_id, driver_id, pickup_location,
                dropoff_location, status, fare, distance,
                started_at, completed_at, created_at
             FROM rides
             WHERE passenger_id = $1
             ORDER BY created_at DESC
             LIMIT $2`,
            [passengerId, limit]
        );

        // Return an array (even if empty)
        return res.status(200).json({
            success: true,
            rides: rides.rows
        });

    } catch (error) {
        console.error('❌ Error fetching ride history:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while fetching ride history'
        });
    }
});

// ============================================================
// DELETE ACCOUNT
// ============================================================

// DELETE /api/passengers/account
router.delete('/account', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;

    try {
        // Delete passenger; cascade will remove wallet, rides, transactions if foreign keys have ON DELETE CASCADE
        // If not, you may need to delete related records manually.
        const result = await pool.query(
            `DELETE FROM passengers WHERE firebase_uid = $1 RETURNING id`,
            [uid]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Passenger not found'
            });
        }

        // Optional: delete Firebase user as well? Usually you'd let the user re-authenticate.
        // We'll just delete from our DB.

        return res.status(204).send(); // No content

    } catch (error) {
        console.error('❌ Error deleting account:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while deleting account'
        });
    }
});

// ============================================================
// ALERTS (as originally defined)
// ============================================================

// GET /api/passengers/alerts
router.get('/alerts', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    console.log('🔔 Loading alerts for Firebase UID:', uid);

    try {
        const result = await pool.query(
            `SELECT
                id, title, body AS description,
                created_at AS timestamp, is_read AS "isRead",
                priority, category, target_screen AS "targetScreen",
                metadata
             FROM alerts
             WHERE user_id = $1
             ORDER BY created_at DESC`,
            [uid]
        );

        console.log(`🔔 Found ${result.rows.length} alerts for ${uid}`);
        return res.status(200).json({
            success: true,
            alerts: result.rows
        });

    } catch (error) {
        console.error('❌ Error fetching passenger alerts:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while fetching alerts',
            details: error.message
        });
    }
});

// PATCH /api/passengers/alerts/:id/read
router.patch('/alerts/:id/read', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    const alertId = req.params.id;

    try {
        const result = await pool.query(
            `UPDATE alerts
             SET is_read = TRUE
             WHERE id = $1 AND user_id = $2
             RETURNING id`,
            [alertId, uid]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Alert not found or not owned by this user'
            });
        }

        return res.status(200).json({
            success: true,
            message: 'Alert marked as read'
        });

    } catch (error) {
        console.error('❌ Error marking alert as read:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error',
            details: error.message
        });
    }
});

// PATCH /api/passengers/alerts/read-all
router.patch('/alerts/read-all', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;

    try {
        const result = await pool.query(
            `UPDATE alerts
             SET is_read = TRUE
             WHERE user_id = $1 AND is_read = FALSE`,
            [uid]
        );

        return res.status(200).json({
            success: true,
            message: 'All alerts marked as read',
            updatedCount: result.rowCount
        });

    } catch (error) {
        console.error('❌ Error marking all alerts as read:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error',
            details: error.message
        });
    }
});

// DELETE /api/passengers/alerts/:id
router.delete('/alerts/:id', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    const alertId = req.params.id;

    try {
        const result = await pool.query(
            `DELETE FROM alerts
             WHERE id = $1 AND user_id = $2
             RETURNING id`,
            [alertId, uid]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Alert not found or not owned by this user'
            });
        }

        return res.status(200).json({
            success: true,
            message: 'Alert deleted'
        });

    } catch (error) {
        console.error('❌ Error deleting alert:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error',
            details: error.message
        });
    }
});

// DELETE /api/passengers/alerts
router.delete('/alerts', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;

    try {
        const result = await pool.query(
            `DELETE FROM alerts WHERE user_id = $1`,
            [uid]
        );

        return res.status(200).json({
            success: true,
            message: 'All alerts cleared',
            deletedCount: result.rowCount
        });

    } catch (error) {
        console.error('❌ Error clearing alerts:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error',
            details: error.message
        });
    }
});

// ============================================================
// EXPORT
// ============================================================

module.exports = router;
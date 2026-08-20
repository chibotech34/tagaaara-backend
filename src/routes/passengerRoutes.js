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

router.patch('/profile', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    const updates = req.body;

    const allowedFields = [
        'full_name', 'phone', 'email', 'gender',
        'emergency_contact_name', 'emergency_contact_phone', 'emergency_relationship',
        'home_address', 'region', 'district', 'town_city',
        'saved_locations', 'preferred_payment_method', 'mobile_money_number',
        'language_preference', 'notification_enabled', 'privacy_enabled'
    ];

    const setClauses = [];
    const values = [];
    let paramIndex = 1;

    for (const field of allowedFields) {
        if (updates.hasOwnProperty(field)) {
            if (field === 'saved_locations') {
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
// CREATE PASSENGER
// ============================================================

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
// TRANSACTIONS
// ============================================================

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
// RIDE HISTORY
// ============================================================

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

router.delete('/account', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;

    try {
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

        return res.status(204).send();

    } catch (error) {
        console.error('❌ Error deleting account:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while deleting account'
        });
    }
});

// ============================================================
// ALERTS (existing)
// ============================================================

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
// NEW: PASSENGER LOCATION AND NEARBY ENDPOINTS
// ============================================================

/**
 * POST /api/passengers/update-location
 * Update passenger's current location and online status.
 * Body: { latitude, longitude, isOnline? }
 */
router.post('/update-location', verifyFirebaseToken, async (req, res) => {
    try {
        const { latitude, longitude, isOnline } = req.body;
        const uid = req.decodedToken.uid;

        if (latitude == null || longitude == null) {
            return res.status(400).json({
                success: false,
                message: 'latitude and longitude are required'
            });
        }

        const lat = Number(latitude);
        const lng = Number(longitude);
        if (!isFinite(lat) || !isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) {
            return res.status(400).json({
                success: false,
                message: 'Invalid coordinates'
            });
        }

        const online = (isOnline === undefined) ? true : Boolean(isOnline);

        const result = await pool.query(
            `UPDATE passengers
             SET current_latitude = $1,
                 current_longitude = $2,
                 is_online = $3,
                 last_location_update = NOW()
             WHERE firebase_uid = $4
             RETURNING id, current_latitude, current_longitude, is_online, last_location_update`,
            [lat, lng, online, uid]
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
        console.error('❌ Update passenger location error:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

/**
 * GET /api/passengers/nearby
 * Returns online passengers within a radius (meters).
 * Query: ?lat=...&lng=...&radius=5000 (default 5 km)
 */
router.get('/nearby', verifyFirebaseToken, async (req, res) => {
    try {
        const { lat, lng, radius = 5000 } = req.query;

        if (!lat || !lng) {
            return res.status(400).json({
                success: false,
                message: 'lat and lng are required'
            });
        }

        const latitude = Number(lat);
        const longitude = Number(lng);
        if (!isFinite(latitude) || !isFinite(longitude)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid coordinates'
            });
        }

        const query = `
            SELECT id,
                   firebase_uid AS uid,
                   full_name,
                   phone,
                   email,
                   current_latitude AS latitude,
                   current_longitude AS longitude,
                   is_online,
                   last_location_update,
                   ROUND(
                       ST_Distance(
                           ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography,
                           ST_SetSRID(ST_MakePoint(current_longitude, current_latitude), 4326)::geography
                       )
                   ) AS distance_meters
            FROM passengers
            WHERE is_online = true
              AND current_latitude IS NOT NULL
              AND current_longitude IS NOT NULL
              AND ST_DWithin(
                    ST_SetSRID(ST_MakePoint(current_longitude, current_latitude), 4326)::geography,
                    ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography,
                    $3
                  )
            ORDER BY distance_meters ASC
            LIMIT 50;
        `;

        const result = await pool.query(query, [longitude, latitude, radius]);

        return res.status(200).json({
            success: true,
            passengers: result.rows
        });

    } catch (error) {
        console.error('❌ Fetch nearby passengers error:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// ============================================================
// WALLET TOP-UP (Add Money)
// ============================================================
router.post('/wallet/topup', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    const { amount, payment_method, provider } = req.body;

    // Validate input
    if (amount == null || amount <= 0) {
        return res.status(400).json({
            success: false,
            message: 'Invalid amount. Must be a positive number.'
        });
    }
    if (!payment_method) {
        return res.status(400).json({
            success: false,
            message: 'Payment method is required.'
        });
    }

    try {
        // 1. Get passenger by firebase_uid
        const passengerResult = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1`,
            [uid]
        );
        if (passengerResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Passenger not found.'
            });
        }
        const passengerId = passengerResult.rows[0].id;

        // 2. Get the wallet
        const walletResult = await pool.query(
            `SELECT id, balance FROM wallets WHERE passenger_id = $1`,
            [passengerId]
        );
        if (walletResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Wallet not found. Please create one first.'
            });
        }
        const wallet = walletResult.rows[0];
        const walletId = wallet.id;
        const oldBalance = parseFloat(wallet.balance);
        const newBalance = oldBalance + amount;

        // 3. Begin a transaction to update balance and create a transaction record
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            // Update wallet balance
            await client.query(
                `UPDATE wallets
                 SET balance = $1, last_transaction_at = NOW(), updated_at = NOW()
                 WHERE id = $2`,
                [newBalance, walletId]
            );

            // Insert transaction record
            const txResult = await client.query(
                `INSERT INTO transactions (
                    wallet_id, passenger_id, type, amount,
                    balance_before, balance_after, status,
                    payment_method, provider, description, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                RETURNING id`,
                [
                    walletId,
                    passengerId,
                    'topup',
                    amount,
                    oldBalance,
                    newBalance,
                    'completed',
                    payment_method,
                    provider || null,
                    `Top-up via ${payment_method}`
                ]
            );

            await client.query('COMMIT');

            return res.status(201).json({
                success: true,
                message: 'Top-up successful',
                transactionId: txResult.rows[0].id,
                newBalance: newBalance
            });
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('❌ Top-up error:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while processing top-up'
        });
    }
});

// ============================================================
// WALLET PAY FOR RIDE
// ============================================================
router.post('/wallet/pay', verifyFirebaseToken, async (req, res) => {
    const uid = req.decodedToken.uid;
    const { ride_id, amount } = req.body;

    if (ride_id == null || amount == null || amount <= 0) {
        return res.status(400).json({
            success: false,
            message: 'ride_id and amount (positive number) are required.'
        });
    }

    try {
        // 1. Get passenger
        const passengerResult = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1`,
            [uid]
        );
        if (passengerResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Passenger not found.'
            });
        }
        const passengerId = passengerResult.rows[0].id;

        // 2. Verify that the ride belongs to this passenger and is in a payable state
        const rideCheck = await pool.query(
            `SELECT id, driver_id, fare, payment_status, status
             FROM rides
             WHERE id = $1 AND passenger_id = $2`,
            [ride_id, passengerId]
        );
        if (rideCheck.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Ride not found or does not belong to you.'
            });
        }
        const ride = rideCheck.rows[0];
        if (ride.payment_status === 'completed') {
            return res.status(400).json({
                success: false,
                message: 'Ride already paid.'
            });
        }
        if (ride.status !== 'completed') {
            return res.status(400).json({
                success: false,
                message: 'Ride must be completed before payment.'
            });
        }
        // Optionally check that amount matches fare, or allow partial – here we require full fare
        if (parseFloat(ride.fare) !== amount) {
            return res.status(400).json({
                success: false,
                message: `Amount must match ride fare of ${ride.fare}.`
            });
        }

        // 3. Get wallet and check balance
        const walletResult = await pool.query(
            `SELECT id, balance FROM wallets WHERE passenger_id = $1`,
            [passengerId]
        );
        if (walletResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Wallet not found.'
            });
        }
        const wallet = walletResult.rows[0];
        const walletId = wallet.id;
        const currentBalance = parseFloat(wallet.balance);
        if (currentBalance < amount) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance.'
            });
        }
        const newBalance = currentBalance - amount;

        // 4. Begin transaction
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            // Deduct from wallet
            await client.query(
                `UPDATE wallets
                 SET balance = $1, total_spent = total_spent + $2,
                     last_transaction_at = NOW(), updated_at = NOW()
                 WHERE id = $3`,
                [newBalance, amount, walletId]
            );

            // Insert transaction record
            const txResult = await client.query(
                `INSERT INTO transactions (
                    wallet_id, passenger_id, ride_id, type, amount,
                    balance_before, balance_after, status,
                    description, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
                RETURNING id`,
                [
                    walletId,
                    passengerId,
                    ride_id,
                    'ridePayment',
                    amount,
                    currentBalance,
                    newBalance,
                    'completed',
                    `Payment for ride #${ride_id}`
                ]
            );

            // Update ride payment status
            await client.query(
                `UPDATE rides
                 SET payment_status = 'completed', paid_at = NOW()
                 WHERE id = $1`,
                [ride_id]
            );

            await client.query('COMMIT');

            return res.status(201).json({
                success: true,
                message: 'Ride paid successfully',
                transactionId: txResult.rows[0].id,
                newBalance: newBalance
            });
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('❌ Pay for ride error:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while processing payment'
        });
    }
});

// ============================================================
// EXPORT
// ============================================================

module.exports = router;
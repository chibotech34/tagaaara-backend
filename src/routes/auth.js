const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const pool = require('../db');
const admin = require('../firebase-admin');

// POST /api/auth/login
router.post('/login', async (req, res) => {
    const { phone, password } = req.body;
    if (!phone || !password) {
        return res.status(400).json({ message: 'Phone and password required' });
    }

    try {
        // 1. Find passenger by phone
        const result = await pool.query(
            'SELECT id, uid, phone, password_hash FROM passengers WHERE phone = $1',
            [phone]
        );
        if (result.rows.length === 0) {
            return res.status(401).json({ message: 'Invalid phone or password' });
        }

        const passenger = result.rows[0];

        // 2. Verify password (bcrypt)
        const match = await bcrypt.compare(password, passenger.password_hash);
        if (!match) {
            return res.status(401).json({ message: 'Invalid phone or password' });
        }

        // 3. Generate a custom Firebase token using the passenger's uid
        const customToken = await admin.auth().createCustomToken(passenger.uid);

        // 4. Return token
        res.json({ customToken });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;
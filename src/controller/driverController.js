// driverController.js
const { Pool } = require('pg');
const pool = new Pool({ /* your PostgreSQL connection config */ });

/**
 * Update driver's current location and online/availability status.
 * PUT /api/drivers/location
 * Body: { uid, latitude, longitude, isOnline?, isAvailable? }
 */
exports.updateDriverLocation = async (req, res) => {
    try {
        const { uid, latitude, longitude, isOnline, isAvailable } = req.body;

        if (!uid || latitude == null || longitude == null) {
            return res.status(400).json({
                success: false,
                message: 'uid, latitude, and longitude are required'
            });
        }

        // Build SET clause dynamically
        const updates = [
            'current_latitude = $2',
            'current_longitude = $3',
            'location = ST_SetSRID(ST_MakePoint($3, $2), 4326)::geography',
            'last_location_update = CURRENT_TIMESTAMP'
        ];
        const values = [uid, latitude, longitude];
        let paramIndex = 4;

        if (isOnline !== undefined) {
            updates.push(`is_online = $${paramIndex++}`);
            values.push(isOnline);
        }
        if (isAvailable !== undefined) {
            updates.push(`is_available = $${paramIndex++}`);
            values.push(isAvailable);
        }

        const query = `
            UPDATE drivers
            SET ${updates.join(', ')}
            WHERE uid = $1
            RETURNING id, is_online, is_available, last_location_update;
        `;

        const result = await pool.query(query, values);

        if (result.rowCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'Driver not found'
            });
        }

        return res.json({
            success: true,
            driver: result.rows[0]
        });
    } catch (error) {
        console.error('Update driver location error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to update location'
        });
    }
};

/**
 * Get nearby online/available drivers within a radius (meters).
 * GET /api/drivers/nearby
 * Query: latitude, longitude, radius (default 5000)
 */
exports.getNearbyDrivers = async (req, res) => {
    try {
        const { latitude, longitude, radius = 5000 } = req.query;

        if (latitude == null || longitude == null) {
            return res.status(400).json({
                success: false,
                message: 'latitude and longitude are required'
            });
        }

        const query = `
            SELECT 
                id,
                uid,
                full_name,
                phone,
                email,
                profile_photo_url,
                vehicle_type,
                registration_number,
                vehicle_color,
                vehicle_model,
                is_online,
                is_available,
                rating,
                ST_AsGeoJSON(location) AS location_geojson,
                ROUND(
                    ST_Distance(
                        location,
                        ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography
                    )
                ) AS distance_meters
            FROM drivers
            WHERE 
                is_online = true
                AND is_available = true
                AND status = 'approved'   -- optional, adjust as needed
                AND ST_DWithin(
                    location,
                    ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography,
                    $3
                )
            ORDER BY distance_meters ASC
            LIMIT 20;
        `;
        const values = [longitude, latitude, radius];

        const result = await pool.query(query, values);

        const drivers = result.rows.map(row => {
            const coords = row.location_geojson ? JSON.parse(row.location_geojson).coordinates : null;
            return {
                id: row.id,
                uid: row.uid,
                fullName: row.full_name,
                phone: row.phone,
                email: row.email,
                profilePhotoUrl: row.profile_photo_url,
                vehicleType: row.vehicle_type,
                registrationNumber: row.registration_number,
                vehicleColor: row.vehicle_color,
                vehicleModel: row.vehicle_model,
                isOnline: row.is_online,
                isAvailable: row.is_available,
                rating: row.rating,
                latitude: coords ? coords[1] : null,
                longitude: coords ? coords[0] : null,
                distanceMeters: row.distance_meters
            };
        });

        return res.json({
            success: true,
            drivers
        });
    } catch (error) {
        console.error('Get nearby drivers error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to fetch nearby drivers'
        });
    }
};
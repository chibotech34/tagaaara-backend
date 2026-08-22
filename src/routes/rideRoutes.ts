import { Router, Request, Response, NextFunction } from 'express';
import pool from '../config/database';
import { firebaseAuth, firebaseMessaging } from '../config/firebase';

const router = Router();

// -------------------------------------------------------------------
// 1. Firebase Token Middleware
// -------------------------------------------------------------------
interface DecodedFirebaseToken {
    uid: string;
    email?: string;
    name?: string;
}

interface AuthenticatedRequest extends Request {
    decodedToken?: DecodedFirebaseToken;
}

const verifyFirebaseToken = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
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
        const decodedToken = await firebaseAuth.verifyIdToken(token);
        req.decodedToken = {
            uid: decodedToken.uid,
            email: decodedToken.email,
            name: decodedToken.name,
        };
        next();
    } catch (error: unknown) {
        console.error('❌ Firebase token verification failed:', error);
        const firebaseError = error as { code?: string; message?: string };
        if (firebaseError.code === 'auth/id-token-expired') {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token expired. Please refresh authentication.',
                code: 'AUTH_TOKEN_EXPIRED',
            });
        } else if (firebaseError.code === 'auth/id-token-revoked') {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token has been revoked. Please sign in again.',
                code: 'AUTH_TOKEN_REVOKED',
            });
        } else {
            res.status(401).json({
                success: false,
                message: 'Firebase authentication failed.',
                code: 'AUTH_TOKEN_INVALID',
            });
        }
    }
};

// -------------------------------------------------------------------
// 2. Helper: get authenticated UID
// -------------------------------------------------------------------
const getAuthenticatedUid = (req: AuthenticatedRequest): string | null => {
    return req.decodedToken?.uid || null;
};

// -------------------------------------------------------------------
// 3. Helper: find nearby online/available drivers
// -------------------------------------------------------------------
async function getNearbyDrivers(lat: number, lng: number, radiusMeters: number = 15000) {
    const query = `
    SELECT id, uid, full_name, fcm_token, current_latitude, current_longitude
    FROM public.drivers
    WHERE status = 'approved'
      AND is_online = true
      AND is_available = true
      AND fcm_token IS NOT NULL
      AND ST_DWithin(
            location,
            ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography,
            $3
          )
    ORDER BY ST_Distance(location, ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography)
    LIMIT 20;
  `;
    const result = await pool.query(query, [lng, lat, radiusMeters]);
    return result.rows;
}

// -------------------------------------------------------------------
// 4. Helper: send FCM push notification to a single driver
// -------------------------------------------------------------------
async function sendRideNotificationToDriver(
    driverFcmToken: string,
    rideData: any,
    passengerName: string,
    rideType: string
) {
    try {
        await firebaseMessaging.send({
            token: driverFcmToken,
            notification: {
                title: 'New Ride Request',
                body: `${passengerName} wants a ride (${rideType})`,
            },
            data: rideData,
            android: {
                priority: 'high',
                notification: { channelId: 'ride_requests' },
            },
            apns: { payload: { aps: { sound: 'default' } } },
        });
    } catch (error) {
        console.error('❌ FCM send error:', error);
    }
}

// -------------------------------------------------------------------
// 5. POST /rides – Create ride (direct driver assignment)  [FIXED]
// -------------------------------------------------------------------
router.post('/rides', verifyFirebaseToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const {
            passenger_id,
            driver_id,
            pickup,          // { lat, lng }
            destination,     // { lat, lng }
            distance,
            duration,
            fare,
            ride_type,
            pickup_address,
            destination_address,
        } = req.body;

        // Validate required fields
        if (!passenger_id || !pickup || !destination) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: passenger_id, pickup, destination.',
            });
        }

        // 1. Verify passenger belongs to authenticated user
        const passengerCheck = await pool.query(
            `SELECT id FROM passengers WHERE id = $1 AND firebase_uid = $2`,
            [passenger_id, req.decodedToken?.uid]
        );
        if (passengerCheck.rows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Passenger ID does not match authenticated user or not found.'
            });
        }

        // 2. Verify driver exists and is available (optional but recommended)
        if (driver_id) {
            const driverCheck = await pool.query(
                `SELECT id FROM drivers WHERE id = $1 AND status = 'approved' AND is_online = true AND is_available = true`,
                [driver_id]
            );
            if (driverCheck.rows.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Driver not available or not found.'
                });
            }
        }

        // 3. Insert ride with driver_earnings and tegaara_commission
        const insertResult = await pool.query(
            `
            INSERT INTO public.rides (
                passenger_id,
                driver_id,
                pickup,
                destination,
                distance,
                duration,
                fare,
                payment_method,
                payment_status,
                status,
                ride_type,
                pickup_address,
                destination_address,
                driver_earnings,
                tegaara_commission,
                requested_at
            )
            VALUES (
                $1,
                $2,
                ST_SetSRID(ST_MakePoint($3, $4), 4326),
                ST_SetSRID(ST_MakePoint($5, $6), 4326),
                $7,
                $8,
                $9,
                $10,
                'pending',
                'accepted',          // direct assignment → accepted
                $11,
                $12,
                $13,
                $9 * 0.8,            // driver earnings (80%)
                $9 * 0.2,            // Tegaara commission (20%)
                NOW()
            )
            RETURNING id
            `,
            [
                passenger_id,
                driver_id || null,
                pickup.lng, pickup.lat,
                destination.lng, destination.lat,
                distance || null,
                duration || null,
                fare || 0,
                'standard',           // payment_method default
                ride_type || 'standard',
                pickup_address || null,
                destination_address || null,
            ]
        );

        const rideId = insertResult.rows[0].id;

        // Optionally notify the driver (if driver_id is provided)
        if (driver_id) {
            // Fetch driver FCM token and send notification
            const driverToken = await pool.query(
                `SELECT fcm_token FROM drivers WHERE id = $1`,
                [driver_id]
            );
            if (driverToken.rows.length > 0 && driverToken.rows[0].fcm_token) {
                // Get passenger name
                const passengerNameResult = await pool.query(
                    `SELECT full_name FROM passengers WHERE id = $1`,
                    [passenger_id]
                );
                const passengerName = passengerNameResult.rows[0]?.full_name || 'Passenger';
                await sendRideNotificationToDriver(
                    driverToken.rows[0].fcm_token,
                    {
                        rideId: rideId.toString(),
                        passengerId: passenger_id.toString(),
                        passengerName,
                        pickupAddress: pickup_address || 'Pickup location',
                        pickupLat: pickup.lat.toString(),
                        pickupLng: pickup.lng.toString(),
                        destinationAddress: destination_address || 'Destination',
                        destLat: destination.lat.toString(),
                        destLng: destination.lng.toString(),
                        rideType: ride_type || 'standard',
                        distanceKm: distance?.toString() || '0',
                        durationMin: duration?.toString() || '0',
                        fare: fare?.toString() || '0',
                        driverEarnings: fare ? (fare * 0.8).toFixed(2) : '0',
                    },
                    passengerName,
                    ride_type || 'standard'
                );
            }
        }

        return res.status(201).json({
            success: true,
            rideId,
            message: 'Ride booked successfully.',
        });
    } catch (error: unknown) {
        console.error('❌ Ride creation error:', error);
        const dbError = error as { code?: string; detail?: string; message?: string };
        if (dbError.code) console.error('DB Error Code:', dbError.code);
        if (dbError.detail) console.error('DB Detail:', dbError.detail);
        return res.status(500).json({
            success: false,
            message: 'Server error while creating ride.',
        });
    }
});

// -------------------------------------------------------------------
// 6. POST /rides/request – Direct request to a specific driver
// -------------------------------------------------------------------
router.post('/rides/request', verifyFirebaseToken, async (req: AuthenticatedRequest, res: Response) => {
    try {
        const {
            driver_id,
            pickup,
            destination,
            ride_type,
            estimated_fare,
            pickup_address,
            destination_address,
        } = req.body;

        if (!driver_id || !pickup || !destination) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: driver_id, pickup, destination.',
            });
        }

        // Verify the driver exists and is available
        const driverCheck = await pool.query(
            `SELECT id, fcm_token, full_name FROM drivers WHERE id = $1 AND status = 'approved' AND is_online = true AND is_available = true`,
            [driver_id]
        );
        if (driverCheck.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Driver not available or not found.',
            });
        }
        const driver = driverCheck.rows[0];

        // Get passenger ID from the authenticated user
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({ success: false, message: 'Unauthenticated.' });
        }
        const passengerResult = await pool.query(
            `SELECT id FROM passengers WHERE firebase_uid = $1`,
            [uid]
        );
        if (passengerResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Passenger profile not found. Please complete registration.',
            });
        }
        const passengerId = passengerResult.rows[0].id;

        // Insert ride with driver assigned immediately (status = 'accepted')
        const insertResult = await pool.query(
            `
            INSERT INTO public.rides (
                passenger_id,
                driver_id,
                pickup,
                destination,
                distance,
                duration,
                fare,
                payment_method,
                payment_status,
                status,
                ride_type,
                pickup_address,
                destination_address,
                driver_earnings,
                tegaara_commission,
                requested_at
            )
            VALUES (
                $1,
                $2,
                ST_SetSRID(ST_MakePoint($3, $4), 4326),
                ST_SetSRID(ST_MakePoint($5, $6), 4326),
                $7,
                $8,
                $9,
                $10,
                'pending',
                'accepted',
                $11,
                $12,
                $13,
                $9 * 0.8,
                $9 * 0.2,
                NOW()
            )
            RETURNING id
            `,
            [
                passengerId,
                driver_id,
                pickup.lng, pickup.lat,
                destination.lng, destination.lat,
                null, // distance – can be calculated later
                null, // duration
                estimated_fare || 0,
                'standard',
                ride_type || 'standard',
                pickup_address || null,
                destination_address || null,
            ]
        );

        const rideId = insertResult.rows[0].id;

        // Notify the specific driver
        const passengerInfo = await pool.query(
            `SELECT full_name FROM passengers WHERE id = $1`,
            [passengerId]
        );
        const passengerName = passengerInfo.rows[0]?.full_name || 'Passenger';

        const notificationPayload = {
            rideId: rideId.toString(),
            passengerId: passengerId.toString(),
            passengerName,
            passengerPhotoUrl: '',
            passengerRating: '4.5',
            passengerRides: '0',
            pickupAddress: pickup_address || 'Pickup location',
            pickupLat: pickup.lat.toString(),
            pickupLng: pickup.lng.toString(),
            destinationAddress: destination_address || 'Destination',
            destLat: destination.lat.toString(),
            destLng: destination.lng.toString(),
            rideType: ride_type || 'standard',
            distanceKm: '0',
            durationMin: '0',
            fare: estimated_fare?.toString() || '0',
            driverEarnings: estimated_fare ? (estimated_fare * 0.8).toFixed(2) : '0',
        };

        if (driver.fcm_token) {
            await sendRideNotificationToDriver(
                driver.fcm_token,
                notificationPayload,
                passengerName,
                ride_type || 'standard'
            );
        }

        return res.status(201).json({
            success: true,
            rideId,
            message: 'Ride requested directly to driver.',
        });
    } catch (error: unknown) {
        console.error('❌ Direct ride request error:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while requesting ride.',
        });
    }
});

// -------------------------------------------------------------------
// 7. POST /rides/:rideId/accept – Driver accepts a broadcasted ride
// -------------------------------------------------------------------
router.post('/rides/:rideId/accept', verifyFirebaseToken, async (req: AuthenticatedRequest, res: Response) => {
    const { rideId } = req.params;
    const { driver_id } = req.body;

    if (!driver_id) {
        return res.status(400).json({
            success: false,
            message: 'Missing driver_id in request body.',
        });
    }

    // Verify the authenticated user owns this driver
    const uid = getAuthenticatedUid(req);
    if (!uid) {
        return res.status(401).json({ success: false, message: 'Unauthenticated.' });
    }
    const driverCheck = await pool.query(
        `SELECT id FROM drivers WHERE uid = $1 AND id = $2`,
        [uid, driver_id]
    );
    if (driverCheck.rows.length === 0) {
        return res.status(403).json({
            success: false,
            message: 'Forbidden: driver_id does not match authenticated user.',
        });
    }

    // Atomically assign driver to ride if still in 'requested' state
    const updateResult = await pool.query(
        `
        UPDATE public.rides
        SET driver_id = $1,
            status = 'accepted',
            driver_earnings = fare * 0.8,
            tegaara_commission = fare * 0.2
        WHERE id = $2
          AND status = 'requested'
          AND driver_id IS NULL
        RETURNING id, passenger_id, driver_id, status
        `,
        [driver_id, rideId]
    );

    if (updateResult.rows.length === 0) {
        return res.status(409).json({
            success: false,
            message: 'Ride already accepted or no longer available.',
        });
    }

    // Optionally notify passenger (implement if needed)

    return res.status(200).json({
        success: true,
        ride: updateResult.rows[0],
        message: 'Ride accepted successfully.',
    });
});

// -------------------------------------------------------------------
// 8. POST /driver/accept-ride – Wrapper for accept
// -------------------------------------------------------------------
router.post('/driver/accept-ride', verifyFirebaseToken, async (req: AuthenticatedRequest, res: Response) => {
    const { rideId, driverId } = req.body;
    if (!rideId || !driverId) {
        return res.status(400).json({
            success: false,
            message: 'Missing rideId or driverId.',
        });
    }
    // Re-use the accept logic by calling the same route handler
    // We'll emulate the same logic inline
    try {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({ success: false, message: 'Unauthenticated.' });
        }
        const driverCheck = await pool.query(
            `SELECT id FROM drivers WHERE uid = $1 AND id = $2`,
            [uid, driverId]
        );
        if (driverCheck.rows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Forbidden: driver_id does not match authenticated user.',
            });
        }
        const updateResult = await pool.query(
            `
            UPDATE public.rides
            SET driver_id = $1,
                status = 'accepted',
                driver_earnings = fare * 0.8,
                tegaara_commission = fare * 0.2
            WHERE id = $2
              AND status = 'requested'
              AND driver_id IS NULL
            RETURNING id, passenger_id, driver_id, status
            `,
            [driverId, rideId]
        );
        if (updateResult.rows.length === 0) {
            return res.status(409).json({
                success: false,
                message: 'Ride already accepted or no longer available.',
            });
        }
        return res.status(200).json({
            success: true,
            ride: updateResult.rows[0],
            message: 'Ride accepted successfully.',
        });
    } catch (error: unknown) {
        console.error('❌ Accept ride error:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while accepting ride.',
        });
    }
});

// -------------------------------------------------------------------
// 9. POST /driver/decline-ride – No-op, just acknowledge
// -------------------------------------------------------------------
router.post('/driver/decline-ride', verifyFirebaseToken, (req: AuthenticatedRequest, res: Response) => {
    return res.status(200).json({
        success: true,
        message: 'Ride declined.',
    });
});

// -------------------------------------------------------------------
// 10. GET /drivers/:uid/current-request – Fetch active ride for driver
// -------------------------------------------------------------------
router.get('/drivers/:uid/current-request', verifyFirebaseToken, async (req: AuthenticatedRequest, res: Response) => {
    const { uid } = req.params;
    const authenticatedUid = getAuthenticatedUid(req);
    if (uid !== authenticatedUid) {
        return res.status(403).json({
            success: false,
            message: 'Forbidden: UID mismatch.',
        });
    }

    try {
        // Get driver_id
        const driverResult = await pool.query(`SELECT id FROM drivers WHERE uid = $1`, [uid]);
        if (driverResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Driver not found.',
            });
        }
        const driverId = driverResult.rows[0].id;

        // Fetch the most recent ride that is accepted or started, and not completed/cancelled
        const rideResult = await pool.query(
            `
            SELECT
                id as "rideId",
                passenger_id as "passengerId",
                pickup_address as "pickupAddress",
                destination_address as "destinationAddress",
                ST_X(pickup) as "pickupLat",
                ST_Y(pickup) as "pickupLng",
                ST_X(destination) as "destLat",
                ST_Y(destination) as "destLng",
                distance as "distanceKm",
                duration as "durationMin",
                fare,
                driver_earnings as "driverEarnings",
                status,
                ride_type as "rideType",
                (SELECT full_name FROM passengers WHERE id = rides.passenger_id) as "passengerName",
                (SELECT profile_photo_url FROM passengers WHERE id = rides.passenger_id) as "passengerPhotoUrl"
            FROM rides
            WHERE driver_id = $1
              AND status IN ('accepted', 'started')
            ORDER BY requested_at DESC
            LIMIT 1
            `,
            [driverId]
        );

        if (rideResult.rows.length === 0) {
            return res.status(200).json({
                success: true,
                ride: null,
            });
        }

        const ride = rideResult.rows[0];
        return res.status(200).json({
            success: true,
            ride: {
                ...ride,
                passengerRating: '4.5',
                passengerRides: '0',
            },
        });
    } catch (error: unknown) {
        console.error('❌ Error fetching current request:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error while fetching current ride.',
        });
    }
});

// -------------------------------------------------------------------
// 11. POST /driver/update-fcm-token – Store FCM token for driver
// -------------------------------------------------------------------
router.post('/driver/update-fcm-token', verifyFirebaseToken, async (req: AuthenticatedRequest, res: Response) => {
    const { fcmToken } = req.body;
    if (!fcmToken) {
        return res.status(400).json({
            success: false,
            message: 'Missing fcmToken.',
        });
    }

    const uid = getAuthenticatedUid(req);
    if (!uid) {
        return res.status(401).json({ success: false, message: 'Unauthenticated.' });
    }

    try {
        await pool.query(
            `UPDATE drivers SET fcm_token = $1 WHERE uid = $2`,
            [fcmToken, uid]
        );
        return res.status(200).json({
            success: true,
            message: 'FCM token updated.',
        });
    } catch (error: unknown) {
        console.error('❌ FCM token update error:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error updating FCM token.',
        });
    }
});

// -------------------------------------------------------------------
// 12. GET /rides/:rideId/status – For polling status
// -------------------------------------------------------------------
router.get('/rides/:rideId/status', verifyFirebaseToken, async (req: AuthenticatedRequest, res: Response) => {
    const { rideId } = req.params;
    try {
        const result = await pool.query(
            `
            SELECT id, status, driver_id, passenger_id, fare, payment_status
            FROM rides
            WHERE id = $1
            `,
            [rideId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Ride not found.' });
        }
        return res.status(200).json({ success: true, ride: result.rows[0] });
    } catch (error: unknown) {
        console.error('❌ Status fetch error:', error);
        return res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// -------------------------------------------------------------------
// 13. POST /rides/:rideId/start – Driver starts the trip
// -------------------------------------------------------------------
router.post('/rides/:rideId/start', verifyFirebaseToken, async (req: AuthenticatedRequest, res: Response) => {
    const { rideId } = req.params;
    const uid = getAuthenticatedUid(req);
    if (!uid) return res.status(401).json({ success: false, message: 'Unauthenticated.' });

    try {
        // Verify driver owns this ride
        const check = await pool.query(
            `SELECT id FROM rides WHERE id = $1 AND driver_id = (SELECT id FROM drivers WHERE uid = $2) AND status = 'accepted'`,
            [rideId, uid]
        );
        if (check.rows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Ride not found or not in accepted state.',
            });
        }

        await pool.query(`UPDATE rides SET status = 'started' WHERE id = $1`, [rideId]);
        return res.status(200).json({ success: true, message: 'Ride started.' });
    } catch (error: unknown) {
        console.error('❌ Start ride error:', error);
        return res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// -------------------------------------------------------------------
// 14. POST /rides/:rideId/complete – Driver completes the trip
// -------------------------------------------------------------------
router.post('/rides/:rideId/complete', verifyFirebaseToken, async (req: AuthenticatedRequest, res: Response) => {
    const { rideId } = req.params;
    const uid = getAuthenticatedUid(req);
    if (!uid) return res.status(401).json({ success: false, message: 'Unauthenticated.' });

    try {
        const check = await pool.query(
            `SELECT id FROM rides WHERE id = $1 AND driver_id = (SELECT id FROM drivers WHERE uid = $2) AND status = 'started'`,
            [rideId, uid]
        );
        if (check.rows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Ride not found or not in started state.',
            });
        }

        await pool.query(
            `UPDATE rides SET status = 'completed', completed_at = NOW() WHERE id = $1`,
            [rideId]
        );
        return res.status(200).json({ success: true, message: 'Ride completed.' });
    } catch (error: unknown) {
        console.error('❌ Complete ride error:', error);
        return res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// -------------------------------------------------------------------
// 15. POST /rides/:rideId/cancel – Cancel ride (by passenger or driver)
// -------------------------------------------------------------------
router.post('/rides/:rideId/cancel', verifyFirebaseToken, async (req: AuthenticatedRequest, res: Response) => {
    const { rideId } = req.params;
    const { reason } = req.body;
    const uid = getAuthenticatedUid(req);
    if (!uid) return res.status(401).json({ success: false, message: 'Unauthenticated.' });

    try {
        // Check if the user is either the passenger or the driver of this ride
        const rideCheck = await pool.query(
            `
            SELECT id FROM rides
            WHERE id = $1
              AND (
                passenger_id = (SELECT id FROM passengers WHERE firebase_uid = $2)
                OR driver_id = (SELECT id FROM drivers WHERE uid = $2)
              )
              AND status NOT IN ('completed', 'cancelled')
            `,
            [rideId, uid]
        );
        if (rideCheck.rows.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Ride not found or cannot be cancelled.',
            });
        }

        await pool.query(
            `UPDATE rides SET status = 'cancelled' WHERE id = $1`,
            [rideId]
        );
        return res.status(200).json({ success: true, message: 'Ride cancelled.' });
    } catch (error: unknown) {
        console.error('❌ Cancel ride error:', error);
        return res.status(500).json({ success: false, message: 'Server error.' });
    }
});

// -------------------------------------------------------------------
// Export router
// -------------------------------------------------------------------
export default router;
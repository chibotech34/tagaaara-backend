import { Router, Response } from 'express';
import pool from '../config/database';
import { firebaseMessaging } from '../config/firebase';
import { verifyFirebaseToken, AuthenticatedRequest } from '../middleware/firebaseAdmin';

import {
    Router,
    Response,
} from 'express';

import pool from '../config/database';

import {
    firebaseMessaging,
} from '../config/firebase';

import {
    verifyFirebaseToken,
    AuthenticatedRequest,
} from '../middleware/firebaseAdmin';

const router = Router();

/*
|--------------------------------------------------------------------------
| Types
|--------------------------------------------------------------------------
*/

interface LocationPoint {
    lat: number;
    lng: number;
}

/*
|--------------------------------------------------------------------------
| Authentication Helpers
|--------------------------------------------------------------------------
*/

function getAuthenticatedUid(
    req: AuthenticatedRequest,
): string | null {
    const uid =
        req.decodedToken?.uid;

    if (
        !uid ||
        typeof uid !== 'string' ||
        !uid.trim()
    ) {
        return null;
    }

    return uid.trim();
}

/*
|--------------------------------------------------------------------------
| Validation Helpers
|--------------------------------------------------------------------------
*/

function isValidLocation(
    value: unknown,
): value is LocationPoint {
    if (
        !value ||
        typeof value !== 'object'
    ) {
        return false;
    }

    const location =
        value as Record<
            string,
            unknown
        >;

    const lat =
        Number(location.lat);

    const lng =
        Number(location.lng);

    return (
        Number.isFinite(lat) &&
        Number.isFinite(lng) &&
        lat >= -90 &&
        lat <= 90 &&
        lng >= -180 &&
        lng <= 180
    );
}

function toNumber(
    value: unknown,
    fallback: number | null = null,
): number | null {
    if (
        value === null ||
        value === undefined ||
        value === ''
    ) {
        return fallback;
    }

    const number =
        Number(value);

    return Number.isFinite(number)
        ? number
        : fallback;
}

/*
|--------------------------------------------------------------------------
| FCM Token Cleanup
|--------------------------------------------------------------------------
*/

async function deleteInvalidFcmToken(
    token: string,
): Promise<void> {
    try {
        await pool.query(
            `
            DELETE FROM public.fcm_tokens
            WHERE token = $1
            `,
            [token],
        );

        console.log(
            '🗑️ Invalid FCM token removed.',
        );
    } catch (error) {
        console.error(
            '❌ Failed to remove invalid FCM token:',
            error,
        );
    }
}

/*
|--------------------------------------------------------------------------
| Send Single FCM Notification
|--------------------------------------------------------------------------
*/

async function sendFcmNotification(
    token: string,
    title: string,
    body: string,
    data: Record<string, string>,
): Promise<boolean> {
    if (
        !token ||
        !token.trim()
    ) {
        return false;
    }

    try {
        await firebaseMessaging.send({
            token: token.trim(),

            notification: {
                title,
                body,
            },

            data,

            android: {
                priority: 'high',

                notification: {
                    channelId:
                        'tegaara_rides',
                    sound: 'default',
                },
            },

            apns: {
                headers: {
                    'apns-priority': '10',
                },
            },
        });

        console.log(
            `✅ FCM notification sent: ${title}`,
        );

        return true;
    } catch (error: any) {
        console.error(
            '❌ FCM send error:',
            error,
        );

        if (
            error?.code ===
            'messaging/invalid-registration-token' ||
            error?.code ===
            'messaging/registration-token-not-registered'
        ) {
            await deleteInvalidFcmToken(
                token,
            );
        }

        return false;
    }
}

/*
|--------------------------------------------------------------------------
| Notify Nearby Drivers
|--------------------------------------------------------------------------
*/

async function notifyNearbyDrivers(
    rideId: number,
    lat: number,
    lng: number,
    rideData: any,
): Promise<void> {
    const radius =
        5000;

    try {
        const result =
            await pool.query(
                `
                SELECT DISTINCT
                    d.uid,
                    ft.token
                FROM public.drivers d
                INNER JOIN public.fcm_tokens ft
                    ON ft.user_id = d.uid
                WHERE d.is_online = true
                  AND d.is_available = true
                  AND d.status = 'approved'
                  AND ft.token IS NOT NULL
                  AND ST_DWithin(
                        d.location,
                        ST_SetSRID(
                            ST_MakePoint(
                                $1,
                                $2
                            ),
                            4326
                        )::geography,
                        $3
                      )
                `,
                [
                    lng,
                    lat,
                    radius,
                ],
            );

        if (
            result.rows.length === 0
        ) {
            console.log(
                `ℹ️ No nearby drivers with FCM tokens for ride ${rideId}`,
            );

            return;
        }

        const tokens =
            result.rows
                .map(
                    row =>
                        row.token,
                )
                .filter(
                    Boolean,
                );

        if (
            tokens.length === 0
        ) {
            return;
        }

        const title =
            'New Ride Request';

        const body =
            `${rideData.passenger_name || 'A passenger'} needs a ride`;

        const dataPayload = {
            type:
                'ride_request',

            rideId:
                rideId.toString(),

            passengerName:
                String(
                    rideData.passenger_name ||
                    'Passenger',
                ),

            pickupLat:
                lat.toString(),

            pickupLng:
                lng.toString(),

            pickupAddress:
                String(
                    rideData.pickup_address ||
                    '',
                ),

            destinationAddress:
                String(
                    rideData.destination_address ||
                    '',
                ),

            fare:
                String(
                    rideData.fare ||
                    0,
                ),

            rideType:
                String(
                    rideData.ride_type ||
                    'standard',
                ),
        };

        console.log(
            `📲 Sending ride ${rideId} notification to ${tokens.length} driver device(s)`,
        );

        const response =
            await firebaseMessaging
                .sendEachForMulticast({
                    tokens,

                    notification: {
                        title,
                        body,
                    },

                    data:
                        dataPayload,

                    android: {
                        priority:
                            'high',

                        notification: {
                            channelId:
                                'tegaara_rides',
                            sound:
                                'default',
                        },
                    },

                    apns: {
                        headers: {
                            'apns-priority':
                                '10',
                        },
                    },
                });

        console.log(
            `📲 Ride ${rideId}: ${response.successCount} notification(s) sent, ${response.failureCount} failed`,
        );

        /*
        |--------------------------------------------------------------------------
        | Remove only invalid tokens
        |--------------------------------------------------------------------------
        */

        for (
            let i = 0;
            i <
            response.responses.length;
            i++
        ) {
            const sendResponse =
                response.responses[i];

            if (
                sendResponse.success
            ) {
                continue;
            }

            const errorCode =
                sendResponse.error
                    ?.code;

            if (
                errorCode ===
                'messaging/invalid-registration-token' ||
                errorCode ===
                'messaging/registration-token-not-registered'
            ) {
                await deleteInvalidFcmToken(
                    tokens[i],
                );
            }
        }
    } catch (error) {
        console.error(
            `❌ Failed to notify nearby drivers for ride ${rideId}:`,
            error,
        );
    }
}

/*
|--------------------------------------------------------------------------
| Passenger FCM Token
|--------------------------------------------------------------------------
*/

async function getPassengerFcmToken(
    passengerId: number,
): Promise<string | null> {
    const result =
        await pool.query(
            `
            SELECT ft.token
            FROM public.fcm_tokens ft
            INNER JOIN public.passengers p
                ON p.firebase_uid =
                   ft.user_id
            WHERE p.id = $1
            ORDER BY ft.updated_at DESC
            LIMIT 1
            `,
            [passengerId],
        );

    return (
        result.rows[0]?.token ||
        null
    );
}

const router = Router();

/*
|--------------------------------------------------------------------------
| Types
|--------------------------------------------------------------------------
*/
interface LocationPoint {
    lat: number;
    lng: number;
}

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/
function getAuthenticatedUid(req: AuthenticatedRequest): string | null {
    const uid = req.decodedToken?.uid;
    if (!uid || typeof uid !== 'string' || !uid.trim()) {
        return null;
    }
    return uid.trim();
}

function isValidLocation(value: unknown): value is LocationPoint {
    if (!value || typeof value !== 'object') return false;
    const location = value as Record<string, unknown>;
    const lat = Number(location.lat);
    const lng = Number(location.lng);
    return Number.isFinite(lat) && Number.isFinite(lng) && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180;
}

function toNumber(value: unknown, fallback: number | null = null): number | null {
    if (value === null || value === undefined || value === '') return fallback;
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
}

/*
|--------------------------------------------------------------------------
| FCM Helpers
|--------------------------------------------------------------------------
*/
async function sendFcmNotification(
    token: string,
    title: string,
    body: string,
    data: Record<string, string>
): Promise<void> {
    if (!token) return;
    try {
        await firebaseMessaging.send({
            notification: { title, body },
            data,
            token,
            android: { priority: 'high' },
            apns: { headers: { 'apns-priority': '10' } },
        });
    } catch (error: any) {
        if (error.code === 'messaging/invalid-registration-token' ||
            error.code === 'messaging/registration-token-not-registered') {
            await pool.query(`DELETE FROM fcm_tokens WHERE token = $1`, [token]);
        }
        console.error('FCM send error:', error);
    }
}

async function notifyNearbyDrivers(rideId: number, lat: number, lng: number, rideData: any) {
    const radius = 5000;
    const result = await pool.query(
        `
        SELECT d.uid, ft.token
        FROM drivers d
        JOIN fcm_tokens ft ON ft.user_id = d.uid
        WHERE d.is_online = true
          AND d.is_available = true
          AND d.status = 'approved'
          AND ft.token IS NOT NULL
          AND ST_DWithin(
                d.location,
                ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography,
                $3
              )
        `,
        [lng, lat, radius]
    );

    const tokens = result.rows.map(row => row.token).filter(Boolean);
    if (tokens.length === 0) return;

    const title = 'New Ride Request';
    const body = `${rideData.passenger_name || 'A passenger'} needs a ride from ${rideData.pickup_address || 'your area'}`;
    const dataPayload = {
        rideId: rideId.toString(),
        passengerName: rideData.passenger_name || 'Passenger',
        pickupLat: lat.toString(),
        pickupLng: lng.toString(),
        pickupAddress: rideData.pickup_address || '',
        destinationAddress: rideData.destination_address || '',
        fare: rideData.fare?.toString() || '0',
        rideType: rideData.ride_type || 'standard',
    };

    try {
        const response = await firebaseMessaging.sendEachForMulticast({
            tokens,
            notification: { title, body },
            data: dataPayload,
            android: { priority: 'high' },
            apns: { headers: { 'apns-priority': '10' } },
        });
        if (response.failureCount > 0) {
            for (let i = 0; i < response.responses.length; i++) {
                if (!response.responses[i].success) {
                    const token = tokens[i];
                    await pool.query(`DELETE FROM fcm_tokens WHERE token = $1`, [token]);
                }
            }
        }
    } catch (error) {
        console.error('Multicast error:', error);
    }
}

/*
|--------------------------------------------------------------------------
| Routes
|--------------------------------------------------------------------------
*/

// POST /rides
router.post(
    '/rides',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            if (!req.body || typeof req.body !== 'object') {
                return res.status(400).json({
                    success: false,
                    message: 'Request body is missing or invalid JSON.',
                });
            }

            const {
                pickup,
                destination,
                distance,
                duration,
                fare,
                ride_type,
                payment_method,
                pickup_address,
                destination_address,
            } = req.body;

            const uid = getAuthenticatedUid(req);
            if (!uid) {
                return res.status(401).json({ success: false, message: 'Unauthenticated.' });
            }

            console.log('🔥 Passenger Firebase UID:', uid);

            // Find passenger
            const passengerResult = await pool.query(
                `
                SELECT id, firebase_uid, full_name, profile_photo_url
                FROM public.passengers
                WHERE firebase_uid = $1::text
                LIMIT 1
                `,
                [uid]
            );
            if (passengerResult.rows.length === 0) {
                return res.status(404).json({ success: false, message: 'Passenger profile not found.' });
            }
            const passenger = passengerResult.rows[0];

            // Validate locations
            if (!isValidLocation(pickup)) {
                return res.status(400).json({ success: false, message: 'Invalid pickup. Expected { lat, lng }.' });
            }
            if (!isValidLocation(destination)) {
                return res.status(400).json({ success: false, message: 'Invalid destination. Expected { lat, lng }.' });
            }

            const pickupLat = Number(pickup.lat);
            const pickupLng = Number(pickup.lng);
            const destinationLat = Number(destination.lat);
            const destinationLng = Number(destination.lng);

            // Check active ride
            const activeRideResult = await pool.query(
                `
                SELECT id
                FROM public.rides
                WHERE passenger_id = $1::integer
                  AND status IN ('requested', 'accepted', 'started')
                ORDER BY requested_at DESC
                LIMIT 1
                `,
                [passenger.id]
            );
            if (activeRideResult.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'You already have an active ride.',
                    rideId: activeRideResult.rows[0].id,
                });
            }

            // Numbers
            const rideDistance = toNumber(distance, 0) ?? 0;
            const rideDuration = Math.round(toNumber(duration, 0) ?? 0);
            const rideFare = toNumber(fare, 0) ?? 0;
            if (rideDistance < 0 || rideDuration < 0 || rideFare < 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Distance, duration and fare cannot be negative.',
                });
            }

            const rideType = typeof ride_type === 'string' && ride_type.trim() ? ride_type.trim() : 'standard';
            const paymentMethod = typeof payment_method === 'string' && payment_method.trim() ? payment_method.trim() : 'cash';

            // Insert ride
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
                    $1::integer,
                    NULL::text,
                    ST_SetSRID(ST_MakePoint($2::double precision, $3::double precision), 4326),
                    ST_SetSRID(ST_MakePoint($4::double precision, $5::double precision), 4326),
                    $6::numeric,
                    $7::integer,
                    $8::numeric,
                    $9::varchar,
                    'pending'::varchar,
                    'requested'::varchar,
                    $10::varchar,
                    $11::text,
                    $12::text,
                    NULL::numeric,
                    NULL::numeric,
                    NOW()
                )
                RETURNING
                    id,
                    passenger_id,
                    driver_id,
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
                `,
                [
                    passenger.id,
                    pickupLng,
                    pickupLat,
                    destinationLng,
                    destinationLat,
                    rideDistance,
                    rideDuration,
                    rideFare,
                    paymentMethod,
                    rideType,
                    pickup_address ?? null,
                    destination_address ?? null,
                ]
            );

            const ride = insertResult.rows[0];
            console.log(`✅ Ride ${ride.id} created.`);

            // Notify nearby drivers
            const rideData = {
                passenger_name: passenger.full_name || 'Passenger',
                pickup_address: pickup_address || '',
                destination_address: destination_address || '',
                fare: rideFare,
                ride_type: rideType,
            };
            notifyNearbyDrivers(ride.id, pickupLat, pickupLng, rideData).catch(err =>
                console.error('Error notifying drivers:', err)
            );

            return res.status(201).json({
                success: true,
                rideId: ride.id,
                ride: {
                    ...ride,
                    pickup: { lat: pickupLat, lng: pickupLng },
                    destination: { lat: destinationLat, lng: destinationLng },
                },
                message: 'Ride request created successfully.',
            });
        } catch (error: unknown) {
            console.error('❌ RIDE CREATION ERROR:', error);
            const dbError = error as { code?: string; message?: string; detail?: string; hint?: string };
            return res.status(500).json({
                success: false,
                message: 'Server error while creating ride.',
                code: dbError.code ?? 'RIDE_CREATION_ERROR',
                error: dbError.message ?? 'Unknown database error',
                detail: dbError.detail ?? null,
                hint: dbError.hint ?? null,
            });
        }
    }
);

// GET /rides/nearby
router.get(
    '/rides/nearby',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const lat = Number(req.query.lat);
            const lng = Number(req.query.lng);
            let radius = Number(req.query.radius);
            if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
                return res.status(400).json({ success: false, message: 'Valid lat and lng are required.' });
            }
            if (!Number.isFinite(radius) || radius <= 0) radius = 5000;
            radius = Math.min(radius, 50000);

            const uid = getAuthenticatedUid(req);
            if (!uid) {
                return res.status(401).json({ success: false, message: 'Unauthenticated.' });
            }

            const driverResult = await pool.query(
                `SELECT uid, status, is_online, is_available FROM public.drivers WHERE uid = $1::text LIMIT 1`,
                [uid]
            );
            if (driverResult.rows.length === 0) {
                return res.status(404).json({ success: false, message: 'Driver profile not found.' });
            }
            const driver = driverResult.rows[0];
            if (driver.status !== 'approved' || !driver.is_online || !driver.is_available) {
                return res.status(200).json([]);
            }

            const result = await pool.query(
                `
                SELECT
                    r.id,
                    r.passenger_id,
                    r.driver_id,
                    r.pickup_address,
                    r.destination_address,
                    ST_Y(r.pickup) AS pickup_lat,
                    ST_X(r.pickup) AS pickup_lng,
                    ST_Y(r.destination) AS dest_lat,
                    ST_X(r.destination) AS dest_lng,
                    r.distance,
                    r.duration,
                    r.fare,
                    r.payment_method,
                    r.payment_status,
                    r.status,
                    r.ride_type,
                    r.requested_at,
                    p.full_name AS passenger_name,
                    p.profile_photo_url AS passenger_photo_url,
                    5.0 AS passenger_rating,
                    ST_Distance(
                        r.pickup::geography,
                        ST_SetSRID(ST_MakePoint($2::double precision, $1::double precision), 4326)::geography
                    ) / 1000.0 AS distance_to_pickup
                FROM public.rides r
                INNER JOIN public.passengers p ON p.id = r.passenger_id
                WHERE r.status = 'requested'
                  AND r.driver_id IS NULL
                  AND ST_DWithin(
                        r.pickup::geography,
                        ST_SetSRID(ST_MakePoint($2::double precision, $1::double precision), 4326)::geography,
                        $3::double precision
                      )
                ORDER BY distance_to_pickup ASC, r.requested_at ASC
                LIMIT 20
                `,
                [lat, lng, radius]
            );

            return res.status(200).json(result.rows);
        } catch (error) {
            console.error('❌ Nearby rides error:', error);
            return res.status(500).json({ success: false, message: 'Server error while finding nearby rides.' });
        }
    }
);

// POST /rides/:rideId/accept
router.post(
    '/rides/:rideId/accept',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const client = await pool.connect();
        try {
            const rideId = Number(req.params.rideId);
            if (!Number.isInteger(rideId) || rideId <= 0) {
                return res.status(400).json({ success: false, message: 'Invalid ride ID.' });
            }

            const uid = getAuthenticatedUid(req);
            if (!uid) {
                return res.status(401).json({ success: false, message: 'Unauthenticated.' });
            }

            console.log(`📥 Accept request: ride=${rideId}, driverUID=${uid}`);

            await client.query('BEGIN');

            const driverResult = await client.query(
                `SELECT uid, full_name, status, is_online, is_available FROM public.drivers WHERE uid = $1::text LIMIT 1`,
                [uid]
            );
            if (driverResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({ success: false, message: 'Driver profile not found.' });
            }
            const driver = driverResult.rows[0];
            if (driver.status !== 'approved' || !driver.is_online || !driver.is_available) {
                await client.query('ROLLBACK');
                return res.status(403).json({ success: false, message: 'Driver is not available.' });
            }

            const updateResult = await client.query(
                `
                UPDATE public.rides
                SET
                    driver_id = $1::text,
                    status = 'accepted',
                    driver_earnings = ROUND((fare * 0.80)::numeric, 2),
                    tegaara_commission = ROUND((fare * 0.20)::numeric, 2)
                WHERE id = $2::integer
                  AND status = 'requested'
                  AND driver_id IS NULL
                RETURNING id
                `,
                [uid, rideId]
            );
            if (updateResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(409).json({
                    success: false,
                    message: 'Ride has already been accepted or is no longer available.',
                });
            }

            await client.query(`UPDATE public.drivers SET is_available = false WHERE uid = $1::text`, [uid]);

            const rideResult = await client.query(
                `
                SELECT
                    r.id AS "rideId",
                    r.passenger_id AS "passengerId",
                    r.driver_id AS "driverId",
                    r.pickup_address AS "pickupAddress",
                    r.destination_address AS "destinationAddress",
                    ST_Y(r.pickup) AS "pickupLat",
                    ST_X(r.pickup) AS "pickupLng",
                    ST_Y(r.destination) AS "destLat",
                    ST_X(r.destination) AS "destLng",
                    r.distance AS "distanceKm",
                    r.duration AS "durationMin",
                    r.fare,
                    r.driver_earnings AS "driverEarnings",
                    r.tegaara_commission AS "tegaaraCommission",
                    r.payment_method AS "paymentMethod",
                    r.payment_status AS "paymentStatus",
                    r.status,
                    r.ride_type AS "rideType",
                    r.requested_at AS "requestedAt",
                    p.full_name AS "passengerName",
                    p.profile_photo_url AS "passengerPhotoUrl"
                FROM public.rides r
                LEFT JOIN public.passengers p ON p.id = r.passenger_id
                WHERE r.id = $1::integer
                LIMIT 1
                `,
                [rideId]
            );

            await client.query('COMMIT');

            const ride = rideResult.rows[0];
            console.log(`✅ Driver Firebase UID ${uid} accepted ride ${rideId}`);

            // Notify passenger
            const passengerTokenResult = await pool.query(
                `SELECT ft.token FROM fcm_tokens ft JOIN passengers p ON p.firebase_uid = ft.user_id WHERE p.id = $1 LIMIT 1`,
                [ride.passengerId]
            );
            const passengerToken = passengerTokenResult.rows[0]?.token;
            if (passengerToken) {
                const driverName = driver.full_name || 'Driver';
                await sendFcmNotification(
                    passengerToken,
                    'Ride Accepted',
                    `Your ride has been accepted by ${driverName}. They are on their way.`,
                    {
                        rideId: rideId.toString(),
                        driverName: driverName,
                        status: 'accepted',
                        pickupAddress: ride.pickupAddress || '',
                        destinationAddress: ride.destinationAddress || '',
                    }
                );
            }

            return res.status(200).json({
                success: true,
                ride,
                message: 'Ride accepted successfully.',
            });
        } catch (error) {
            try { await client.query('ROLLBACK'); } catch (_) { }
            console.error('❌ Accept ride error:', error);
            return res.status(500).json({ success: false, message: 'Server error while accepting ride.' });
        } finally {
            client.release();
        }
    }
);

// POST /driver/accept-ride (compatibility)
router.post(
    '/driver/accept-ride',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const client = await pool.connect();
        try {
            const rideId = Number(req.body?.rideId);
            if (!Number.isInteger(rideId) || rideId <= 0) {
                return res.status(400).json({ success: false, message: 'Invalid rideId.' });
            }

            const uid = getAuthenticatedUid(req);
            if (!uid) {
                return res.status(401).json({ success: false, message: 'Unauthenticated.' });
            }

            await client.query('BEGIN');

            const driverResult = await client.query(
                `SELECT uid, full_name, status, is_online, is_available FROM public.drivers WHERE uid = $1::text LIMIT 1`,
                [uid]
            );
            if (driverResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({ success: false, message: 'Driver profile not found.' });
            }
            const driver = driverResult.rows[0];
            if (driver.status !== 'approved' || !driver.is_online || !driver.is_available) {
                await client.query('ROLLBACK');
                return res.status(403).json({ success: false, message: 'Driver is not available.' });
            }

            const result = await client.query(
                `
                UPDATE public.rides
                SET
                    driver_id = $1::text,
                    status = 'accepted',
                    driver_earnings = ROUND((fare * 0.80)::numeric, 2),
                    tegaara_commission = ROUND((fare * 0.20)::numeric, 2)
                WHERE id = $2::integer
                  AND status = 'requested'
                  AND driver_id IS NULL
                RETURNING id
                `,
                [uid, rideId]
            );
            if (result.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(409).json({ success: false, message: 'Ride already accepted or unavailable.' });
            }

            await client.query(`UPDATE public.drivers SET is_available = false WHERE uid = $1::text`, [uid]);

            const rideResult = await client.query(
                `
                SELECT
                    r.id AS "rideId",
                    r.passenger_id AS "passengerId",
                    r.driver_id AS "driverId",
                    r.pickup_address AS "pickupAddress",
                    r.destination_address AS "destinationAddress",
                    ST_Y(r.pickup) AS "pickupLat",
                    ST_X(r.pickup) AS "pickupLng",
                    ST_Y(r.destination) AS "destLat",
                    ST_X(r.destination) AS "destLng",
                    r.distance AS "distanceKm",
                    r.duration AS "durationMin",
                    r.fare,
                    r.driver_earnings AS "driverEarnings",
                    r.tegaara_commission AS "tegaaraCommission",
                    r.payment_method AS "paymentMethod",
                    r.payment_status AS "paymentStatus",
                    r.status,
                    r.ride_type AS "rideType",
                    r.requested_at AS "requestedAt",
                    p.full_name AS "passengerName",
                    p.profile_photo_url AS "passengerPhotoUrl"
                FROM public.rides r
                LEFT JOIN public.passengers p ON p.id = r.passenger_id
                WHERE r.id = $1::integer
                `,
                [rideId]
            );

            await client.query('COMMIT');

            const ride = rideResult.rows[0];
            // Notify passenger
            const passengerTokenResult = await pool.query(
                `SELECT ft.token FROM fcm_tokens ft JOIN passengers p ON p.firebase_uid = ft.user_id WHERE p.id = $1 LIMIT 1`,
                [ride.passengerId]
            );
            const passengerToken = passengerTokenResult.rows[0]?.token;
            if (passengerToken) {
                const driverName = driver.full_name || 'Driver';
                await sendFcmNotification(
                    passengerToken,
                    'Ride Accepted',
                    `Your ride has been accepted by ${driverName}. They are on their way.`,
                    {
                        rideId: rideId.toString(),
                        driverName: driverName,
                        status: 'accepted',
                        pickupAddress: ride.pickupAddress || '',
                        destinationAddress: ride.destinationAddress || '',
                    }
                );
            }

            return res.status(200).json({
                success: true,
                ride: ride,
                message: 'Ride accepted successfully.',
            });
        } catch (error) {
            try { await client.query('ROLLBACK'); } catch (_) { }
            console.error('❌ Compatibility accept error:', error);
            return res.status(500).json({ success: false, message: 'Server error while accepting ride.' });
        } finally {
            client.release();
        }
    }
);

// POST /driver/decline-ride
router.post(
    '/driver/decline-ride',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const rideId = Number(req.body?.rideId);
            if (!Number.isInteger(rideId) || rideId <= 0) {
                return res.status(400).json({ success: false, message: 'Invalid ride ID.' });
            }
            const uid = getAuthenticatedUid(req);
            if (!uid) {
                return res.status(401).json({ success: false, message: 'Unauthenticated.' });
            }
            console.log(`ℹ️ Driver ${uid} declined ride ${rideId}`);
            return res.status(200).json({ success: true, rideId, message: 'Ride declined.' });
        } catch (error) {
            console.error('❌ Decline ride error:', error);
            return res.status(500).json({ success: false, message: 'Server error while declining ride.' });
        }
    }
);

// GET /drivers/:uid/current-request
router.get(
    '/drivers/:uid/current-request',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const authenticatedUid = getAuthenticatedUid(req);
            if (!authenticatedUid) {
                return res.status(401).json({ success: false, message: 'Unauthenticated.' });
            }
            const requestedUid = req.params.uid;
            if (requestedUid !== authenticatedUid) {
                return res.status(403).json({ success: false, message: 'UID mismatch.' });
            }

            const driverResult = await pool.query(
                `SELECT uid, full_name, status FROM public.drivers WHERE uid = $1::text LIMIT 1`,
                [authenticatedUid]
            );
            if (driverResult.rows.length === 0) {
                return res.status(404).json({ success: false, message: 'Driver not found.' });
            }

            const rideResult = await pool.query(
                `
                SELECT
                    r.id AS "rideId",
                    r.passenger_id AS "passengerId",
                    r.driver_id AS "driverId",
                    r.pickup_address AS "pickupAddress",
                    r.destination_address AS "destinationAddress",
                    ST_Y(r.pickup) AS "pickupLat",
                    ST_X(r.pickup) AS "pickupLng",
                    ST_Y(r.destination) AS "destLat",
                    ST_X(r.destination) AS "destLng",
                    r.distance AS "distanceKm",
                    r.duration AS "durationMin",
                    r.fare,
                    r.driver_earnings AS "driverEarnings",
                    r.tegaara_commission AS "tegaaraCommission",
                    r.payment_method AS "paymentMethod",
                    r.payment_status AS "paymentStatus",
                    r.status,
                    r.ride_type AS "rideType",
                    r.requested_at AS "requestedAt",
                    p.full_name AS "passengerName",
                    p.profile_photo_url AS "passengerPhotoUrl"
                FROM public.rides r
                LEFT JOIN public.passengers p ON p.id = r.passenger_id
                WHERE r.driver_id = $1::text
                  AND r.status IN ('accepted', 'started')
                ORDER BY r.requested_at DESC
                LIMIT 1
                `,
                [authenticatedUid]
            );

            if (rideResult.rows.length === 0) {
                return res.status(200).json({ success: true, ride: null });
            }
            const ride = rideResult.rows[0];
            return res.status(200).json({
                success: true,
                ride: {
                    ...ride,
                    passengerRating: 5.0,
                    passengerRides: 0,
                },
            });
        } catch (error) {
            console.error('❌ Current ride error:', error);
            return res.status(500).json({ success: false, message: 'Server error while fetching current ride.' });
        }
    }
);

// POST /driver/update-fcm-token (deprecated, kept for compatibility)
router.post(
    '/driver/update-fcm-token',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const fcmToken = req.body?.fcmToken;
            if (typeof fcmToken !== 'string' || !fcmToken.trim()) {
                return res.status(400).json({ success: false, message: 'Valid fcmToken is required.' });
            }
            const uid = getAuthenticatedUid(req);
            if (!uid) {
                return res.status(401).json({ success: false, message: 'Unauthenticated.' });
            }
            const result = await pool.query(
                `UPDATE public.drivers SET fcm_token = $1::text WHERE uid = $2::text RETURNING uid`,
                [fcmToken.trim(), uid]
            );
            if (result.rows.length === 0) {
                return res.status(404).json({ success: false, message: 'Driver profile not found.' });
            }
            return res.status(200).json({ success: true, message: 'FCM token updated successfully.' });
        } catch (error) {
            console.error('❌ FCM token error:', error);
            return res.status(500).json({ success: false, message: 'Server error updating FCM token.' });
        }
    }
);

// GET /rides/:rideId/status
router.get(
    '/rides/:rideId/status',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const rideId = Number(req.params.rideId);
            if (!Number.isInteger(rideId) || rideId <= 0) {
                return res.status(400).json({ success: false, message: 'Invalid ride ID.' });
            }
            const uid = getAuthenticatedUid(req);
            if (!uid) {
                return res.status(401).json({ success: false, message: 'Unauthenticated.' });
            }

            const result = await pool.query(
                `
                SELECT
                    r.id,
                    r.passenger_id,
                    r.driver_id,
                    r.fare,
                    r.payment_method,
                    r.payment_status,
                    r.status,
                    r.ride_type,
                    r.requested_at,
                    r.completed_at
                FROM public.rides r
                LEFT JOIN public.passengers p ON p.id = r.passenger_id
                WHERE r.id = $1::integer
                  AND (p.firebase_uid = $2::text OR r.driver_id = $2::text)
                LIMIT 1
                `,
                [rideId, uid]
            );
            if (result.rows.length === 0) {
                return res.status(404).json({ success: false, message: 'Ride not found.' });
            }
            return res.status(200).json({ success: true, ride: result.rows[0] });
        } catch (error) {
            console.error('❌ Ride status error:', error);
            return res.status(500).json({ success: false, message: 'Server error while fetching ride status.' });
        }
    }
);

// POST /rides/:rideId/start
router.post(
    '/rides/:rideId/start',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const rideId = Number(req.params.rideId);
            if (!Number.isInteger(rideId) || rideId <= 0) {
                return res.status(400).json({ success: false, message: 'Invalid ride ID.' });
            }
            const uid = getAuthenticatedUid(req);
            if (!uid) {
                return res.status(401).json({ success: false, message: 'Unauthenticated.' });
            }

            const result = await pool.query(
                `
                UPDATE public.rides
                SET status = 'started'
                WHERE id = $1::integer
                  AND driver_id = $2::text
                  AND status = 'accepted'
                RETURNING id, driver_id, status
                `,
                [rideId, uid]
            );
            if (result.rows.length === 0) {
                return res.status(409).json({ success: false, message: 'Ride not found or cannot be started.' });
            }
            return res.status(200).json({ success: true, ride: result.rows[0], message: 'Ride started successfully.' });
        } catch (error) {
            console.error('❌ Start ride error:', error);
            return res.status(500).json({ success: false, message: 'Server error while starting ride.' });
        }
    }
);

// POST /rides/:rideId/complete
router.post(
    '/rides/:rideId/complete',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const client = await pool.connect();
        try {
            const rideId = Number(req.params.rideId);
            if (!Number.isInteger(rideId) || rideId <= 0) {
                return res.status(400).json({ success: false, message: 'Invalid ride ID.' });
            }
            const uid = getAuthenticatedUid(req);
            if (!uid) {
                return res.status(401).json({ success: false, message: 'Unauthenticated.' });
            }

            await client.query('BEGIN');

            const result = await client.query(
                `
                UPDATE public.rides
                SET status = 'completed', completed_at = NOW()
                WHERE id = $1::integer
                  AND driver_id = $2::text
                  AND status = 'started'
                RETURNING id, driver_id, status, completed_at
                `,
                [rideId, uid]
            );
            if (result.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(409).json({ success: false, message: 'Ride not found or cannot be completed.' });
            }

            await client.query(`UPDATE public.drivers SET is_available = true WHERE uid = $1::text`, [uid]);
            await client.query('COMMIT');

            return res.status(200).json({ success: true, ride: result.rows[0], message: 'Ride completed successfully.' });
        } catch (error) {
            try { await client.query('ROLLBACK'); } catch (_) { }
            console.error('❌ Complete ride error:', error);
            return res.status(500).json({ success: false, message: 'Server error while completing ride.' });
        } finally {
            client.release();
        }
    }
);

// POST /rides/:rideId/cancel
router.post(
    '/rides/:rideId/cancel',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        try {
            const rideId = Number(req.params.rideId);
            if (!Number.isInteger(rideId) || rideId <= 0) {
                return res.status(400).json({ success: false, message: 'Invalid ride ID.' });
            }
            const uid = getAuthenticatedUid(req);
            if (!uid) {
                return res.status(401).json({ success: false, message: 'Unauthenticated.' });
            }

            const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim() : 'Not specified';

            const result = await pool.query(
                `
                UPDATE public.rides
                SET status = 'cancelled'
                WHERE id = $1::integer
                  AND status NOT IN ('completed', 'cancelled')
                  AND (
                      passenger_id = (SELECT p.id FROM public.passengers p WHERE p.firebase_uid = $2::text LIMIT 1)
                      OR driver_id = $2::text
                  )
                RETURNING id, driver_id, status
                `,
                [rideId, uid]
            );
            if (result.rows.length === 0) {
                return res.status(403).json({ success: false, message: 'Ride not found or cannot be cancelled.' });
            }

            const cancelledRide = result.rows[0];
            if (cancelledRide.driver_id) {
                await pool.query(`UPDATE public.drivers SET is_available = true WHERE uid = $1::text`, [cancelledRide.driver_id]);
            }

            console.log(`Ride ${rideId} cancelled by ${uid}. Reason: ${reason}`);
            return res.status(200).json({ success: true, ride: cancelledRide, message: 'Ride cancelled successfully.' });
        } catch (error) {
            console.error('❌ Cancel ride error:', error);
            return res.status(500).json({ success: false, message: 'Server error while cancelling ride.' });
        }
    }
);

export default router;
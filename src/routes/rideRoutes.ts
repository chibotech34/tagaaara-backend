import { Router, Request, Response, NextFunction } from 'express';
import pool from '../config/database';
import { firebaseAuth, firebaseMessaging } from '../config/firebase';

const router = Router();

/* ============================================================
   TYPES
============================================================ */

interface DecodedFirebaseToken {
    uid: string;
    email?: string;
    name?: string;
}

interface AuthenticatedRequest extends Request {
    decodedToken?: DecodedFirebaseToken;
}

interface LocationPoint {
    lat: number;
    lng: number;
}

/* ============================================================
   FIREBASE AUTH MIDDLEWARE
============================================================ */

const verifyFirebaseToken = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
            success: false,
            message: 'Missing or invalid Authorization header.',
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

        const firebaseError = error as {
            code?: string;
            message?: string;
        };

        if (firebaseError.code === 'auth/id-token-expired') {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token expired. Refresh authentication.',
                code: 'AUTH_TOKEN_EXPIRED',
            });
            return;
        }

        if (firebaseError.code === 'auth/id-token-revoked') {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token revoked. Sign in again.',
                code: 'AUTH_TOKEN_REVOKED',
            });
            return;
        }

        res.status(401).json({
            success: false,
            message: 'Firebase authentication failed.',
            code: 'AUTH_TOKEN_INVALID',
        });
    }
};

/* ============================================================
   HELPERS
============================================================ */

function getAuthenticatedUid(
    req: AuthenticatedRequest,
): string | null {
    return req.decodedToken?.uid ?? null;
}

function isValidLocation(value: unknown): value is LocationPoint {
    if (!value || typeof value !== 'object') {
        return false;
    }

    const location = value as Record<string, unknown>;

    const lat = Number(location.lat);
    const lng = Number(location.lng);

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
    if (value === null || value === undefined || value === '') {
        return fallback;
    }

    const number = Number(value);

    return Number.isFinite(number) ? number : fallback;
}

/* ============================================================
   GET NEARBY DRIVERS
============================================================ */

async function getNearbyDrivers(
    lat: number,
    lng: number,
    radiusMeters = 15000,
) {
    const query = `
        SELECT
            d.id,
            d.uid,
            d.full_name,
            d.fcm_token,
            d.current_latitude,
            d.current_longitude,
            d.vehicle_type,
            d.vehicle_model,
            d.vehicle_number
        FROM public.drivers d
        WHERE d.status = 'approved'
          AND d.is_online = true
          AND d.is_available = true
          AND d.current_latitude IS NOT NULL
          AND d.current_longitude IS NOT NULL
          AND ST_DWithin(
                ST_SetSRID(
                    ST_MakePoint(
                        d.current_longitude::double precision,
                        d.current_latitude::double precision
                    ),
                    4326
                )::geography,
                ST_SetSRID(
                    ST_MakePoint($1, $2),
                    4326
                )::geography,
                $3
          )
        ORDER BY ST_Distance(
            ST_SetSRID(
                ST_MakePoint(
                    d.current_longitude::double precision,
                    d.current_latitude::double precision
                ),
                4326
            )::geography,
            ST_SetSRID(
                ST_MakePoint($1, $2),
                4326
            )::geography
        )
        LIMIT 20
    `;

    const result = await pool.query(
        query,
        [lng, lat, radiusMeters],
    );

    return result.rows;
}

/* ============================================================
   SEND RIDE NOTIFICATION
============================================================ */

async function sendRideNotificationToDriver(
    driverFcmToken: string,
    rideData: Record<string, string>,
    passengerName: string,
    rideType: string,
): Promise<void> {
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

                notification: {
                    channelId: 'ride_requests',
                },
            },

            apns: {
                payload: {
                    aps: {
                        sound: 'default',
                    },
                },
            },
        });

        console.log(
            `✅ Ride notification sent to driver: ${driverFcmToken.substring(
                0,
                10,
            )}...`,
        );
    } catch (error) {
        console.error(
            '❌ FCM ride notification failed:',
            error,
        );
    }
}

/* ============================================================
   1. GET /rides/nearby
   Driver app uses this to find passenger ride requests.
============================================================ */

router.get(
    '/rides/nearby',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const lat = Number(req.query.lat);
            const lng = Number(req.query.lng);

            let radius = Number(req.query.radius);

            if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
                return res.status(400).json({
                    success: false,
                    message: 'Valid lat and lng are required.',
                });
            }

            if (!Number.isFinite(radius) || radius <= 0) {
                radius = 5000;
            }

            radius = Math.min(radius, 50000);

            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Unauthenticated.',
                });
            }

            /*
             * Make sure this Firebase user is actually a driver.
             */
            const driverResult = await pool.query(
                `
                SELECT
                    id,
                    status,
                    is_online,
                    is_available
                FROM public.drivers
                WHERE uid = $1
                LIMIT 1
                `,
                [uid],
            );

            if (driverResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver profile not found.',
                });
            }

            const driver = driverResult.rows[0];

            if (driver.status !== 'approved') {
                return res.status(403).json({
                    success: false,
                    message: 'Driver account is not approved.',
                });
            }

            if (!driver.is_online || !driver.is_available) {
                return res.status(200).json([]);
            }

            /*
             * IMPORTANT:
             * Only rides waiting for a driver are returned here.
             */
            const query = `
                SELECT
                    r.id,
                    r.passenger_id,
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
                        ST_SetSRID(
                            ST_MakePoint(
                                $2,
                                $1
                            ),
                            4326
                        )::geography
                    ) / 1000.0 AS distance_to_pickup

                FROM public.rides r

                INNER JOIN public.passengers p
                    ON p.id = r.passenger_id

                WHERE r.status = 'requested'
                  AND r.driver_id IS NULL

                  AND ST_DWithin(
                        r.pickup::geography,
                        ST_SetSRID(
                            ST_MakePoint(
                                $2,
                                $1
                            ),
                            4326
                        )::geography,
                        $3
                  )

                ORDER BY
                    distance_to_pickup ASC,
                    r.requested_at ASC

                LIMIT 20
            `;

            const result = await pool.query(
                query,
                [lat, lng, radius],
            );

            return res.status(200).json(result.rows);
        } catch (error: unknown) {
            console.error(
                '❌ Nearby rides error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message: 'Server error while finding nearby rides.',
            });
        }
    },
);

/* ============================================================
   2. POST /rides
   Passenger books a specific driver.

   IMPORTANT:
   This is the endpoint your Flutter ApiService.bookRide()
   currently calls.
============================================================ */

router.post(
    '/rides',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const {
                passenger_id,
                driver_id,
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

            /* ------------------------------------------------
               Validate passenger
            ------------------------------------------------ */

            const passengerId = Number(passenger_id);

            if (
                !Number.isInteger(passengerId) ||
                passengerId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message: 'A valid passenger_id is required.',
                });
            }

            /* ------------------------------------------------
               Validate locations
            ------------------------------------------------ */

            if (!isValidLocation(pickup)) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid pickup. Expected { lat, lng }.',
                });
            }

            if (!isValidLocation(destination)) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid destination. Expected { lat, lng }.',
                });
            }

            /* ------------------------------------------------
               Validate coordinates
            ------------------------------------------------ */

            const pickupLat = Number(pickup.lat);
            const pickupLng = Number(pickup.lng);

            const destinationLat = Number(destination.lat);
            const destinationLng = Number(destination.lng);

            /* ------------------------------------------------
               Validate Firebase user
            ------------------------------------------------ */

            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Unauthenticated.',
                });
            }

            /* ------------------------------------------------
               Verify passenger belongs to Firebase user
            ------------------------------------------------ */

            const passengerResult = await pool.query(
                `
                SELECT
                    id,
                    firebase_uid,
                    full_name
                FROM public.passengers
                WHERE id = $1
                  AND firebase_uid = $2
                LIMIT 1
                `,
                [passengerId, uid],
            );

            if (passengerResult.rows.length === 0) {
                return res.status(403).json({
                    success: false,
                    message:
                        'Passenger ID does not match authenticated user.',
                });
            }

            const passenger =
                passengerResult.rows[0];

            /* ------------------------------------------------
               Validate driver if supplied
            ------------------------------------------------ */

            let driver:
                | {
                    id: number;
                    uid: string;
                    full_name: string;
                    fcm_token: string | null;
                }
                | null = null;

            if (driver_id !== null && driver_id !== undefined) {
                const driverId = Number(driver_id);

                if (
                    !Number.isInteger(driverId) ||
                    driverId <= 0
                ) {
                    return res.status(400).json({
                        success: false,
                        message: 'Invalid driver_id.',
                    });
                }

                const driverResult = await pool.query(
                    `
                    SELECT
                        id,
                        uid,
                        full_name,
                        fcm_token
                    FROM public.drivers
                    WHERE id = $1
                      AND status = 'approved'
                      AND is_online = true
                      AND is_available = true
                    LIMIT 1
                    `,
                    [driverId],
                );

                if (driverResult.rows.length === 0) {
                    return res.status(409).json({
                        success: false,
                        message:
                            'Driver is no longer available.',
                    });
                }

                driver = driverResult.rows[0];
            }

            /* ------------------------------------------------
               Prevent duplicate active rides
            ------------------------------------------------ */

            const activeRideResult = await pool.query(
                `
                SELECT id
                FROM public.rides
                WHERE passenger_id = $1
                  AND status IN (
                      'requested',
                      'accepted',
                      'started'
                  )
                ORDER BY requested_at DESC
                LIMIT 1
                `,
                [passengerId],
            );

            if (activeRideResult.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    message:
                        'You already have an active ride.',
                    rideId:
                        activeRideResult.rows[0].id,
                });
            }

            /* ------------------------------------------------
               Clean numeric values
            ------------------------------------------------ */

            const rideDistance =
                toNumber(distance, null);

            const rideDuration =
                toNumber(duration, null);

            const rideFare =
                toNumber(fare, 0) ?? 0;

            if (rideFare < 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Fare cannot be negative.',
                });
            }

            const rideType =
                typeof ride_type === 'string' &&
                    ride_type.trim().length > 0
                    ? ride_type.trim()
                    : 'standard';

            const paymentMethod =
                typeof payment_method === 'string' &&
                    payment_method.trim().length > 0
                    ? payment_method.trim()
                    : 'standard';

            /*
             * If a specific driver was selected:
             * status = accepted
             *
             * Otherwise:
             * status = requested
             */

            const rideStatus =
                driver !== null
                    ? 'accepted'
                    : 'requested';

            /* ------------------------------------------------
               CREATE RIDE
               
               IMPORTANT:
               No JavaScript // comments exist inside SQL.
               
               pickup/destination are geometry(Point,4326)
               in your database.
            ------------------------------------------------ */

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
                    ST_SetSRID(
                        ST_MakePoint($3, $4),
                        4326
                    ),
                    ST_SetSRID(
                        ST_MakePoint($5, $6),
                        4326
                    ),
                    $7,
                    $8,
                    $9,
                    $10,
                    'pending',
                    $11,
                    $12,
                    $13,
                    $14,
                    CASE
                        WHEN $2 IS NOT NULL
                        THEN ROUND(($9 * 0.80)::numeric, 2)
                        ELSE NULL
                    END,
                    CASE
                        WHEN $2 IS NOT NULL
                        THEN ROUND(($9 * 0.20)::numeric, 2)
                        ELSE NULL
                    END,
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
                    passengerId,
                    driver?.id ?? null,

                    pickupLng,
                    pickupLat,

                    destinationLng,
                    destinationLat,

                    rideDistance,
                    rideDuration,
                    rideFare,

                    paymentMethod,
                    rideStatus,
                    rideType,

                    pickup_address ?? null,
                    destination_address ?? null,
                ],
            );

            if (insertResult.rows.length === 0) {
                throw new Error(
                    'Ride was not inserted.',
                );
            }

            const ride = insertResult.rows[0];

            const rideId = ride.id;

            console.log(
                `✅ Ride ${rideId} created successfully.`,
            );

            /* ------------------------------------------------
               Notify selected driver
            ------------------------------------------------ */

            if (
                driver &&
                driver.fcm_token
            ) {
                const notificationPayload = {
                    rideId: String(rideId),

                    passengerId:
                        String(passengerId),

                    passengerName:
                        passenger.full_name ||
                        'Passenger',

                    pickupAddress:
                        pickup_address ||
                        'Pickup location',

                    pickupLat:
                        String(pickupLat),

                    pickupLng:
                        String(pickupLng),

                    destinationAddress:
                        destination_address ||
                        'Destination',

                    destLat:
                        String(destinationLat),

                    destLng:
                        String(destinationLng),

                    rideType:
                        rideType,

                    distanceKm:
                        String(
                            rideDistance ?? 0,
                        ),

                    durationMin:
                        String(
                            rideDuration ?? 0,
                        ),

                    fare:
                        String(rideFare),

                    driverEarnings:
                        (
                            rideFare * 0.8
                        ).toFixed(2),
                };

                await sendRideNotificationToDriver(
                    driver.fcm_token,
                    notificationPayload,
                    passenger.full_name ||
                    'Passenger',
                    rideType,
                );
            }

            /* ------------------------------------------------
               Response
            ------------------------------------------------ */

            return res.status(201).json({
                success: true,

                rideId: rideId,

                ride: {
                    ...ride,

                    pickup: {
                        lat: pickupLat,
                        lng: pickupLng,
                    },

                    destination: {
                        lat: destinationLat,
                        lng: destinationLng,
                    },
                },

                message:
                    driver !== null
                        ? 'Ride booked successfully. Driver has been notified.'
                        : 'Ride request created successfully.',
            });
        } catch (error: unknown) {
            console.error(
                '❌ RIDE CREATION ERROR',
            );

            console.error(error);

            const dbError = error as {
                code?: string;
                detail?: string;
                hint?: string;
                message?: string;
            };

            console.error(
                'Database code:',
                dbError.code,
            );

            console.error(
                'Database message:',
                dbError.message,
            );

            console.error(
                'Database detail:',
                dbError.detail,
            );

            console.error(
                'Database hint:',
                dbError.hint,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while creating ride.',
                error:
                    process.env.NODE_ENV ===
                        'development'
                        ? dbError.message
                        : undefined,
            });
        }
    },
);

/* ============================================================
   3. POST /rides/request
   Alternative endpoint used by older Flutter booking code.
============================================================ */

router.post(
    '/rides/request',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
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

            if (!driver_id) {
                return res.status(400).json({
                    success: false,
                    message:
                        'driver_id is required.',
                });
            }

            if (!isValidLocation(pickup)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid pickup.',
                });
            }

            if (!isValidLocation(destination)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid destination.',
                });
            }

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Unauthenticated.',
                });
            }

            /* --------------------------------------------
               Find passenger from Firebase UID
            -------------------------------------------- */

            const passengerResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        full_name
                    FROM public.passengers
                    WHERE firebase_uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                passengerResult.rows.length === 0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger profile not found.',
                });
            }

            const passenger =
                passengerResult.rows[0];

            /* --------------------------------------------
               Verify driver
            -------------------------------------------- */

            const driverResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        uid,
                        full_name,
                        fcm_token
                    FROM public.drivers
                    WHERE id = $1
                      AND status = 'approved'
                      AND is_online = true
                      AND is_available = true
                    LIMIT 1
                    `,
                    [Number(driver_id)],
                );

            if (
                driverResult.rows.length === 0
            ) {
                return res.status(409).json({
                    success: false,
                    message:
                        'Driver is no longer available.',
                });
            }

            const driver =
                driverResult.rows[0];

            /* --------------------------------------------
               Prevent duplicate ride
            -------------------------------------------- */

            const activeRide =
                await pool.query(
                    `
                    SELECT id
                    FROM public.rides
                    WHERE passenger_id = $1
                      AND status IN (
                          'requested',
                          'accepted',
                          'started'
                      )
                    LIMIT 1
                    `,
                    [passenger.id],
                );

            if (activeRide.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    message:
                        'Passenger already has an active ride.',
                    rideId:
                        activeRide.rows[0].id,
                });
            }

            const fare =
                toNumber(
                    estimated_fare,
                    0,
                ) ?? 0;

            const rideType =
                typeof ride_type === 'string' &&
                    ride_type.trim()
                    ? ride_type.trim()
                    : 'standard';

            /* --------------------------------------------
               Insert
            -------------------------------------------- */

            const result =
                await pool.query(
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
                        ST_SetSRID(
                            ST_MakePoint($3, $4),
                            4326
                        ),
                        ST_SetSRID(
                            ST_MakePoint($5, $6),
                            4326
                        ),
                        NULL,
                        NULL,
                        $7,
                        'standard',
                        'pending',
                        'accepted',
                        $8,
                        $9,
                        $10,
                        ROUND(($7 * 0.80)::numeric, 2),
                        ROUND(($7 * 0.20)::numeric, 2),
                        NOW()
                    )
                    RETURNING id
                    `,
                    [
                        passenger.id,
                        driver.id,

                        pickup.lng,
                        pickup.lat,

                        destination.lng,
                        destination.lat,

                        fare,
                        rideType,

                        pickup_address ??
                        null,

                        destination_address ??
                        null,
                    ],
                );

            const rideId =
                result.rows[0].id;

            /* --------------------------------------------
               Notify driver
            -------------------------------------------- */

            if (driver.fcm_token) {
                await sendRideNotificationToDriver(
                    driver.fcm_token,
                    {
                        rideId:
                            String(rideId),

                        passengerId:
                            String(passenger.id),

                        passengerName:
                            passenger.full_name ||
                            'Passenger',

                        pickupAddress:
                            pickup_address ||
                            'Pickup location',

                        pickupLat:
                            String(
                                pickup.lat,
                            ),

                        pickupLng:
                            String(
                                pickup.lng,
                            ),

                        destinationAddress:
                            destination_address ||
                            'Destination',

                        destLat:
                            String(
                                destination.lat,
                            ),

                        destLng:
                            String(
                                destination.lng,
                            ),

                        rideType,

                        distanceKm: '0',

                        durationMin: '0',

                        fare:
                            String(fare),

                        driverEarnings:
                            (
                                fare * 0.8
                            ).toFixed(2),
                    },

                    passenger.full_name ||
                    'Passenger',

                    rideType,
                );
            }

            return res.status(201).json({
                success: true,
                rideId,
                message:
                    'Ride requested successfully.',
            });
        } catch (error: unknown) {
            console.error(
                '❌ /rides/request error:',
                error,
            );

            const dbError = error as {
                code?: string;
                message?: string;
                detail?: string;
            };

            console.error(
                'DB code:',
                dbError.code,
            );

            console.error(
                'DB message:',
                dbError.message,
            );

            console.error(
                'DB detail:',
                dbError.detail,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while requesting ride.',
            });
        }
    },
);

/* ============================================================
   4. DRIVER ACCEPTS A BROADCASTED RIDE
   POST /rides/:rideId/accept

   This version gets the driver ID from Firebase UID.
   Flutter does NOT need to send driver_id.
============================================================ */

router.post(
    '/rides/:rideId/accept',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const rideId =
                Number(req.params.rideId);

            if (
                !Number.isInteger(rideId) ||
                rideId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid ride ID.',
                });
            }

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            /* --------------------------------------------
               Get driver from Firebase UID
            -------------------------------------------- */

            const driverResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        full_name
                    FROM public.drivers
                    WHERE uid = $1
                      AND status = 'approved'
                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                driverResult.rows.length === 0
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        'Driver profile not found or not approved.',
                });
            }

            const driver =
                driverResult.rows[0];

            /* --------------------------------------------
               Atomically accept ride
            -------------------------------------------- */

            const updateResult =
                await pool.query(
                    `
                    UPDATE public.rides
                    SET
                        driver_id = $1,
                        status = 'accepted',
                        driver_earnings =
                            ROUND(
                                (fare * 0.80)::numeric,
                                2
                            ),
                        tegaara_commission =
                            ROUND(
                                (fare * 0.20)::numeric,
                                2
                            )
                    WHERE id = $2
                      AND status = 'requested'
                      AND driver_id IS NULL
                    RETURNING
                        id,
                        passenger_id,
                        driver_id,
                        status,
                        fare,
                        driver_earnings,
                        tegaara_commission
                    `,
                    [
                        driver.id,
                        rideId,
                    ],
                );

            if (
                updateResult.rows.length === 0
            ) {
                return res.status(409).json({
                    success: false,
                    message:
                        'Ride has already been accepted or is no longer available.',
                });
            }

            /* --------------------------------------------
               Driver becomes unavailable
            -------------------------------------------- */

            await pool.query(
                `
                UPDATE public.drivers
                SET is_available = false
                WHERE id = $1
                `,
                [driver.id],
            );

            const ride =
                updateResult.rows[0];

            console.log(
                `✅ Driver ${driver.id} accepted ride ${rideId}`,
            );

            return res.status(200).json({
                success: true,
                ride,
                message:
                    'Ride accepted successfully.',
            });
        } catch (error: unknown) {
            console.error(
                '❌ Accept ride error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while accepting ride.',
            });
        }
    },
);

/* ============================================================
   5. POST /driver/accept-ride
   Compatibility endpoint.
============================================================ */

router.post(
    '/driver/accept-ride',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const {
                rideId,
                driverId,
            } = req.body;

            const parsedRideId =
                Number(rideId);

            if (
                !Number.isInteger(
                    parsedRideId,
                ) ||
                parsedRideId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid rideId.',
                });
            }

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            let actualDriverId: number;

            if (driverId) {
                actualDriverId =
                    Number(driverId);
            } else {
                const driverResult =
                    await pool.query(
                        `
                        SELECT id
                        FROM public.drivers
                        WHERE uid = $1
                        LIMIT 1
                        `,
                        [uid],
                    );

                if (
                    driverResult.rows.length ===
                    0
                ) {
                    return res.status(404).json({
                        success: false,
                        message:
                            'Driver profile not found.',
                    });
                }

                actualDriverId =
                    driverResult.rows[0].id;
            }

            /* Verify driver belongs to user */

            const ownershipResult =
                await pool.query(
                    `
                    SELECT id
                    FROM public.drivers
                    WHERE id = $1
                      AND uid = $2
                    LIMIT 1
                    `,
                    [
                        actualDriverId,
                        uid,
                    ],
                );

            if (
                ownershipResult.rows.length ===
                0
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        'Driver does not belong to authenticated user.',
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE public.rides
                    SET
                        driver_id = $1,
                        status = 'accepted',
                        driver_earnings =
                            ROUND(
                                (fare * 0.80)::numeric,
                                2
                            ),
                        tegaara_commission =
                            ROUND(
                                (fare * 0.20)::numeric,
                                2
                            )
                    WHERE id = $2
                      AND status = 'requested'
                      AND driver_id IS NULL
                    RETURNING
                        id,
                        passenger_id,
                        driver_id,
                        status
                    `,
                    [
                        actualDriverId,
                        parsedRideId,
                    ],
                );

            if (result.rows.length === 0) {
                return res.status(409).json({
                    success: false,
                    message:
                        'Ride already accepted or no longer available.',
                });
            }

            await pool.query(
                `
                UPDATE public.drivers
                SET is_available = false
                WHERE id = $1
                `,
                [actualDriverId],
            );

            return res.status(200).json({
                success: true,
                ride: result.rows[0],
                message:
                    'Ride accepted successfully.',
            });
        } catch (error) {
            console.error(
                '❌ Driver accept error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while accepting ride.',
            });
        }
    },
);

/* ============================================================
   6. DRIVER DECLINES RIDE
============================================================ */

router.post(
    '/driver/decline-ride',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        return res.status(200).json({
            success: true,
            message: 'Ride declined.',
        });
    },
);

/* ============================================================
   7. DRIVER CURRENT ACTIVE RIDE
   GET /drivers/:uid/current-request
============================================================ */

router.get(
    '/drivers/:uid/current-request',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            if (req.params.uid !== uid) {
                return res.status(403).json({
                    success: false,
                    message:
                        'UID mismatch.',
                });
            }

            /* --------------------------------------------
               Find driver
            -------------------------------------------- */

            const driverResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        full_name
                    FROM public.drivers
                    WHERE uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                driverResult.rows.length === 0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Driver not found.',
                });
            }

            const driverId =
                driverResult.rows[0].id;

            /* --------------------------------------------
               Find active ride
            -------------------------------------------- */

            const rideResult =
                await pool.query(
                    `
                    SELECT
                        r.id AS "rideId",

                        r.passenger_id AS "passengerId",

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

                    LEFT JOIN public.passengers p
                        ON p.id = r.passenger_id

                    WHERE r.driver_id = $1
                      AND r.status IN (
                          'accepted',
                          'started'
                      )

                    ORDER BY r.requested_at DESC

                    LIMIT 1
                    `,
                    [driverId],
                );

            if (
                rideResult.rows.length === 0
            ) {
                return res.status(200).json({
                    success: true,
                    ride: null,
                });
            }

            const ride =
                rideResult.rows[0];

            return res.status(200).json({
                success: true,

                ride: {
                    ...ride,

                    passengerRating: 5.0,

                    passengerRides: 0,
                },
            });
        } catch (error) {
            console.error(
                '❌ Current ride error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while fetching current ride.',
            });
        }
    },
);

/* ============================================================
   8. UPDATE DRIVER FCM TOKEN
============================================================ */

router.post(
    '/driver/update-fcm-token',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const {
                fcmToken,
            } = req.body;

            if (
                typeof fcmToken !== 'string' ||
                !fcmToken.trim()
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Valid fcmToken is required.',
                });
            }

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE public.drivers
                    SET
                        fcm_token = $1
                    WHERE uid = $2
                    RETURNING id
                    `,
                    [
                        fcmToken.trim(),
                        uid,
                    ],
                );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Driver profile not found.',
                });
            }

            return res.status(200).json({
                success: true,
                message:
                    'FCM token updated successfully.',
            });
        } catch (error) {
            console.error(
                '❌ FCM token error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error updating FCM token.',
            });
        }
    },
);

/* ============================================================
   9. GET RIDE STATUS
============================================================ */

router.get(
    '/rides/:rideId/status',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const rideId =
                Number(req.params.rideId);

            if (
                !Number.isInteger(rideId) ||
                rideId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid ride ID.',
                });
            }

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        passenger_id,
                        driver_id,
                        fare,
                        payment_method,
                        payment_status,
                        status,
                        ride_type,
                        requested_at,
                        completed_at
                    FROM public.rides
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [rideId],
                );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Ride not found.',
                });
            }

            return res.status(200).json({
                success: true,
                ride: result.rows[0],
            });
        } catch (error) {
            console.error(
                '❌ Ride status error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while fetching ride status.',
            });
        }
    },
);

/* ============================================================
   10. START RIDE
============================================================ */

router.post(
    '/rides/:rideId/start',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const rideId =
                Number(req.params.rideId);

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE public.rides r
                    SET
                        status = 'started'
                    FROM public.drivers d
                    WHERE r.id = $1
                      AND r.driver_id = d.id
                      AND d.uid = $2
                      AND r.status = 'accepted'
                    RETURNING
                        r.id,
                        r.status
                    `,
                    [
                        rideId,
                        uid,
                    ],
                );

            if (result.rows.length === 0) {
                return res.status(409).json({
                    success: false,
                    message:
                        'Ride not found or cannot be started.',
                });
            }

            return res.status(200).json({
                success: true,
                ride: result.rows[0],
                message:
                    'Ride started successfully.',
            });
        } catch (error) {
            console.error(
                '❌ Start ride error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while starting ride.',
            });
        }
    },
);

/* ============================================================
   11. COMPLETE RIDE
============================================================ */

router.post(
    '/rides/:rideId/complete',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const rideId =
                Number(req.params.rideId);

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE public.rides r
                    SET
                        status = 'completed',
                        completed_at = NOW()
                    FROM public.drivers d
                    WHERE r.id = $1
                      AND r.driver_id = d.id
                      AND d.uid = $2
                      AND r.status = 'started'
                    RETURNING
                        r.id,
                        r.status,
                        r.completed_at
                    `,
                    [
                        rideId,
                        uid,
                    ],
                );

            if (result.rows.length === 0) {
                return res.status(409).json({
                    success: false,
                    message:
                        'Ride not found or cannot be completed.',
                });
            }

            /* Driver is available again */

            await pool.query(
                `
                UPDATE public.drivers
                SET
                    is_available = true
                WHERE uid = $1
                `,
                [uid],
            );

            return res.status(200).json({
                success: true,
                ride: result.rows[0],
                message:
                    'Ride completed successfully.',
            });
        } catch (error) {
            console.error(
                '❌ Complete ride error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while completing ride.',
            });
        }
    },
);

/* ============================================================
   12. CANCEL RIDE
============================================================ */

router.post(
    '/rides/:rideId/cancel',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const rideId =
                Number(req.params.rideId);

            const {
                reason,
            } = req.body;

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE public.rides r
                    SET
                        status = 'cancelled'
                    WHERE r.id = $1
                      AND r.status NOT IN (
                          'completed',
                          'cancelled'
                      )
                      AND (
                          r.passenger_id = (
                              SELECT p.id
                              FROM public.passengers p
                              WHERE p.firebase_uid = $2
                              LIMIT 1
                          )
                          OR
                          r.driver_id = (
                              SELECT d.id
                              FROM public.drivers d
                              WHERE d.uid = $2
                              LIMIT 1
                          )
                      )
                    RETURNING
                        r.id,
                        r.driver_id,
                        r.status
                    `,
                    [
                        rideId,
                        uid,
                    ],
                );

            if (result.rows.length === 0) {
                return res.status(403).json({
                    success: false,
                    message:
                        'Ride not found or cannot be cancelled.',
                });
            }

            /* --------------------------------------------
               If driver cancelled, make driver available
            -------------------------------------------- */

            const cancelledRide =
                result.rows[0];

            if (cancelledRide.driver_id) {
                await pool.query(
                    `
                    UPDATE public.drivers
                    SET
                        is_available = true
                    WHERE id = $1
                    `,
                    [
                        cancelledRide.driver_id,
                    ],
                );
            }

            console.log(
                `Ride ${rideId} cancelled. Reason: ${reason || 'Not specified'
                }`,
            );

            return res.status(200).json({
                success: true,
                ride: cancelledRide,
                message:
                    'Ride cancelled successfully.',
            });
        } catch (error) {
            console.error(
                '❌ Cancel ride error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while cancelling ride.',
            });
        }
    },
);

/* ============================================================
   EXPORT
============================================================ */

export default router;
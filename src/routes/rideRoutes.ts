import {
    Router,
    Request,
    Response,
    NextFunction,
} from 'express';

import pool from '../config/database';

import {
    firebaseAuth,
    firebaseMessaging,
} from '../config/firebase';

const router = Router();

/*
|--------------------------------------------------------------------------
| TYPES
|--------------------------------------------------------------------------
*/

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

/*
|--------------------------------------------------------------------------
| FIREBASE AUTHENTICATION
|--------------------------------------------------------------------------
*/

const verifyFirebaseToken = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (
        !authHeader ||
        !authHeader.startsWith('Bearer ')
    ) {
        res.status(401).json({
            success: false,
            message: 'Missing or invalid Authorization header.',
            code: 'AUTH_HEADER_MISSING',
        });

        return;
    }

    const token = authHeader
        .substring(7)
        .trim();

    if (!token) {
        res.status(401).json({
            success: false,
            message: 'Firebase ID token is missing.',
            code: 'AUTH_TOKEN_MISSING',
        });

        return;
    }

    try {
        const decodedToken =
            await firebaseAuth.verifyIdToken(token);

        req.decodedToken = {
            uid: decodedToken.uid,
            email: decodedToken.email,
            name: decodedToken.name,
        };

        next();
    } catch (error: unknown) {
        console.error(
            '❌ Firebase token verification failed:',
            error,
        );

        const firebaseError = error as {
            code?: string;
            message?: string;
        };

        if (
            firebaseError.code ===
            'auth/id-token-expired'
        ) {
            res.status(401).json({
                success: false,
                message:
                    'Firebase ID token expired. Refresh authentication.',
                code: 'AUTH_TOKEN_EXPIRED',
            });

            return;
        }

        if (
            firebaseError.code ===
            'auth/id-token-revoked'
        ) {
            res.status(401).json({
                success: false,
                message:
                    'Firebase ID token revoked. Sign in again.',
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

/*
|--------------------------------------------------------------------------
| HELPERS
|--------------------------------------------------------------------------
*/

function getAuthenticatedUid(
    req: AuthenticatedRequest,
): string | null {
    return req.decodedToken?.uid ?? null;
}

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
        value as Record<string, unknown>;

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
    if (
        value === null ||
        value === undefined ||
        value === ''
    ) {
        return fallback;
    }

    const number = Number(value);

    return Number.isFinite(number)
        ? number
        : fallback;
}

/*
|--------------------------------------------------------------------------
| SEND RIDE NOTIFICATION
|--------------------------------------------------------------------------
*/

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
                body:
                    `${passengerName} wants a ride (${rideType})`,
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
            `✅ Ride notification sent to driver: ${driverFcmToken.substring(0, 10)}...`,
        );
    } catch (error) {
        console.error(
            '❌ FCM ride notification failed:',
            error,
        );
    }
}

/*
|--------------------------------------------------------------------------
| POST /rides
|--------------------------------------------------------------------------
|
| Flutter sends:
|
| {
|   pickup: {lat, lng},
|   destination: {lat, lng},
|   distance,
|   duration,
|   fare,
|   ride_type,
|   payment_method,
|   pickup_address,
|   destination_address
| }
|
| Passenger is identified by Firebase UID.
|
|--------------------------------------------------------------------------
*/

router.post(
    '/rides',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            if (
                !req.body ||
                typeof req.body !== 'object'
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Request body is missing or invalid JSON.',
                    code:
                        'REQUEST_BODY_MISSING',
                });
            }

            console.log(
                '📦 /rides request body:',
                JSON.stringify(req.body),
            );

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

            /*
            |--------------------------------------------------------------------------
            | AUTHENTICATED PASSENGER
            |--------------------------------------------------------------------------
            */

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Unauthenticated.',
                });
            }

            const passengerResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        firebase_uid,
                        full_name,
                        profile_photo_url
                    FROM public.passengers
                    WHERE firebase_uid = $1::text
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

            /*
            |--------------------------------------------------------------------------
            | LOCATIONS
            |--------------------------------------------------------------------------
            */

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

            const pickupLat =
                Number(pickup.lat);

            const pickupLng =
                Number(pickup.lng);

            const destinationLat =
                Number(destination.lat);

            const destinationLng =
                Number(destination.lng);

            /*
            |--------------------------------------------------------------------------
            | ACTIVE RIDE CHECK
            |--------------------------------------------------------------------------
            */

            const activeRideResult =
                await pool.query(
                    `
                    SELECT id
                    FROM public.rides
                    WHERE passenger_id = $1::integer
                      AND status IN (
                          'requested',
                          'accepted',
                          'started'
                      )
                    ORDER BY requested_at DESC
                    LIMIT 1
                    `,
                    [passenger.id],
                );

            if (
                activeRideResult.rows.length > 0
            ) {
                return res.status(409).json({
                    success: false,
                    message:
                        'You already have an active ride.',
                    rideId:
                        activeRideResult.rows[0].id,
                });
            }

            /*
            |--------------------------------------------------------------------------
            | NUMERIC VALUES
            |--------------------------------------------------------------------------
            */

            const rideDistance =
                toNumber(distance, 0) ?? 0;

            const rawDuration =
                toNumber(duration, 0) ?? 0;

            const rideDuration =
                Math.round(rawDuration);

            const rideFare =
                toNumber(fare, 0) ?? 0;

            if (rideDistance < 0) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Distance cannot be negative.',
                });
            }

            if (rideDuration < 0) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Duration cannot be negative.',
                });
            }

            if (rideFare < 0) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Fare cannot be negative.',
                });
            }

            /*
            |--------------------------------------------------------------------------
            | RIDE TYPE
            |--------------------------------------------------------------------------
            */

            const rideType =
                typeof ride_type === 'string' &&
                    ride_type.trim()
                    ? ride_type.trim()
                    : 'standard';

            /*
            |--------------------------------------------------------------------------
            | PAYMENT
            |--------------------------------------------------------------------------
            */

            const paymentMethod =
                typeof payment_method === 'string' &&
                    payment_method.trim().length > 0
                    ? payment_method.trim()
                    : 'cash';

            /*
            |--------------------------------------------------------------------------
            | INSERT
            |--------------------------------------------------------------------------
            */

            const insertResult =
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
                        $1::integer,

                        NULL::bigint,

                        ST_SetSRID(
                            ST_MakePoint(
                                $2::double precision,
                                $3::double precision
                            ),
                            4326
                        ),

                        ST_SetSRID(
                            ST_MakePoint(
                                $4::double precision,
                                $5::double precision
                            ),
                            4326
                        ),

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
                    ],
                );

            if (
                insertResult.rows.length === 0
            ) {
                throw new Error(
                    'Ride was not inserted.',
                );
            }

            const ride =
                insertResult.rows[0];

            const rideId =
                ride.id;

            console.log(
                `✅ Ride ${rideId} created successfully for passenger ${passenger.id}.`,
            );

            /*
            |--------------------------------------------------------------------------
            | RESPONSE
            |--------------------------------------------------------------------------
            */

            return res.status(201).json({
                success: true,

                rideId,

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
                    'Ride request created successfully.',
            });
        } catch (error: unknown) {
            console.error(
                '❌ RIDE CREATION ERROR:',
                error,
            );

            const dbError = error as {
                code?: string;
                message?: string;
                detail?: string;
                hint?: string;
            };

            return res.status(500).json({
                success: false,
                message:
                    'Server error while creating ride.',
                code:
                    dbError.code ??
                    'RIDE_CREATION_ERROR',
                error:
                    dbError.message ??
                    'Unknown database error',
                detail:
                    dbError.detail ?? null,
                hint:
                    dbError.hint ?? null,
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| GET /rides/nearby
|--------------------------------------------------------------------------
*/

router.get(
    '/rides/nearby',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const lat =
                Number(req.query.lat);

            const lng =
                Number(req.query.lng);

            let radius =
                Number(req.query.radius);

            if (
                !Number.isFinite(lat) ||
                !Number.isFinite(lng)
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Valid lat and lng are required.',
                });
            }

            if (
                !Number.isFinite(radius) ||
                radius <= 0
            ) {
                radius = 5000;
            }

            radius = Math.min(
                radius,
                50000,
            );

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            const driverResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        status,
                        is_online,
                        is_available
                    FROM public.drivers
                    WHERE uid = $1::text
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
                        'Driver profile not found.',
                });
            }

            const driver =
                driverResult.rows[0];

            if (
                driver.status !== 'approved'
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        'Driver account is not approved.',
                });
            }

            if (
                !driver.is_online ||
                !driver.is_available
            ) {
                return res.status(200).json([]);
            }

            const result =
                await pool.query(
                    `
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
                                    $2::double precision,
                                    $1::double precision
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
                                    $2::double precision,
                                    $1::double precision
                                ),
                                4326
                            )::geography,
                            $3::double precision
                      )

                    ORDER BY
                        distance_to_pickup ASC,
                        r.requested_at ASC

                    LIMIT 20
                    `,
                    [
                        lat,
                        lng,
                        radius,
                    ],
                );

            return res.status(200).json(
                result.rows,
            );
        } catch (error) {
            console.error(
                '❌ Nearby rides error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while finding nearby rides.',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| DRIVER ACCEPT RIDE
|--------------------------------------------------------------------------
|
| POST /rides/:rideId/accept
|
| Firebase UID is the REAL driver identity.
| driverId from Flutter is NOT trusted.
|
|--------------------------------------------------------------------------
*/

router.post(
    '/rides/:rideId/accept',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        const client =
            await pool.connect();

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

            await client.query('BEGIN');

            /*
            |--------------------------------------------------------------------------
            | FIND AUTHENTICATED DRIVER
            |--------------------------------------------------------------------------
            */

            const driverResult =
                await client.query(
                    `
                    SELECT
                        id,
                        uid,
                        full_name,
                        status,
                        is_online,
                        is_available
                    FROM public.drivers
                    WHERE uid = $1::text
                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                driverResult.rows.length === 0
            ) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    success: false,
                    message:
                        'Driver profile not found.',
                });
            }

            const driver =
                driverResult.rows[0];

            if (
                driver.status !== 'approved'
            ) {
                await client.query('ROLLBACK');

                return res.status(403).json({
                    success: false,
                    message:
                        'Driver account is not approved.',
                });
            }

            if (
                !driver.is_online ||
                !driver.is_available
            ) {
                await client.query('ROLLBACK');

                return res.status(409).json({
                    success: false,
                    message:
                        'Driver is not currently available.',
                });
            }

            /*
            |--------------------------------------------------------------------------
            | ATOMIC ACCEPT
            |--------------------------------------------------------------------------
            */

            const updateResult =
                await client.query(
                    `
                    UPDATE public.rides
                    SET
                        driver_id = $1::bigint,

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

                    WHERE id = $2::integer

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
                await client.query('ROLLBACK');

                return res.status(409).json({
                    success: false,
                    message:
                        'Ride has already been accepted or is no longer available.',
                });
            }

            /*
            |--------------------------------------------------------------------------
            | DRIVER BECOMES UNAVAILABLE
            |--------------------------------------------------------------------------
            */

            await client.query(
                `
                UPDATE public.drivers
                SET is_available = false
                WHERE id = $1::bigint
                `,
                [driver.id],
            );

            await client.query('COMMIT');

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
        } catch (error) {
            await client.query('ROLLBACK');

            console.error(
                '❌ Accept ride error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while accepting ride.',
            });
        } finally {
            client.release();
        }
    },
);

/*
|--------------------------------------------------------------------------
| COMPATIBILITY ACCEPT ENDPOINT
|--------------------------------------------------------------------------
|
| Keeps older Flutter code working.
|
| POST /driver/accept-ride
|
|--------------------------------------------------------------------------
*/

router.post(
    '/driver/accept-ride',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const rideId =
                Number(req.body?.rideId);

            if (
                !Number.isInteger(rideId) ||
                rideId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid rideId.',
                });
            }

            /*
            |--------------------------------------------------------------------------
            | Internally use the canonical accept route logic.
            |--------------------------------------------------------------------------
            |
            | We do not trust driverId from the client.
            |
            */

            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            const driverResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        status,
                        is_online,
                        is_available
                    FROM public.drivers
                    WHERE uid = $1::text
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
                        'Driver profile not found.',
                });
            }

            const driver =
                driverResult.rows[0];

            if (
                driver.status !== 'approved'
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        'Driver account is not approved.',
                });
            }

            if (
                !driver.is_online ||
                !driver.is_available
            ) {
                return res.status(409).json({
                    success: false,
                    message:
                        'Driver is not available.',
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE public.rides
                    SET
                        driver_id = $1::bigint,
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
                    WHERE id = $2::integer
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
                result.rows.length === 0
            ) {
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
                WHERE id = $1::bigint
                `,
                [driver.id],
            );

            return res.status(200).json({
                success: true,
                ride: result.rows[0],
                message:
                    'Ride accepted successfully.',
            });
        } catch (error) {
            console.error(
                '❌ Compatibility accept error:',
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

/*
|--------------------------------------------------------------------------
| DRIVER DECLINE
|--------------------------------------------------------------------------
*/

router.post(
    '/driver/decline-ride',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const rideId =
                Number(req.body?.rideId);

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

            /*
            |--------------------------------------------------------------------------
            | This endpoint intentionally does not modify the ride.
            |
            | A driver declining simply means the driver does not accept it.
            | The ride remains requested for other drivers.
            |--------------------------------------------------------------------------
            */

            return res.status(200).json({
                success: true,
                rideId,
                message:
                    'Ride declined.',
            });
        } catch (error) {
            console.error(
                '❌ Decline ride error:',
                error,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while declining ride.',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| DRIVER CURRENT RIDE
|--------------------------------------------------------------------------
*/

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

            if (
                req.params.uid !== uid
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        'UID mismatch.',
                });
            }

            const driverResult =
                await pool.query(
                    `
                    SELECT id
                    FROM public.drivers
                    WHERE uid = $1::text
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

                    WHERE r.driver_id = $1::bigint

                      AND r.status IN (
                          'accepted',
                          'started'
                      )

                    ORDER BY
                        r.requested_at DESC

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

/*
|--------------------------------------------------------------------------
| UPDATE DRIVER FCM TOKEN
|--------------------------------------------------------------------------
*/

router.post(
    '/driver/update-fcm-token',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const fcmToken =
                req.body?.fcmToken;

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
                    SET fcm_token = $1::text
                    WHERE uid = $2::text
                    RETURNING id
                    `,
                    [
                        fcmToken.trim(),
                        uid,
                    ],
                );

            if (
                result.rows.length === 0
            ) {
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

/*
|--------------------------------------------------------------------------
| GET RIDE STATUS
|--------------------------------------------------------------------------
*/

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
                    WHERE id = $1::integer
                    LIMIT 1
                    `,
                    [rideId],
                );

            if (
                result.rows.length === 0
            ) {
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

/*
|--------------------------------------------------------------------------
| START RIDE
|--------------------------------------------------------------------------
*/

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

            const result =
                await pool.query(
                    `
                    UPDATE public.rides r

                    SET status = 'started'

                    FROM public.drivers d

                    WHERE r.id = $1::integer

                      AND r.driver_id = d.id

                      AND d.uid = $2::text

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

            if (
                result.rows.length === 0
            ) {
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

/*
|--------------------------------------------------------------------------
| COMPLETE RIDE
|--------------------------------------------------------------------------
*/

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

            const result =
                await pool.query(
                    `
                    UPDATE public.rides r

                    SET
                        status = 'completed',
                        completed_at = NOW()

                    FROM public.drivers d

                    WHERE r.id = $1::integer

                      AND r.driver_id = d.id

                      AND d.uid = $2::text

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

            if (
                result.rows.length === 0
            ) {
                return res.status(409).json({
                    success: false,
                    message:
                        'Ride not found or cannot be completed.',
                });
            }

            await pool.query(
                `
                UPDATE public.drivers
                SET is_available = true
                WHERE uid = $1::text
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

/*
|--------------------------------------------------------------------------
| CANCEL RIDE
|--------------------------------------------------------------------------
*/

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

            const reason =
                req.body?.reason ??
                'Not specified';

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

                    SET status = 'cancelled'

                    WHERE r.id = $1::integer

                      AND r.status NOT IN (
                          'completed',
                          'cancelled'
                      )

                      AND (
                          r.passenger_id = (
                              SELECT p.id
                              FROM public.passengers p
                              WHERE p.firebase_uid = $2::text
                              LIMIT 1
                          )

                          OR

                          r.driver_id = (
                              SELECT d.id
                              FROM public.drivers d
                              WHERE d.uid = $2::text
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

            if (
                result.rows.length === 0
            ) {
                return res.status(403).json({
                    success: false,
                    message:
                        'Ride not found or cannot be cancelled.',
                });
            }

            const cancelledRide =
                result.rows[0];

            if (
                cancelledRide.driver_id
            ) {
                await pool.query(
                    `
                    UPDATE public.drivers
                    SET is_available = true
                    WHERE id = $1::bigint
                    `,
                    [
                        cancelledRide.driver_id,
                    ],
                );
            }

            console.log(
                `Ride ${rideId} cancelled. Reason: ${reason}`,
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

export default router;
import { Router, Response } from 'express';
import pool from '../config/database';
import { firebaseMessaging } from '../config/firebase';
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
    req: AuthenticatedRequest
): string | null {
    const uid = req.decodedToken?.uid;

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
    value: unknown
): value is LocationPoint {
    if (!value || typeof value !== 'object') {
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
    fallback: number | null = null
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
| DRIVER AVAILABILITY HELPER
|--------------------------------------------------------------------------
*/

async function restoreDriverAvailability(
    client: any,
    driverUid: string
): Promise<void> {
    await client.query(
        `
        UPDATE public.drivers
        SET
            is_available =
                CASE
                    WHEN status = 'approved'
                     AND is_online = true
                    THEN true
                    ELSE false
                END,
            updated_at = NOW()
        WHERE uid = $1::text
        `,
        [driverUid]
    );
}

/*
|--------------------------------------------------------------------------
| FCM
|--------------------------------------------------------------------------
*/

async function sendFcmNotification(
    token: string,
    title: string,
    body: string,
    data: Record<string, string>
): Promise<void> {
    if (!token || !token.trim()) {
        return;
    }

    const enrichedData: Record<string, string> = {
        ...data,
        title,
        body,
    };

    try {
        await firebaseMessaging.send({
            token,

            notification: {
                title,
                body,
            },

            data: enrichedData,

            android: {
                priority: 'high',
                ttl: 60 * 1000,

                notification: {
                    channelId: 'tegaara_ride_channel',
                    priority: 'high' as const,
                    defaultSound: true,
                    defaultVibrateTimings: true,
                    defaultLightSettings: true,
                    clickAction:
                        'FLUTTER_NOTIFICATION_CLICK',
                },
            },

            apns: {
                headers: {
                    'apns-priority': '10',
                    'apns-push-type': 'alert',
                },

                payload: {
                    aps: {
                        alert: {
                            title,
                            body,
                        },
                        sound: 'default',
                        badge: 1,
                        contentAvailable: true,
                        mutableContent: true,
                    },
                },
            },
        });
    } catch (error: any) {
        if (
            error?.code ===
            'messaging/invalid-registration-token' ||
            error?.code ===
            'messaging/registration-token-not-registered'
        ) {
            try {
                await pool.query(
                    `
                    DELETE FROM public.fcm_tokens
                    WHERE token = $1
                    `,
                    [token]
                );
            } catch (deleteError) {
                console.error(
                    '❌ Failed deleting invalid FCM token:',
                    deleteError
                );
            }
        }

        console.error(
            '❌ FCM notification error:',
            error
        );
    }
}

/*
|--------------------------------------------------------------------------
| Notify Nearby Drivers
|--------------------------------------------------------------------------
*/

async function notifyNearbyDrivers(
    rideId: number,
    pickupLat: number,
    pickupLng: number,
    rideData: {
        passenger_name?: string;
        pickup_address?: string;
        destination_address?: string;
        fare?: number;
        ride_type?: string;
    }
): Promise<void> {
    try {
        const radiusMeters = 5000;

        const result = await pool.query(
            `
            SELECT DISTINCT
                d.uid,
                ft.token
            FROM public.drivers d

            INNER JOIN public.driver_wallets dw
                ON dw.driver_id = d.id
               AND dw.balance >= dw.minimum_balance

            INNER JOIN public.fcm_tokens ft
                ON ft.user_id = d.uid

            WHERE d.is_online = true
              AND d.is_available = true
              AND d.status = 'approved'
              AND ft.token IS NOT NULL
              AND ST_DWithin(
                    d.location::geography,
                    ST_SetSRID(
                        ST_MakePoint(
                            $1::double precision,
                            $2::double precision
                        ),
                        4326
                    )::geography,
                    $3::double precision
              )
            `,
            [
                pickupLng,
                pickupLat,
                radiusMeters,
            ]
        );

        const tokens = result.rows
            .map((row) => row.token)
            .filter(
                (token): token is string =>
                    typeof token === 'string' &&
                    token.trim().length > 0
            );

        if (tokens.length === 0) {
            console.log(
                `ℹ️ No nearby funded drivers with FCM tokens for ride ${rideId}`
            );
            return;
        }

        const title = 'New Ride Request';

        const body =
            `${rideData.passenger_name || 'A passenger'} ` +
            `needs a ride from ` +
            `${rideData.pickup_address || 'your area'}`;

        const dataPayload = {
            role: 'driver',
            notificationType: 'ride_request',
            targetScreen: 'driver_home',

            rideId: String(rideId),

            passengerName:
                rideData.passenger_name ||
                'Passenger',

            pickupLat:
                String(pickupLat),

            pickupLng:
                String(pickupLng),

            pickupAddress:
                rideData.pickup_address ||
                '',

            destinationAddress:
                rideData.destination_address ||
                '',

            fare:
                String(rideData.fare ?? 0),

            rideType:
                rideData.ride_type ||
                'standard',

            status: 'requested',
        };

        const response =
            await firebaseMessaging
                .sendEachForMulticast({
                    tokens,

                    notification: {
                        title,
                        body,
                    },

                    data: {
                        ...dataPayload,
                        title,
                        body,
                    },

                    android: {
                        priority: 'high',
                        ttl: 60 * 1000,

                        notification: {
                            channelId:
                                'tegaara_ride_channel',
                            priority: 'high',
                            defaultSound: true,
                            defaultVibrateTimings:
                                true,
                            defaultLightSettings:
                                true,
                            clickAction:
                                'FLUTTER_NOTIFICATION_CLICK',
                        },
                    },

                    apns: {
                        headers: {
                            'apns-priority': '10',
                            'apns-push-type': 'alert',
                        },

                        payload: {
                            aps: {
                                alert: {
                                    title,
                                    body,
                                },
                                sound: 'default',
                                badge: 1,
                                contentAvailable: true,
                                mutableContent: true,
                            },
                        },
                    },
                });

        console.log(
            `📨 Ride ${rideId}: ` +
            `${response.successCount} driver notifications sent, ` +
            `${response.failureCount} failed`
        );

        if (response.failureCount > 0) {
            for (
                let i = 0;
                i < response.responses.length;
                i++
            ) {
                const notificationResult =
                    response.responses[i];

                if (
                    !notificationResult.success
                ) {
                    const token = tokens[i];

                    const errorCode =
                        notificationResult.error
                            ?.code;

                    if (
                        errorCode ===
                        'messaging/invalid-registration-token' ||
                        errorCode ===
                        'messaging/registration-token-not-registered'
                    ) {
                        await pool.query(
                            `
                            DELETE FROM public.fcm_tokens
                            WHERE token = $1
                            `,
                            [token]
                        );
                    }
                }
            }
        }
    } catch (error) {
        console.error(
            '❌ Error notifying nearby drivers:',
            error
        );
    }
}

/*
|--------------------------------------------------------------------------
| CREATE RIDE
|--------------------------------------------------------------------------
*/

router.post(
    '/rides',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response
    ) => {
        try {
            if (
                !req.body ||
                typeof req.body !== 'object'
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Request body is missing or invalid.',
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

            console.log(
                '🔥 Creating ride for Firebase UID:',
                uid
            );

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
                    [uid]
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

            if (!isValidLocation(pickup)) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid pickup. Expected { lat, lng }.',
                });
            }

            if (
                !isValidLocation(destination)
            ) {
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

            const activeRideResult =
                await pool.query(
                    `
                    SELECT id
                    FROM public.rides
                    WHERE passenger_id = $1::integer
                      AND status IN (
                          'requested',
                          'accepted',
                          'arrived',
                          'started'
                      )
                    ORDER BY requested_at DESC
                    LIMIT 1
                    `,
                    [passenger.id]
                );

            if (
                activeRideResult.rows.length > 0
            ) {
                return res.status(409).json({
                    success: false,
                    message:
                        'You already have an active ride.',
                    rideId:
                        activeRideResult
                            .rows[0]
                            .id,
                });
            }

            const rideDistance =
                toNumber(distance, 0) ?? 0;

            const rideDuration =
                Math.round(
                    toNumber(duration, 0) ?? 0
                );

            const rideFare =
                toNumber(fare, 0) ?? 0;

            if (
                rideDistance < 0 ||
                rideDuration < 0 ||
                rideFare < 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Distance, duration and fare cannot be negative.',
                });
            }

            const rideType =
                typeof ride_type === 'string' &&
                    ride_type.trim()
                    ? ride_type.trim()
                    : 'standard';

            const paymentMethod =
                typeof payment_method ===
                    'string' &&
                    payment_method.trim()
                    ? payment_method.trim()
                    : 'cash';

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
                        NULL::text,

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
                    ]
                );

            const ride =
                insertResult.rows[0];

            console.log(
                `✅ Ride ${ride.id} created for passenger UID ${uid}`
            );

            await notifyNearbyDrivers(
                ride.id,
                pickupLat,
                pickupLng,
                {
                    passenger_name:
                        passenger.full_name ||
                        'Passenger',

                    pickup_address:
                        pickup_address ||
                        '',

                    destination_address:
                        destination_address ||
                        '',

                    fare: rideFare,

                    ride_type:
                        rideType,
                }
            );

            return res.status(201).json({
                success: true,
                rideId: ride.id,

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
                error
            );

            const dbError =
                error as {
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
    }
);

/*
|--------------------------------------------------------------------------
| GET NEARBY RIDES
|--------------------------------------------------------------------------
*/

router.get(
    '/rides/nearby',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response
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

            radius =
                Math.min(radius, 50000);

            const driverResult =
                await pool.query(
                    `
                    SELECT
                        uid,
                        full_name,
                        status,
                        is_online,
                        is_available
                    FROM public.drivers
                    WHERE uid = $1::text
                    LIMIT 1
                    `,
                    [uid]
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
                driver.status !== 'approved' ||
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
                        r.driver_id,

                        r.pickup_address,
                        r.destination_address,

                        ST_Y(r.pickup)
                            AS pickup_lat,

                        ST_X(r.pickup)
                            AS pickup_lng,

                        ST_Y(r.destination)
                            AS dest_lat,

                        ST_X(r.destination)
                            AS dest_lng,

                        r.distance,
                        r.duration,
                        r.fare,

                        r.payment_method,
                        r.payment_status,

                        r.status,
                        r.ride_type,
                        r.requested_at,

                        p.full_name
                            AS passenger_name,

                        p.profile_photo_url
                            AS passenger_photo_url,

                        5.0
                            AS passenger_rating,

                        0
                            AS passenger_rides,

                        ST_Distance(
                            r.pickup::geography,

                            ST_SetSRID(
                                ST_MakePoint(
                                    $2::double precision,
                                    $1::double precision
                                ),
                                4326
                            )::geography
                        ) / 1000.0
                            AS distance_to_pickup

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
                    ]
                );

            return res.status(200).json(
                result.rows
            );
        } catch (error) {
            console.error(
                '❌ Nearby rides error:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while finding nearby rides.',
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| GET PENDING RIDES  (driver dispatch queue)
|--------------------------------------------------------------------------
*/

router.get(
    '/rides/pending',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response
    ) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Unauthenticated.',
                });
            }

            const driverResult = await pool.query(
                `
                SELECT
                    uid,
                    full_name,
                    status,
                    is_online,
                    is_available,
                    current_latitude,
                    current_longitude
                FROM public.drivers
                WHERE uid = $1::text
                LIMIT 1
                `,
                [uid]
            );

            if (driverResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver profile not found.',
                });
            }

            const driver = driverResult.rows[0];

            if (driver.status !== 'approved' || !driver.is_online) {
                console.log(
                    `ℹ️ Pending rides: driver ${uid} not eligible ` +
                    `(status=${driver.status}, is_online=${driver.is_online})`
                );

                return res.status(200).json({
                    success: true,
                    rides: [],
                });
            }

            if (!driver.is_available) {
                const activeRide = await pool.query(
                    `
                    SELECT id
                    FROM public.rides
                    WHERE driver_id = $1::text
                      AND status IN ('accepted', 'arrived', 'started')
                    LIMIT 1
                    `,
                    [uid]
                );

                if (activeRide.rows.length === 0) {
                    await pool.query(
                        `
                        UPDATE public.drivers
                        SET
                            is_available = true,
                            updated_at = NOW()
                        WHERE uid = $1::text
                        `,
                        [uid]
                    );

                    driver.is_available = true;

                    console.log(
                        `🔧 Auto-restored is_available for driver ${uid}`
                    );
                } else {
                    console.log(
                        `ℹ️ Pending rides: driver ${uid} has active ride ` +
                        `${activeRide.rows[0].id}; skipping`
                    );

                    return res.status(200).json({
                        success: true,
                        rides: [],
                    });
                }
            }

            let lat = Number(req.query.lat);
            let lng = Number(req.query.lng);

            if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
                lat = Number(driver.current_latitude);
                lng = Number(driver.current_longitude);
            }

            if (
                !Number.isFinite(lat) ||
                !Number.isFinite(lng) ||
                lat < -90 ||
                lat > 90 ||
                lng < -180 ||
                lng > 180
            ) {
                console.log(
                    `ℹ️ Pending rides: driver ${uid} has no usable location ` +
                    `(lat=${lat}, lng=${lng})`
                );

                return res.status(400).json({
                    success: false,
                    message:
                        'Your current location is unavailable. ' +
                        'Please enable GPS and go online before fetching pending rides.',
                });
            }

            let radiusKm = Number(req.query.radiusKm);

            if (!Number.isFinite(radiusKm) || radiusKm <= 0) {
                radiusKm = 10;
            }

            radiusKm = Math.min(radiusKm, 50);

            const radiusMeters = radiusKm * 1000;

            const result = await pool.query(
                `
                SELECT
                    r.id
                        AS "rideId",

                    r.passenger_id
                        AS "passengerId",

                    r.driver_id
                        AS "driverId",

                    r.pickup_address
                        AS "pickupAddress",

                    r.destination_address
                        AS "destinationAddress",

                    ST_Y(r.pickup)
                        AS "pickupLat",

                    ST_X(r.pickup)
                        AS "pickupLng",

                    ST_Y(r.destination)
                        AS "destLat",

                    ST_X(r.destination)
                        AS "destLng",

                    r.distance
                        AS "distanceKm",

                    r.duration
                        AS "durationMin",

                    r.fare,

                    r.payment_method
                        AS "paymentMethod",

                    r.payment_status
                        AS "paymentStatus",

                    r.status,

                    r.ride_type
                        AS "rideType",

                    r.requested_at
                        AS "requestedAt",

                    p.full_name
                        AS "passengerName",

                    p.profile_photo_url
                        AS "passengerPhotoUrl",

                    5.0
                        AS "passengerRating",

                    0
                        AS "passengerRides",

                    ST_Distance(
                        r.pickup::geography,

                        ST_SetSRID(
                            ST_MakePoint(
                                $2::double precision,
                                $1::double precision
                            ),
                            4326
                        )::geography
                    ) / 1000.0
                        AS "distanceToPickupKm"

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
                    "distanceToPickupKm" ASC,
                    r.requested_at ASC

                LIMIT 20
                `,
                [lat, lng, radiusMeters]
            );

            console.log(
                `📋 Pending rides for driver ${uid}: ` +
                `${result.rows.length} found ` +
                `(lat=${lat}, lng=${lng}, radiusKm=${radiusKm})`
            );

            return res.status(200).json({
                success: true,
                rides: result.rows,
            });
        } catch (error) {
            console.error(
                '❌ Pending rides error:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while finding pending rides.',
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| GET RIDE HISTORY (driver)
|--------------------------------------------------------------------------
*/

router.get(
    '/rides/history',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response
    ) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Unauthenticated.',
                });
            }

            let limit = parseInt(
                String(req.query.limit ?? '50'),
                10
            );
            if (!Number.isFinite(limit) || limit <= 0) limit = 50;
            if (limit > 100) limit = 100;

            let offset = parseInt(
                String(req.query.offset ?? '0'),
                10
            );
            if (!Number.isFinite(offset) || offset < 0) offset = 0;

            const driverCheck = await pool.query(
                `
                SELECT uid
                FROM public.drivers
                WHERE uid = $1::text
                LIMIT 1
                `,
                [uid]
            );

            if (driverCheck.rows.length === 0) {
                console.warn(
                    `ℹ️ History: driver ${uid} not found — returning [].`
                );
                return res.status(200).json({
                    success: true,
                    rides: [],
                });
            }

            const sql = `
                SELECT
                    r.id                     AS "rideId",
                    r.passenger_id           AS "passengerId",
                    r.driver_id              AS "driverId",

                    r.pickup_address         AS "pickupAddress",
                    r.destination_address    AS "destinationAddress",

                    ST_Y(r.pickup)           AS "pickupLat",
                    ST_X(r.pickup)           AS "pickupLng",
                    ST_Y(r.destination)      AS "destLat",
                    ST_X(r.destination)      AS "destLng",

                    r.distance               AS "distanceKm",
                    r.duration               AS "durationMin",
                    r.fare,

                    r.driver_earnings        AS "driverEarnings",
                    r.tegaara_commission     AS "tegaaraCommission",

                    r.payment_method         AS "paymentMethod",
                    r.payment_status         AS "paymentStatus",

                    r.status,
                    r.ride_type              AS "rideType",

                    r.requested_at           AS "requestedAt",
                    r.completed_at           AS "completedAt",

                    p.full_name              AS "passengerName",
                    p.profile_photo_url      AS "passengerPhotoUrl",

                    5.0                      AS "passengerRating",
                    0                        AS "passengerRides"

                FROM public.rides r

                LEFT JOIN public.passengers p
                    ON p.id = r.passenger_id

                WHERE r.driver_id = $1::text
                  AND r.status IN ('completed', 'cancelled')

                ORDER BY r.id DESC

                LIMIT $2 OFFSET $3
            `;

            console.log(
                `📜 History query driver=${uid} limit=${limit} offset=${offset}`
            );

            const result = await pool.query(sql, [
                uid,
                limit,
                offset,
            ]);

            console.log(
                `✅ Ride history for driver ${uid}: ` +
                `${result.rows.length} row(s)`
            );

            return res.status(200).json({
                success: true,
                rides: result.rows,
            });
        } catch (error: unknown) {
            const pgError = error as {
                code?: string;
                message?: string;
                detail?: string;
                hint?: string;
                position?: string;
            };

            console.error('❌ Ride history error:', {
                code: pgError.code,
                message: pgError.message,
                detail: pgError.detail,
                hint: pgError.hint,
                position: pgError.position,
            });

            return res.status(500).json({
                success: false,
                message:
                    'Server error while fetching ride history.',
                code:
                    pgError.code ?? 'HISTORY_FETCH_FAILED',
                detail: pgError.message ?? null,
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| ACCEPT RIDE
|--------------------------------------------------------------------------
*/

router.post(
    '/rides/:rideId/accept',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response
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

            console.log(
                `📥 Accept ride=${rideId}, driverFirebaseUID=${uid}`
            );

            await client.query('BEGIN');

            const driverResult =
                await client.query(
                    `
                    SELECT
                        id,
                        uid,
                        full_name,
                        profile_photo_url,
                        current_latitude,
                        current_longitude,
                        status,
                        is_online,
                        is_available,
                        vehicle_type,
                        vehicle_model,
                        vehicle_color,
                        registration_number,
                        vehicle_year
                    FROM public.drivers
                    WHERE uid = $1::text
                    LIMIT 1
                    FOR UPDATE
                    `,
                    [uid]
                );

            if (
                driverResult.rows.length === 0
            ) {
                await client.query(
                    'ROLLBACK'
                );

                return res.status(404).json({
                    success: false,
                    message:
                        'Driver profile not found.',
                });
            }

            const driver =
                driverResult.rows[0];

            if (
                driver.status !== 'approved' ||
                !driver.is_online ||
                !driver.is_available
            ) {
                await client.query(
                    'ROLLBACK'
                );

                return res.status(403).json({
                    success: false,
                    message:
                        'Driver is not available.',
                });
            }

            const walletResult =
                await client.query(
                    `
                    SELECT
                        id,
                        balance,
                        minimum_balance
                    FROM public.driver_wallets
                    WHERE driver_id = $1
                    FOR UPDATE
                    `,
                    [driver.id]
                );

            if (
                walletResult.rows.length === 0
            ) {
                await client.query(
                    'ROLLBACK'
                );

                return res.status(402).json({
                    success: false,
                    code: 'WALLET_NOT_FOUND',
                    message:
                        'Your driver wallet has not been created yet. ' +
                        'Please open your wallet and top up before accepting rides.',
                });
            }

            const wallet =
                walletResult.rows[0];

            const walletBalance =
                Number(wallet.balance);

            const walletMinimum =
                Number(wallet.minimum_balance);

            if (
                !Number.isFinite(walletBalance) ||
                !Number.isFinite(walletMinimum) ||
                walletBalance < walletMinimum
            ) {
                await client.query(
                    'ROLLBACK'
                );

                const shortfall =
                    Number(
                        Math.max(
                            0,
                            walletMinimum - walletBalance
                        ).toFixed(2)
                    );

                return res.status(402).json({
                    success: false,
                    code: 'INSUFFICIENT_WALLET_BALANCE',
                    message:
                        `You need at least GH₵${walletMinimum.toFixed(2)} ` +
                        `in your wallet to accept a ride. Top up ` +
                        `GH₵${shortfall.toFixed(2)} and try again.`,
                    balance: walletBalance,
                    minimum_balance: walletMinimum,
                    shortfall,
                });
            }

            const updateResult =
                await client.query(
                    `
                    UPDATE public.rides

                    SET
                        driver_id = $1::text,
                        status    = 'accepted'

                    WHERE id = $2::integer

                      AND status = 'requested'

                      AND driver_id IS NULL

                    RETURNING id
                    `,
                    [
                        uid,
                        rideId,
                    ]
                );

            if (
                updateResult.rows.length === 0
            ) {
                await client.query(
                    'ROLLBACK'
                );

                return res.status(409).json({
                    success: false,
                    message:
                        'Ride has already been accepted or is no longer available.',
                });
            }

            await client.query(
                `
                UPDATE public.drivers

                SET
                    is_available = false,
                    updated_at = NOW()

                WHERE uid = $1::text
                `,
                [uid]
            );

            const rideResult =
                await client.query(
                    `
                    SELECT
                        r.id AS "rideId",

                        r.passenger_id
                            AS "passengerId",

                        r.driver_id
                            AS "driverId",

                        r.pickup_address
                            AS "pickupAddress",

                        r.destination_address
                            AS "destinationAddress",

                        ST_Y(r.pickup)
                            AS "pickupLat",

                        ST_X(r.pickup)
                            AS "pickupLng",

                        ST_Y(r.destination)
                            AS "destLat",

                        ST_X(r.destination)
                            AS "destLng",

                        r.distance
                            AS "distanceKm",

                        r.duration
                            AS "durationMin",

                        r.fare,

                        r.driver_earnings
                            AS "driverEarnings",

                        r.tegaara_commission
                            AS "tegaaraCommission",

                        r.payment_method
                            AS "paymentMethod",

                        r.payment_status
                            AS "paymentStatus",

                        r.status,

                        r.ride_type
                            AS "rideType",

                        r.requested_at
                            AS "requestedAt",

                        p.full_name
                            AS "passengerName",

                        p.profile_photo_url
                            AS "passengerPhotoUrl"

                    FROM public.rides r

                    LEFT JOIN public.passengers p
                        ON p.id = r.passenger_id

                    WHERE r.id = $1::integer

                    LIMIT 1
                    `,
                    [rideId]
                );

            await client.query(
                'COMMIT'
            );

            const ride =
                rideResult.rows[0];

            console.log(
                `✅ Driver ${uid} accepted ride ${rideId}`
            );

            /*
            |----------------------------------------------------------
            | Notify PASSENGER that the driver accepted
            |----------------------------------------------------------
            */
            try {
                const passengerTokenResult =
                    await pool.query(
                        `
                        SELECT ft.token

                        FROM public.fcm_tokens ft

                        INNER JOIN public.passengers p
                            ON p.firebase_uid =
                               ft.user_id

                        WHERE p.id = $1

                          AND ft.token IS NOT NULL

                        ORDER BY
                            ft.updated_at DESC NULLS LAST

                        LIMIT 1
                        `,
                        [
                            ride.passengerId,
                        ]
                    );

                const passengerToken =
                    passengerTokenResult
                        .rows[0]?.token;

                if (passengerToken) {
                    const driverName =
                        driver.full_name ||
                        'Driver';

                    const driverLat =
                        driver.current_latitude != null
                            ? String(
                                driver.current_latitude
                            )
                            : '';

                    const driverLng =
                        driver.current_longitude != null
                            ? String(
                                driver.current_longitude
                            )
                            : '';

                    await sendFcmNotification(
                        passengerToken,

                        'Ride Accepted',

                        `Your ride has been accepted by ${driverName}. They are on their way.`,

                        {
                            role: 'passenger',
                            notificationType:
                                'ride_accepted',
                            targetScreen:
                                'track_ride',
                            status: 'accepted',

                            rideId:
                                String(rideId),

                            driverName,

                            driverPhoto:
                                driver.profile_photo_url ||
                                '',

                            driverLat,
                            driverLng,

                            vehicleType:
                                driver.vehicle_type ||
                                '',

                            vehicleModel:
                                driver.vehicle_model ||
                                '',

                            vehicleColor:
                                driver.vehicle_color ||
                                '',

                            vehicleRegistration:
                                driver.registration_number ||
                                '',

                            vehicleYear:
                                driver.vehicle_year != null
                                    ? String(
                                        driver.vehicle_year
                                    )
                                    : '',

                            pickupAddress:
                                ride.pickupAddress ||
                                '',

                            destinationAddress:
                                ride.destinationAddress ||
                                '',

                            pickupLat:
                                ride.pickupLat != null
                                    ? String(
                                        ride.pickupLat
                                    )
                                    : '',

                            pickupLng:
                                ride.pickupLng != null
                                    ? String(
                                        ride.pickupLng
                                    )
                                    : '',

                            destLat:
                                ride.destLat != null
                                    ? String(
                                        ride.destLat
                                    )
                                    : '',

                            destLng:
                                ride.destLng != null
                                    ? String(
                                        ride.destLng
                                    )
                                    : '',

                            fare:
                                ride.fare != null
                                    ? String(
                                        ride.fare
                                    )
                                    : '',

                            distanceKm:
                                ride.distanceKm != null
                                    ? String(
                                        ride.distanceKm
                                    )
                                    : '',

                            durationMin:
                                ride.durationMin != null
                                    ? String(
                                        ride.durationMin
                                    )
                                    : '',
                        }
                    );
                }
            } catch (
            notificationError
            ) {
                console.error(
                    '❌ Passenger notification failed:',
                    notificationError
                );
            }

            /*
            |----------------------------------------------------------
            | Notify DRIVER — confirmation of their own acceptance
            |----------------------------------------------------------
            */
            try {
                const driverTokenResult =
                    await pool.query(
                        `
                        SELECT token

                        FROM public.fcm_tokens

                        WHERE user_id = $1::text

                        ORDER BY
                            updated_at DESC NULLS LAST

                        LIMIT 1
                        `,
                        [uid]
                    );

                const driverToken =
                    driverTokenResult
                        .rows[0]?.token;

                if (driverToken) {
                    await sendFcmNotification(
                        driverToken,

                        'Ride Accepted',

                        `You accepted ride #${rideId}. Head to ${ride.pickupAddress || 'the pickup location'}.`,

                        {
                            role: 'driver',
                            notificationType:
                                'ride_accepted_driver',
                            targetScreen:
                                'driver_ride',
                            status: 'accepted',

                            rideId:
                                String(rideId),

                            passengerName:
                                ride.passengerName ||
                                'Passenger',

                            passengerPhoto:
                                ride.passengerPhotoUrl ||
                                '',

                            pickupAddress:
                                ride.pickupAddress ||
                                '',

                            destinationAddress:
                                ride.destinationAddress ||
                                '',

                            pickupLat:
                                ride.pickupLat != null
                                    ? String(
                                        ride.pickupLat
                                    )
                                    : '',

                            pickupLng:
                                ride.pickupLng != null
                                    ? String(
                                        ride.pickupLng
                                    )
                                    : '',

                            destLat:
                                ride.destLat != null
                                    ? String(
                                        ride.destLat
                                    )
                                    : '',

                            destLng:
                                ride.destLng != null
                                    ? String(
                                        ride.destLng
                                    )
                                    : '',

                            fare:
                                ride.fare != null
                                    ? String(
                                        ride.fare
                                    )
                                    : '',

                            distanceKm:
                                ride.distanceKm != null
                                    ? String(
                                        ride.distanceKm
                                    )
                                    : '',

                            durationMin:
                                ride.durationMin != null
                                    ? String(
                                        ride.durationMin
                                    )
                                    : '',
                        }
                    );
                }
            } catch (
            notificationError
            ) {
                console.error(
                    '❌ Driver acceptance notification failed:',
                    notificationError
                );
            }

            return res.status(200).json({
                success: true,
                ride,
                message:
                    'Ride accepted successfully.',
            });
        } catch (error) {
            try {
                await client.query(
                    'ROLLBACK'
                );
            } catch (_) { }

            console.error(
                '❌ Accept ride error:',
                error
            );

            const dbError =
                error as {
                    code?: string;
                    message?: string;
                    detail?: string;
                };

            if (dbError.code === '23514') {
                return res.status(402).json({
                    success: false,
                    code: 'INSUFFICIENT_WALLET_BALANCE',
                    message:
                        'Insufficient wallet balance. Please top up your wallet before accepting a ride.',
                });
            }

            return res.status(500).json({
                success: false,
                message:
                    'Server error while accepting ride.',
                code:
                    dbError.code ??
                    'ACCEPT_RIDE_FAILED',
                error:
                    dbError.message ??
                    'Unknown database error',
                detail:
                    dbError.detail ?? null,
            });
        } finally {
            client.release();
        }
    }
);

/*
|--------------------------------------------------------------------------
| MARK ARRIVED AT PICKUP
|--------------------------------------------------------------------------
*/

router.post(
    '/rides/:rideId/arrived',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response
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
                    message: 'Invalid ride ID.',
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

            console.log(
                `📍 Mark arrived: ride=${rideId}, driverUID=${uid}`
            );

            await client.query('BEGIN');

            const driverResult =
                await client.query(
                    `
                    SELECT
                        uid,
                        status,
                        is_online,
                        is_available
                    FROM public.drivers
                    WHERE uid = $1::text
                    LIMIT 1
                    FOR UPDATE
                    `,
                    [uid]
                );

            if (
                driverResult.rows.length === 0
            ) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                });
            }

            const result =
                await client.query(
                    `
                    UPDATE public.rides

                    SET
                        status = 'arrived'

                    WHERE id = $1::integer

                      AND driver_id = $2::text

                      AND status = 'accepted'

                    RETURNING
                        id,
                        driver_id,
                        status
                    `,
                    [rideId, uid]
                );

            if (
                result.rows.length === 0
            ) {
                await client.query('ROLLBACK');

                return res.status(409).json({
                    success: false,
                    message:
                        'Ride not found or cannot be marked as arrived.',
                });
            }

            await client.query('COMMIT');

            console.log(
                `✅ Ride ${rideId} marked arrived by driver ${uid}`
            );

            try {
                const passengerTokenResult =
                    await pool.query(
                        `
                        SELECT ft.token

                        FROM public.fcm_tokens ft

                        INNER JOIN public.passengers p
                            ON p.firebase_uid =
                               ft.user_id

                        INNER JOIN public.rides r
                            ON r.passenger_id = p.id

                        WHERE r.id = $1

                          AND ft.token IS NOT NULL

                        ORDER BY
                            ft.updated_at DESC NULLS LAST

                        LIMIT 1
                        `,
                        [rideId]
                    );

                const passengerToken =
                    passengerTokenResult
                        .rows[0]?.token;

                if (passengerToken) {
                    await sendFcmNotification(
                        passengerToken,

                        'Driver Has Arrived',

                        'Your driver has arrived at the pickup location.',

                        {
                            role: 'passenger',
                            notificationType:
                                'ride_arrived',
                            targetScreen:
                                'track_ride',
                            rideId:
                                String(rideId),
                            status: 'arrived',
                        }
                    );
                }
            } catch (
            notificationError
            ) {
                console.error(
                    '❌ Passenger arrived notification failed:',
                    notificationError
                );
            }

            return res.status(200).json({
                success: true,
                ride: result.rows[0],
                message:
                    'Marked as arrived at pickup.',
            });
        } catch (error) {
            try {
                await client.query('ROLLBACK');
            } catch (_) { }

            console.error(
                '❌ Mark arrived error:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while marking ride as arrived.',
            });
        } finally {
            client.release();
        }
    }
);

/*
|--------------------------------------------------------------------------
| CURRENT DRIVER RIDE
|--------------------------------------------------------------------------
*/

router.get(
    '/drivers/:uid/current-request',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response
    ) => {
        try {
            const authenticatedUid =
                getAuthenticatedUid(req);

            if (!authenticatedUid) {
                return res.status(401).json({
                    success: false,
                    message:
                        'Unauthenticated.',
                });
            }

            const requestedUid =
                String(req.params.uid).trim();

            if (
                requestedUid !==
                authenticatedUid
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
                    SELECT
                        uid,
                        full_name,
                        status,
                        is_online,
                        is_available
                    FROM public.drivers
                    WHERE uid = $1::text
                    LIMIT 1
                    `,
                    [authenticatedUid]
                );

            if (
                driverResult.rows.length === 0
            ) {
                return res.status(200).json({
                    success: true,
                    ride: null,
                });
            }

            const rideResult =
                await pool.query(
                    `
                    SELECT
                        r.id AS "rideId",

                        r.passenger_id
                            AS "passengerId",

                        r.driver_id
                            AS "driverId",

                        r.pickup_address
                            AS "pickupAddress",

                        r.destination_address
                            AS "destinationAddress",

                        ST_Y(r.pickup)
                            AS "pickupLat",

                        ST_X(r.pickup)
                            AS "pickupLng",

                        ST_Y(r.destination)
                            AS "destLat",

                        ST_X(r.destination)
                            AS "destLng",

                        r.distance
                            AS "distanceKm",

                        r.duration
                            AS "durationMin",

                        r.fare,

                        r.driver_earnings
                            AS "driverEarnings",

                        r.tegaara_commission
                            AS "tegaaraCommission",

                        r.payment_method
                            AS "paymentMethod",

                        r.payment_status
                            AS "paymentStatus",

                        r.status,

                        r.ride_type
                            AS "rideType",

                        r.requested_at
                            AS "requestedAt",

                        p.full_name
                            AS "passengerName",

                        p.profile_photo_url
                            AS "passengerPhotoUrl"

                    FROM public.rides r

                    LEFT JOIN public.passengers p
                        ON p.id = r.passenger_id

                    WHERE r.driver_id =
                          $1::text

                      AND r.status IN (
                          'accepted',
                          'arrived',
                          'started'
                      )

                    ORDER BY
                        r.requested_at DESC

                    LIMIT 1
                    `,
                    [authenticatedUid]
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
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while fetching current ride.',
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| DECLINE RIDE
|--------------------------------------------------------------------------
*/

router.post(
    '/driver/decline-ride',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response
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

            console.log(
                `ℹ️ Driver ${uid} declined ride ${rideId}`
            );

            return res.status(200).json({
                success: true,
                rideId,
                message:
                    'Ride declined.',
            });
        } catch (error) {
            console.error(
                '❌ Decline ride error:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while declining ride.',
            });
        }
    }
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
        res: Response
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
                        r.id,
                        r.passenger_id,
                        r.driver_id,
                        r.pickup_address,
                        r.destination_address,

                        ST_Y(r.pickup)
                            AS pickup_lat,

                        ST_X(r.pickup)
                            AS pickup_lng,

                        ST_Y(r.destination)
                            AS dest_lat,

                        ST_X(r.destination)
                            AS dest_lng,

                        r.distance,
                        r.duration,
                        r.fare,
                        r.payment_method,
                        r.payment_status,
                        r.status,
                        r.ride_type,
                        r.requested_at,
                        r.completed_at,

                        d.full_name
                            AS driver_name,

                        d.profile_photo_url
                            AS driver_photo,

                        d.current_latitude
                            AS driver_lat,

                        d.current_longitude
                            AS driver_lng,

                        d.vehicle_type,
                        d.vehicle_model,
                        d.vehicle_color,

                        d.registration_number
                            AS vehicle_registration,

                        d.vehicle_year

                    FROM public.rides r

                    LEFT JOIN public.passengers p
                        ON p.id = r.passenger_id

                    LEFT JOIN public.drivers d
                        ON d.uid = r.driver_id

                    WHERE r.id = $1::integer

                      AND (
                          p.firebase_uid =
                              $2::text

                          OR r.driver_id =
                              $2::text
                      )

                    LIMIT 1
                    `,
                    [rideId, uid]
                );

            if (
                result.rows.length === 0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Ride not found or you are not authorized.',
                });
            }

            return res.status(200).json({
                success: true,
                ride: result.rows[0],
            });
        } catch (error) {
            console.error(
                '❌ Ride status error:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while fetching ride status.',
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| PAY RIDE  (passenger pays → driver is notified + wallet is credited)
|--------------------------------------------------------------------------
*/

router.post(
    '/rides/:rideId/pay',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response
    ) => {
        const client = await pool.connect();

        try {
            const rideId = Number(req.params.rideId);

            if (!Number.isInteger(rideId) || rideId <= 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid ride ID.',
                });
            }

            const uid = getAuthenticatedUid(req);
            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Unauthenticated.',
                });
            }

            const paymentMethod =
                typeof req.body?.paymentMethod === 'string' &&
                    req.body.paymentMethod.trim()
                    ? req.body.paymentMethod.trim()
                    : 'cash';

            await client.query('BEGIN');

            const rideResult = await client.query(
                `
                SELECT
                    r.id,
                    r.passenger_id,
                    r.driver_id,
                    r.fare,
                    r.payment_status,
                    r.pickup_address,
                    r.destination_address,
                    p.firebase_uid AS passenger_firebase_uid,
                    p.full_name    AS passenger_name
                FROM public.rides r
                LEFT JOIN public.passengers p
                    ON p.id = r.passenger_id
                WHERE r.id = $1::integer
                LIMIT 1
                FOR UPDATE OF r
                `,
                [rideId]
            );

            if (rideResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({
                    success: false,
                    message: 'Ride not found.',
                });
            }

            const ride = rideResult.rows[0];

            if (ride.passenger_firebase_uid !== uid) {
                await client.query('ROLLBACK');
                return res.status(403).json({
                    success: false,
                    message:
                        'You are not authorized to pay for this ride.',
                });
            }

            if (ride.payment_status === 'paid') {
                await client.query('ROLLBACK');
                return res.status(200).json({
                    success: true,
                    alreadyPaid: true,
                    message: 'Ride already paid.',
                });
            }

            const fare = Number(ride.fare) || 0;

            const commission = Math.min(2.0, fare);
            const driverEarnings = Math.max(0, fare - commission);

            await client.query(
                `
                UPDATE public.rides
                SET
                    payment_status     = 'paid',
                    payment_method     = $1::varchar,
                    driver_earnings    = $2::numeric,
                    tegaara_commission = $3::numeric
                WHERE id = $4::integer
                `,
                [paymentMethod, driverEarnings, commission, rideId]
            );

            const driverFirebaseUid: string | null = ride.driver_id;
            let newDriverBalance: number | null = null;

            if (driverFirebaseUid) {
                const driverResult = await client.query(
                    `
                    SELECT id
                    FROM public.drivers
                    WHERE uid = $1::text
                    LIMIT 1
                    `,
                    [driverFirebaseUid]
                );

                const driverNumericId = driverResult.rows[0]?.id;

                if (driverNumericId) {
                    const walletUpdate = await client.query(
                        `
                        UPDATE public.driver_wallets
                        SET
                            balance    = balance + $1::numeric,
                            updated_at = NOW()
                        WHERE driver_id = $2
                        RETURNING balance
                        `,
                        [driverEarnings, driverNumericId]
                    );

                    if (walletUpdate.rows[0]?.balance != null) {
                        newDriverBalance = Number(
                            walletUpdate.rows[0].balance
                        );
                    }
                }
            }

            await client.query('COMMIT');

            console.log(
                `💵 Ride ${rideId} paid. fare=${fare} ` +
                `driverEarnings=${driverEarnings} commission=${commission}`
            );

            if (driverFirebaseUid) {
                try {
                    const tokenResult = await pool.query(
                        `
                        SELECT token
                        FROM public.fcm_tokens
                        WHERE user_id = $1::text
                        ORDER BY updated_at DESC NULLS LAST
                        LIMIT 1
                        `,
                        [driverFirebaseUid]
                    );

                    const driverToken = tokenResult.rows[0]?.token;

                    if (driverToken) {
                        await sendFcmNotification(
                            driverToken,
                            'Payment Received',
                            `You earned GH₵${driverEarnings.toFixed(2)} for ride #${rideId}.`,
                            {
                                role: 'driver',
                                notificationType: 'payment_received',
                                targetScreen: 'driver_wallet',
                                status: 'paid',
                                rideId: String(rideId),

                                amount: driverEarnings.toFixed(2),
                                fare: fare.toFixed(2),
                                commission: commission.toFixed(2),
                                paymentMethod,

                                newBalance:
                                    newDriverBalance != null
                                        ? newDriverBalance.toFixed(2)
                                        : '',

                                passengerName:
                                    ride.passenger_name || '',

                                pickupAddress:
                                    ride.pickup_address || '',

                                destinationAddress:
                                    ride.destination_address || '',
                            }
                        );
                    }
                } catch (notificationError) {
                    console.error(
                        '❌ Driver payment notification failed:',
                        notificationError
                    );
                }
            }

            return res.status(200).json({
                success: true,
                rideId,
                paymentStatus: 'paid',
                driverEarnings,
                tegaaraCommission: commission,
                message: 'Payment processed successfully.',
            });
        } catch (error) {
            try {
                await client.query('ROLLBACK');
            } catch (_) { }

            console.error('❌ Pay ride error:', error);

            return res.status(500).json({
                success: false,
                message: 'Server error while processing payment.',
            });
        } finally {
            client.release();
        }
    }
);

/*
|--------------------------------------------------------------------------
| GET RIDE DETAILS (single ride — camelCase, works for any status)
|--------------------------------------------------------------------------
|
| Used by RideService.fetchRideById on the driver app. Returns the same
| shape as /drivers/:uid/current-request so RideRequest.fromJson can parse
| the response directly. Works for both active and terminal rides.
|
| NOTE: registered LAST among GET /rides/* routes so it doesn't shadow
| /rides/history, /rides/nearby, /rides/pending, or /rides/:rideId/status.
|
*/

router.get(
    '/rides/:rideId',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response
    ) => {
        try {
            const rideId = Number(req.params.rideId);

            if (!Number.isInteger(rideId) || rideId <= 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid ride ID.',
                });
            }

            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Unauthenticated.',
                });
            }

            const result = await pool.query(
                `
                SELECT
                    r.id                        AS "rideId",
                    r.passenger_id              AS "passengerId",
                    r.driver_id                 AS "driverId",

                    r.pickup_address            AS "pickupAddress",
                    r.destination_address       AS "destinationAddress",

                    ST_Y(r.pickup)              AS "pickupLat",
                    ST_X(r.pickup)              AS "pickupLng",
                    ST_Y(r.destination)         AS "destLat",
                    ST_X(r.destination)         AS "destLng",

                    r.distance                  AS "distanceKm",
                    r.duration                  AS "durationMin",
                    r.fare,

                    r.driver_earnings           AS "driverEarnings",
                    r.tegaara_commission        AS "tegaaraCommission",

                    r.payment_method            AS "paymentMethod",
                    r.payment_status            AS "paymentStatus",

                    r.status,
                    r.ride_type                 AS "rideType",

                    r.requested_at              AS "requestedAt",
                    r.completed_at              AS "completedAt",

                    p.full_name                 AS "passengerName",
                    p.profile_photo_url         AS "passengerPhotoUrl",

                    5.0                         AS "passengerRating",
                    0                           AS "passengerRides",

                    d.full_name                 AS "driverName",
                    d.profile_photo_url         AS "driverPhoto",
                    d.current_latitude          AS "driverLat",
                    d.current_longitude         AS "driverLng",
                    d.vehicle_type              AS "vehicleType",
                    d.vehicle_model             AS "vehicleModel",
                    d.vehicle_color             AS "vehicleColor",
                    d.registration_number       AS "vehicleRegistration",
                    d.vehicle_year              AS "vehicleYear"

                FROM public.rides r

                LEFT JOIN public.passengers p
                    ON p.id = r.passenger_id

                LEFT JOIN public.drivers d
                    ON d.uid = r.driver_id

                WHERE r.id = $1::integer

                  AND (
                      p.firebase_uid = $2::text
                      OR r.driver_id = $2::text
                  )

                LIMIT 1
                `,
                [rideId, uid]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Ride not found or you are not authorized.',
                });
            }

            return res.status(200).json({
                success: true,
                ride: result.rows[0],
            });
        } catch (error) {
            console.error(
                '❌ Get ride details error:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while fetching ride details.',
            });
        }
    }
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
        res: Response
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

            const driverResult =
                await client.query(
                    `
                    SELECT
                        uid,
                        status,
                        is_online,
                        is_available
                    FROM public.drivers
                    WHERE uid = $1::text
                    LIMIT 1
                    FOR UPDATE
                    `,
                    [uid]
                );

            if (
                driverResult.rows.length === 0
            ) {
                await client.query(
                    'ROLLBACK'
                );

                return res.status(404).json({
                    success: false,
                    message:
                        'Driver not found.',
                });
            }

            const result =
                await client.query(
                    `
                    UPDATE public.rides

                    SET
                        status = 'started'

                    WHERE id = $1::integer

                      AND driver_id =
                          $2::text

                      AND status IN (
                          'accepted',
                          'arrived'
                      )

                    RETURNING
                        id,
                        driver_id,
                        status
                    `,
                    [
                        rideId,
                        uid,
                    ]
                );

            if (
                result.rows.length === 0
            ) {
                await client.query(
                    'ROLLBACK'
                );

                return res.status(409).json({
                    success: false,
                    message:
                        'Ride not found or cannot be started.',
                });
            }

            await client.query(
                `
                UPDATE public.drivers

                SET
                    is_available = false,
                    updated_at = NOW()

                WHERE uid = $1::text
                `,
                [uid]
            );

            await client.query(
                'COMMIT'
            );

            console.log(
                `✅ Ride ${rideId} started by driver ${uid}`
            );

            return res.status(200).json({
                success: true,
                ride:
                    result.rows[0],
                message:
                    'Ride started successfully.',
            });
        } catch (error) {
            try {
                await client.query(
                    'ROLLBACK'
                );
            } catch (_) { }

            console.error(
                '❌ Start ride error:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while starting ride.',
            });
        } finally {
            client.release();
        }
    }
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
        res: Response
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

            await client.query(
                'BEGIN'
            );

            const driverResult =
                await client.query(
                    `
                    SELECT
                        uid,
                        status,
                        is_online,
                        is_available
                    FROM public.drivers
                    WHERE uid = $1::text
                    LIMIT 1
                    FOR UPDATE
                    `,
                    [uid]
                );

            if (
                driverResult.rows.length === 0
            ) {
                await client.query(
                    'ROLLBACK'
                );

                return res.status(404).json({
                    success: false,
                    message:
                        'Driver not found.',
                });
            }

            const result =
                await client.query(
                    `
                    UPDATE public.rides

                    SET
                        status = 'completed',
                        completed_at = NOW()

                    WHERE id = $1::integer

                      AND driver_id =
                          $2::text

                      AND status =
                          'started'

                    RETURNING
                        id,
                        driver_id,
                        status,
                        completed_at
                    `,
                    [
                        rideId,
                        uid,
                    ]
                );

            if (
                result.rows.length === 0
            ) {
                await client.query(
                    'ROLLBACK'
                );

                return res.status(409).json({
                    success: false,
                    message:
                        'Ride not found or cannot be completed.',
                });
            }

            await restoreDriverAvailability(
                client,
                uid
            );

            await client.query(
                'COMMIT'
            );

            console.log(
                `✅ Ride ${rideId} completed. Driver ${uid} availability restored.`
            );

            return res.status(200).json({
                success: true,
                ride:
                    result.rows[0],
                message:
                    'Ride completed successfully.',
            });
        } catch (error) {
            try {
                await client.query(
                    'ROLLBACK'
                );
            } catch (_) { }

            console.error(
                '❌ Complete ride error:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while completing ride.',
            });
        } finally {
            client.release();
        }
    }
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
        res: Response
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

            const reason =
                typeof req.body?.reason ===
                    'string'
                    ? req.body.reason.trim()
                    : 'Not specified';

            console.log(
                `🚫 Cancelling ride ${rideId} by user ${uid}. Reason: ${reason}`
            );

            await client.query('BEGIN');

            const rideResult =
                await client.query(
                    `
                    SELECT
                        r.id,
                        r.passenger_id,
                        r.driver_id,
                        r.status,

                        p.firebase_uid
                            AS passenger_firebase_uid

                    FROM public.rides r

                    LEFT JOIN public.passengers p
                        ON p.id = r.passenger_id

                    WHERE r.id = $1::integer

                      AND r.status NOT IN (
                          'completed',
                          'cancelled'
                      )

                      AND (
                          p.firebase_uid =
                              $2::text

                          OR r.driver_id =
                              $2::text
                      )

                    LIMIT 1

                    FOR UPDATE OF r
                    `,
                    [
                        rideId,
                        uid,
                    ]
                );

            if (
                rideResult.rows.length === 0
            ) {
                await client.query(
                    'ROLLBACK'
                );

                return res.status(403).json({
                    success: false,
                    message:
                        'Ride not found or cannot be cancelled.',
                });
            }

            const ride =
                rideResult.rows[0];

            const passengerFirebaseUid =
                ride.passenger_firebase_uid;

            const driverFirebaseUid =
                ride.driver_id;

            const cancelledBy =
                driverFirebaseUid === uid
                    ? 'driver'
                    : 'passenger';

            const updateResult =
                await client.query(
                    `
                    UPDATE public.rides

                    SET
                        status = 'cancelled'

                    WHERE id = $1::integer

                    RETURNING
                        id,
                        passenger_id,
                        driver_id,
                        status
                    `,
                    [rideId]
                );

            if (
                updateResult.rows.length === 0
            ) {
                await client.query(
                    'ROLLBACK'
                );

                return res.status(409).json({
                    success: false,
                    message:
                        'Ride could not be cancelled.',
                });
            }

            if (driverFirebaseUid) {
                await restoreDriverAvailability(
                    client,
                    driverFirebaseUid
                );
            }

            await client.query(
                'COMMIT'
            );

            const notificationPromises:
                Promise<void>[] = [];

            if (
                passengerFirebaseUid &&
                passengerFirebaseUid !== uid
            ) {
                try {
                    const passengerTokenResult =
                        await pool.query(
                            `
                            SELECT token

                            FROM public.fcm_tokens

                            WHERE user_id =
                                  $1::text

                            ORDER BY
                                updated_at
                                DESC NULLS LAST

                            LIMIT 1
                            `,
                            [
                                passengerFirebaseUid,
                            ]
                        );

                    const passengerToken =
                        passengerTokenResult
                            .rows[0]?.token;

                    if (passengerToken) {
                        notificationPromises.push(
                            sendFcmNotification(
                                passengerToken,

                                'Ride Cancelled',

                                `Your ride has been cancelled. Reason: ${reason}`,

                                {
                                    role:
                                        'passenger',

                                    notificationType:
                                        'ride_cancelled',

                                    targetScreen:
                                        'passenger_home',

                                    rideId:
                                        String(
                                            rideId
                                        ),

                                    status:
                                        'cancelled',

                                    cancellationReason:
                                        reason,

                                    cancelledBy,
                                }
                            )
                        );
                    }
                } catch (error) {
                    console.error(
                        '❌ Passenger cancellation notification error:',
                        error
                    );
                }
            }

            if (
                driverFirebaseUid &&
                driverFirebaseUid !== uid
            ) {
                try {
                    const driverTokenResult =
                        await pool.query(
                            `
                            SELECT token

                            FROM public.fcm_tokens

                            WHERE user_id =
                                  $1::text

                            ORDER BY
                                updated_at
                                DESC NULLS LAST

                            LIMIT 1
                            `,
                            [
                                driverFirebaseUid,
                            ]
                        );

                    const driverToken =
                        driverTokenResult
                            .rows[0]?.token;

                    if (driverToken) {
                        notificationPromises.push(
                            sendFcmNotification(
                                driverToken,

                                'Ride Cancelled',

                                `Ride #${rideId} has been cancelled. Reason: ${reason}`,

                                {
                                    role:
                                        'driver',

                                    notificationType:
                                        'ride_cancelled',

                                    targetScreen:
                                        'driver_home',

                                    rideId:
                                        String(
                                            rideId
                                        ),

                                    status:
                                        'cancelled',

                                    cancellationReason:
                                        reason,

                                    cancelledBy,
                                }
                            )
                        );
                    }
                } catch (error) {
                    console.error(
                        '❌ Driver cancellation notification error:',
                        error
                    );
                }
            }

            await Promise.allSettled(
                notificationPromises
            );

            console.log(
                `✅ Ride ${rideId} marked cancelled. ` +
                `cancelledBy=${cancelledBy}`
            );

            return res.status(200).json({
                success: true,

                rideId,

                status:
                    'cancelled',

                cancelledBy,

                message:
                    'Ride cancelled successfully.',
            });
        } catch (error) {
            try {
                await client.query(
                    'ROLLBACK'
                );
            } catch (_) { }

            console.error(
                '❌ Cancel ride error:',
                error
            );

            const dbError =
                error as {
                    code?: string;
                    message?: string;
                    detail?: string;
                };

            return res.status(500).json({
                success: false,
                message:
                    'Server error while cancelling ride.',
                code:
                    dbError.code ??
                    'CANCEL_RIDE_FAILED',
                error:
                    dbError.message ??
                    'Unknown database error',
                detail:
                    dbError.detail ?? null,
            });
        } finally {
            client.release();
        }
    }
);

/*
|--------------------------------------------------------------------------
| GENERIC RIDE STATUS UPDATE
|--------------------------------------------------------------------------
*/

const DRIVER_STATUS_TRANSITIONS: Record<string, string[]> = {
    arrived: ['accepted'],
    started: ['accepted', 'arrived'],
    completed: ['started'],
};

router.post(
    '/rides/:rideId/status',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response
    ) => {
        const client = await pool.connect();

        try {
            const rideId =
                Number(req.params.rideId);

            if (
                !Number.isInteger(rideId) ||
                rideId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid ride ID.',
                });
            }

            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Unauthenticated.',
                });
            }

            const nextStatus = String(
                req.body?.status ?? ''
            )
                .trim()
                .toLowerCase();

            const allowedFrom =
                DRIVER_STATUS_TRANSITIONS[nextStatus];

            if (!allowedFrom) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid status. Allowed: arrived, started, completed.',
                });
            }

            await client.query('BEGIN');

            const driverResult =
                await client.query(
                    `
                    SELECT uid
                    FROM public.drivers
                    WHERE uid = $1::text
                    LIMIT 1
                    FOR UPDATE
                    `,
                    [uid]
                );

            if (
                driverResult.rows.length === 0
            ) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                });
            }

            const isCompleted =
                nextStatus === 'completed';

            const result =
                await client.query(
                    `
                    UPDATE public.rides

                    SET
                        status = $1::varchar,
                        completed_at =
                            CASE
                                WHEN $1::varchar = 'completed'
                                THEN NOW()
                                ELSE completed_at
                            END

                    WHERE id = $2::integer

                      AND driver_id = $3::text

                      AND status = ANY($4::varchar[])

                    RETURNING
                        id,
                        driver_id,
                        status,
                        completed_at
                    `,
                    [
                        nextStatus,
                        rideId,
                        uid,
                        allowedFrom,
                    ]
                );

            if (
                result.rows.length === 0
            ) {
                await client.query('ROLLBACK');

                return res.status(409).json({
                    success: false,
                    message: `Ride cannot be marked as ${nextStatus}.`,
                });
            }

            if (isCompleted) {
                await restoreDriverAvailability(
                    client,
                    uid
                );
            }

            await client.query('COMMIT');

            console.log(
                `✅ Ride ${rideId} status → ${nextStatus} (driver ${uid})`
            );

            if (!isCompleted) {
                try {
                    const passengerTokenResult =
                        await pool.query(
                            `
                            SELECT ft.token

                            FROM public.fcm_tokens ft

                            INNER JOIN public.passengers p
                                ON p.firebase_uid =
                                   ft.user_id

                            INNER JOIN public.rides r
                                ON r.passenger_id = p.id

                            WHERE r.id = $1

                              AND ft.token IS NOT NULL

                            ORDER BY
                                ft.updated_at DESC NULLS LAST

                            LIMIT 1
                            `,
                            [rideId]
                        );

                    const passengerToken =
                        passengerTokenResult
                            .rows[0]?.token;

                    if (passengerToken) {
                        const title =
                            nextStatus === 'arrived'
                                ? 'Driver Has Arrived'
                                : 'Ride Started';

                        const body =
                            nextStatus === 'arrived'
                                ? 'Your driver has arrived at the pickup location.'
                                : 'Your ride has started. Enjoy your trip!';

                        await sendFcmNotification(
                            passengerToken,
                            title,
                            body,
                            {
                                role: 'passenger',
                                notificationType:
                                    nextStatus === 'arrived'
                                        ? 'ride_arrived'
                                        : 'ride_started',
                                targetScreen:
                                    'track_ride',
                                rideId:
                                    String(rideId),
                                status: nextStatus,
                            }
                        );
                    }
                } catch (
                notificationError
                ) {
                    console.error(
                        '❌ Passenger status notification failed:',
                        notificationError
                    );
                }
            }

            return res.status(200).json({
                success: true,
                ride: result.rows[0],
                message: `Ride marked as ${nextStatus}.`,
            });
        } catch (error) {
            try {
                await client.query('ROLLBACK');
            } catch (_) { }

            console.error(
                '❌ Update ride status error:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'Server error while updating ride status.',
            });
        } finally {
            client.release();
        }
    }
);

export default router;
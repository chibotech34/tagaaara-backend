// src/routes/passengerRoutes.ts

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

/* ==========================================================================
 * TYPES
 * ========================================================================== */

interface DecodedFirebaseToken {
    uid: string;
    email?: string;
    name?: string;
    phone_number?: string;
}

interface AuthenticatedRequest extends Request {
    decodedToken?: DecodedFirebaseToken;
}

/* ==========================================================================
 * FIREBASE ID-TOKEN MIDDLEWARE
 * ========================================================================== */

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
        const decoded = await firebaseAuth.verifyIdToken(token);

        req.decodedToken = {
            uid: decoded.uid,
            email: decoded.email,
            name: decoded.name,
            phone_number: decoded.phone_number,
        };

        next();
    } catch (err: unknown) {
        console.error(
            '❌ Firebase token verification failed:',
            err,
        );

        const firebaseError = err as {
            code?: string;
        };

        if (
            firebaseError.code ===
            'auth/id-token-expired'
        ) {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token expired.',
                code: 'AUTH_TOKEN_EXPIRED',
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

/* ==========================================================================
 * GET AUTHENTICATED FIREBASE UID
 * ========================================================================== */

const getAuthenticatedUid = (
    req: AuthenticatedRequest,
): string | null => {
    return req.decodedToken?.uid ?? null;
};

/* ==========================================================================
 * NOTIFICATION HELPERS
 * ========================================================================== */

const createAlert = async (
    client: any,
    userId: string,
    title: string,
    body: string,
    category: string,
    priority: string,
    targetScreen: string,
    metadata: Record<string, unknown>,
): Promise<void> => {
    if (!userId || !userId.trim()) {
        return;
    }

    await client.query(
        `
        INSERT INTO public.alerts (
            user_id,
            title,
            body,
            category,
            priority,
            is_read,
            target_screen,
            metadata,
            created_at
        )
        VALUES (
            $1::text,
            $2::text,
            $3::text,
            $4::text,
            $5::text,
            false,
            $6::text,
            $7::jsonb,
            NOW()
        )
        `,
        [
            userId,
            title,
            body,
            category,
            priority,
            targetScreen,
            JSON.stringify(metadata),
        ],
    );
};

const sendFcmNotification = async (
    token: string,
    title: string,
    body: string,
    data: Record<string, string>,
): Promise<void> => {
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
                    channelId:
                        'tegaara_ride_channel',

                    priority:
                        'high' as const,

                    defaultSound:
                        true,

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
                    'apns-priority':
                        '10',

                    'apns-push-type':
                        'alert',
                },

                payload: {
                    aps: {
                        alert: {
                            title,
                            body,
                        },

                        sound:
                            'default',

                        badge:
                            1,

                        contentAvailable:
                            true,

                        mutableContent:
                            true,
                    },
                },
            },
        });

        console.log(
            `🔔 FCM sent successfully: ${title}`,
        );
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
                    [token],
                );

                console.log(
                    '🗑️ Removed invalid FCM token.',
                );
            } catch (deleteError) {
                console.error(
                    '❌ Failed deleting invalid FCM token:',
                    deleteError,
                );
            }
        }

        console.error(
            '❌ FCM notification error:',
            error,
        );
    }
};

const getUserFcmToken = async (
    userId: string,
): Promise<string | null> => {
    if (!userId || !userId.trim()) {
        return null;
    }

    try {
        const result = await pool.query(
            `
            SELECT token
            FROM public.fcm_tokens
            WHERE user_id = $1
              AND token IS NOT NULL
              AND TRIM(token) <> ''
            ORDER BY updated_at DESC NULLS LAST
            LIMIT 1
            `,
            [userId],
        );

        return result.rows[0]?.token ?? null;
    } catch (error) {
        console.error(
            `❌ Failed to get FCM token for ${userId}:`,
            error,
        );

        return null;
    }
};

/* ==========================================================================
 * GET /api/passengers/profile
 * ========================================================================== */

router.get(
    '/profile',
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
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const result =
                await pool.query(
                    `
                    SELECT
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
                        profile_photo_url,
                        account_status,
                        phone_verified,
                        email_verified,
                        updated_at,
                        is_online,
                        last_online_at,
                        current_latitude,
                        current_longitude,
                        last_location_update,
                        fcm_token
                    FROM public.passengers
                    WHERE firebase_uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger profile not found.',
                    code:
                        'PASSENGER_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                passenger:
                    result.rows[0],
            });
        } catch (error: unknown) {
            const e = error as {
                message?: string;
                code?: string;
            };

            console.error(
                '❌ Error fetching passenger profile:',
                e,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to fetch passenger profile.',
                code:
                    'PASSENGER_FETCH_FAILED',
                error:
                    e.message,
            });
        }
    },
);

/* ==========================================================================
 * PATCH /api/passengers/profile
 * ========================================================================== */

router.patch(
    '/profile',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        const client =
            await pool.connect();

        let transactionStarted =
            false;

        try {
            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                client.release();

                return res.status(401).json({
                    success: false,
                    message:
                        'Authentication required.',
                    code:
                        'AUTH_REQUIRED',
                });
            }

            const body =
                req.body ?? {};

            if (
                typeof body !== 'object' ||
                Array.isArray(body) ||
                body === null
            ) {
                client.release();

                return res.status(400).json({
                    success: false,
                    message:
                        'Request body must be a JSON object.',
                    code:
                        'INVALID_REQUEST_BODY',
                });
            }

            const receivedFields =
                Object.keys(body);

            if (
                receivedFields.length === 0
            ) {
                client.release();

                return res.status(400).json({
                    success: false,
                    message:
                        'No profile fields were provided for update.',
                    code:
                        'NO_FIELDS_TO_UPDATE',
                });
            }

            const allowedFields =
                new Set([
                    'full_name',
                    'phone',
                    'email',
                    'gender',
                    'emergency_contact_name',
                    'emergency_contact_phone',
                    'emergency_relationship',
                    'home_address',
                    'region',
                    'district',
                    'town_city',
                    'saved_locations',
                    'preferred_payment_method',
                    'mobile_money_number',
                    'language_preference',
                    'notification_enabled',
                    'privacy_enabled',
                    'profile_photo_url',
                ]);

            const unknownFields =
                receivedFields.filter(
                    (field) =>
                        !allowedFields.has(
                            field,
                        ),
                );

            if (
                unknownFields.length > 0
            ) {
                client.release();

                return res.status(400).json({
                    success: false,
                    message:
                        'One or more fields cannot be updated.',
                    code:
                        'INVALID_PROFILE_FIELDS',
                    fields:
                        unknownFields,
                });
            }

            const updateParts:
                string[] = [];

            const values:
                unknown[] = [];

            const addField = (
                column: string,
                value: unknown,
            ): void => {
                values.push(value);

                updateParts.push(
                    `${column} = $${values.length}`,
                );
            };

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'full_name',
                )
            ) {
                const fullName =
                    String(
                        body.full_name ??
                        '',
                    ).trim();

                if (!fullName) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Full name cannot be empty.',
                        code:
                            'INVALID_FULL_NAME',
                    });
                }

                if (
                    fullName.length >
                    150
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Full name is too long.',
                        code:
                            'INVALID_FULL_NAME',
                    });
                }

                addField(
                    'full_name',
                    fullName,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'phone',
                )
            ) {
                const phone =
                    String(
                        body.phone ??
                        '',
                    ).trim();

                if (
                    phone &&
                    phone.length >
                    30
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Phone number is invalid.',
                        code:
                            'INVALID_PHONE',
                    });
                }

                addField(
                    'phone',
                    phone || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'email',
                )
            ) {
                const email =
                    String(
                        body.email ??
                        '',
                    )
                        .trim()
                        .toLowerCase();

                if (
                    email &&
                    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
                        email,
                    )
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Please provide a valid email address.',
                        code:
                            'INVALID_EMAIL',
                    });
                }

                addField(
                    'email',
                    email || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'gender',
                )
            ) {
                const gender =
                    String(
                        body.gender ??
                        '',
                    ).trim();

                if (
                    gender.length >
                    50
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Gender value is too long.',
                        code:
                            'INVALID_GENDER',
                    });
                }

                addField(
                    'gender',
                    gender || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'emergency_contact_name',
                )
            ) {
                const name =
                    String(
                        body.emergency_contact_name ??
                        '',
                    ).trim();

                if (
                    name.length >
                    150
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Emergency contact name is too long.',
                        code:
                            'INVALID_EMERGENCY_NAME',
                    });
                }

                addField(
                    'emergency_contact_name',
                    name || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'emergency_contact_phone',
                )
            ) {
                const phone =
                    String(
                        body.emergency_contact_phone ??
                        '',
                    ).trim();

                if (
                    phone.length >
                    30
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Emergency contact phone number is invalid.',
                        code:
                            'INVALID_EMERGENCY_PHONE',
                    });
                }

                addField(
                    'emergency_contact_phone',
                    phone || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'emergency_relationship',
                )
            ) {
                const relationship =
                    String(
                        body.emergency_relationship ??
                        '',
                    ).trim();

                if (
                    relationship.length >
                    100
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Emergency relationship is too long.',
                        code:
                            'INVALID_EMERGENCY_RELATIONSHIP',
                    });
                }

                addField(
                    'emergency_relationship',
                    relationship || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'home_address',
                )
            ) {
                const address =
                    String(
                        body.home_address ??
                        '',
                    ).trim();

                if (
                    address.length >
                    255
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Home address is too long.',
                        code:
                            'INVALID_HOME_ADDRESS',
                    });
                }

                addField(
                    'home_address',
                    address || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'region',
                )
            ) {
                const region =
                    String(
                        body.region ??
                        '',
                    ).trim();

                if (
                    region.length >
                    100
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Region value is too long.',
                        code:
                            'INVALID_REGION',
                    });
                }

                addField(
                    'region',
                    region || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'district',
                )
            ) {
                const district =
                    String(
                        body.district ??
                        '',
                    ).trim();

                if (
                    district.length >
                    100
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'District value is too long.',
                        code:
                            'INVALID_DISTRICT',
                    });
                }

                addField(
                    'district',
                    district || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'town_city',
                )
            ) {
                const townCity =
                    String(
                        body.town_city ??
                        '',
                    ).trim();

                if (
                    townCity.length >
                    100
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Town/City value is too long.',
                        code:
                            'INVALID_TOWN_CITY',
                    });
                }

                addField(
                    'town_city',
                    townCity || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'saved_locations',
                )
            ) {
                const savedLocations =
                    body.saved_locations;

                if (
                    !Array.isArray(
                        savedLocations,
                    )
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'saved_locations must be an array.',
                        code:
                            'INVALID_SAVED_LOCATIONS',
                    });
                }

                values.push(
                    JSON.stringify(
                        savedLocations,
                    ),
                );

                updateParts.push(
                    `saved_locations = $${values.length}::jsonb`,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'preferred_payment_method',
                )
            ) {
                const paymentMethod =
                    String(
                        body.preferred_payment_method ??
                        '',
                    ).trim();

                if (
                    paymentMethod.length >
                    100
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Preferred payment method is too long.',
                        code:
                            'INVALID_PAYMENT_METHOD',
                    });
                }

                addField(
                    'preferred_payment_method',
                    paymentMethod || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'mobile_money_number',
                )
            ) {
                const mobileMoney =
                    String(
                        body.mobile_money_number ??
                        '',
                    ).trim();

                if (
                    mobileMoney.length >
                    30
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Mobile money number is invalid.',
                        code:
                            'INVALID_MOBILE_MONEY_NUMBER',
                    });
                }

                addField(
                    'mobile_money_number',
                    mobileMoney || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'language_preference',
                )
            ) {
                const language =
                    String(
                        body.language_preference ??
                        '',
                    ).trim();

                if (
                    language.length >
                    50
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Language value is too long.',
                        code:
                            'INVALID_LANGUAGE',
                    });
                }

                addField(
                    'language_preference',
                    language || null,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'notification_enabled',
                )
            ) {
                const notificationValue =
                    body.notification_enabled;

                if (
                    typeof notificationValue !==
                    'boolean'
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'notification_enabled must be true or false.',
                        code:
                            'INVALID_NOTIFICATION_VALUE',
                    });
                }

                addField(
                    'notification_enabled',
                    notificationValue,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'privacy_enabled',
                )
            ) {
                const privacyValue =
                    body.privacy_enabled;

                if (
                    typeof privacyValue !==
                    'boolean'
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'privacy_enabled must be true or false.',
                        code:
                            'INVALID_PRIVACY_VALUE',
                    });
                }

                addField(
                    'privacy_enabled',
                    privacyValue,
                );
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    'profile_photo_url',
                )
            ) {
                const photoUrl =
                    String(
                        body.profile_photo_url ??
                        '',
                    ).trim();

                if (
                    photoUrl.length >
                    1000
                ) {
                    client.release();

                    return res.status(400).json({
                        success: false,
                        message:
                            'Profile photo URL is too long.',
                        code:
                            'INVALID_PROFILE_PHOTO_URL',
                    });
                }

                addField(
                    'profile_photo_url',
                    photoUrl || null,
                );
            }

            if (
                updateParts.length ===
                0
            ) {
                client.release();

                return res.status(400).json({
                    success: false,
                    message:
                        'No valid profile fields were provided.',
                    code:
                        'NO_VALID_FIELDS',
                });
            }

            updateParts.push(
                'updated_at = CURRENT_TIMESTAMP',
            );

            await client.query('BEGIN');

            transactionStarted =
                true;

            const passengerResult =
                await client.query(
                    `
                    SELECT
                        id,
                        firebase_uid
                    FROM public.passengers
                    WHERE firebase_uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                passengerResult.rows.length ===
                0
            ) {
                await client.query(
                    'ROLLBACK',
                );

                transactionStarted =
                    false;

                client.release();

                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger profile not found.',
                    code:
                        'PASSENGER_NOT_FOUND',
                });
            }

            values.push(uid);

            const uidParameter =
                values.length;

            const updateResult =
                await client.query(
                    `
                    UPDATE public.passengers
                    SET
                        ${updateParts.join(', ')}
                    WHERE firebase_uid = $${uidParameter}
                    RETURNING
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
                        profile_photo_url,
                        account_status,
                        phone_verified,
                        email_verified,
                        updated_at,
                        is_online,
                        last_online_at,
                        current_latitude,
                        current_longitude,
                        last_location_update,
                        fcm_token
                    `,
                    values,
                );

            if (
                updateResult.rows.length ===
                0
            ) {
                await client.query(
                    'ROLLBACK',
                );

                transactionStarted =
                    false;

                client.release();

                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger profile could not be updated.',
                    code:
                        'PROFILE_UPDATE_FAILED',
                });
            }

            await client.query(
                'COMMIT',
            );

            transactionStarted =
                false;

            client.release();

            console.log(
                `✅ Passenger profile updated: ${uid}`,
                receivedFields,
            );

            return res.status(200).json({
                success: true,
                message:
                    'Profile updated successfully.',
                updatedFields:
                    receivedFields,
                passenger:
                    updateResult.rows[0],
            });
        } catch (error: unknown) {
            if (transactionStarted) {
                try {
                    await client.query(
                        'ROLLBACK',
                    );
                } catch (
                rollbackError
                ) {
                    console.error(
                        '❌ Rollback error:',
                        rollbackError,
                    );
                }
            }

            client.release();

            const e = error as {
                message?: string;
                code?: string;
                detail?: string;
                constraint?: string;
            };

            console.error(
                '❌ Update passenger profile error:',
                e,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to update passenger profile.',
                code:
                    e.code ??
                    'PROFILE_UPDATE_FAILED',
                error:
                    e.message ??
                    'Unknown database error',
                detail:
                    e.detail ?? null,
                constraint:
                    e.constraint ?? null,
            });
        }
    },
);

/* ==========================================================================
 * GET /api/passengers/alerts
 * ========================================================================== */

router.get(
    '/alerts',
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
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        user_id,
                        title,
                        body,
                        category,
                        priority,
                        is_read,
                        target_screen,
                        metadata,
                        created_at
                    FROM public.alerts
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    `,
                    [uid],
                );

            const unreadResult =
                await pool.query(
                    `
                    SELECT
                        COUNT(*)::int AS unread_count
                    FROM public.alerts
                    WHERE user_id = $1
                      AND is_read = false
                    `,
                    [uid],
                );

            const unreadCount =
                Number(
                    unreadResult.rows[0]
                        ?.unread_count ?? 0,
                );

            return res.status(200).json({
                success: true,
                count:
                    result.rows.length,
                unreadCount,
                alerts:
                    result.rows,
            });
        } catch (error: unknown) {
            const e = error as {
                message?: string;
            };

            console.error(
                '❌ Error fetching passenger alerts:',
                e,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to load alerts.',
                code:
                    'ALERTS_FETCH_FAILED',
                error:
                    e.message,
            });
        }
    },
);

/* ==========================================================================
 * PATCH /api/passengers/alerts/:alertId/read
 * ========================================================================== */

router.patch(
    '/alerts/:alertId/read',
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
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const alertId =
                Number(
                    req.params.alertId,
                );

            if (
                !Number.isInteger(
                    alertId,
                ) ||
                alertId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid alert ID.',
                    code:
                        'INVALID_ALERT_ID',
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE public.alerts
                    SET is_read = true
                    WHERE id = $1
                      AND user_id = $2
                    RETURNING
                        id,
                        user_id,
                        title,
                        body,
                        category,
                        priority,
                        is_read,
                        target_screen,
                        metadata,
                        created_at
                    `,
                    [
                        alertId,
                        uid,
                    ],
                );

            if (
                result.rows.length ===
                0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Alert not found.',
                    code:
                        'ALERT_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message:
                    'Alert marked as read.',
                alert:
                    result.rows[0],
            });
        } catch (error: unknown) {
            const e = error as {
                message?: string;
            };

            console.error(
                '❌ Error marking alert as read:',
                e,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to mark alert as read.',
                code:
                    'ALERT_READ_FAILED',
                error:
                    e.message,
            });
        }
    },
);

/* ==========================================================================
 * PATCH /api/passengers/alerts/read-all
 * ========================================================================== */

router.patch(
    '/alerts/read-all',
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
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE public.alerts
                    SET is_read = true
                    WHERE user_id = $1
                      AND is_read = false
                    RETURNING id
                    `,
                    [uid],
                );

            return res.status(200).json({
                success: true,
                message:
                    'All alerts marked as read.',
                updatedCount:
                    result.rows.length,
            });
        } catch (error: unknown) {
            const e = error as {
                message?: string;
            };

            console.error(
                '❌ Error marking all alerts as read:',
                e,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to mark all alerts as read.',
                code:
                    'ALERTS_READ_ALL_FAILED',
                error:
                    e.message,
            });
        }
    },
);

/* ==========================================================================
 * DELETE /api/passengers/alerts/:alertId
 * ========================================================================== */

router.delete(
    '/alerts/:alertId',
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
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const alertId =
                Number(
                    req.params.alertId,
                );

            if (
                !Number.isInteger(
                    alertId,
                ) ||
                alertId <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid alert ID.',
                    code:
                        'INVALID_ALERT_ID',
                });
            }

            const result =
                await pool.query(
                    `
                    DELETE FROM public.alerts
                    WHERE id = $1
                      AND user_id = $2
                    RETURNING id
                    `,
                    [
                        alertId,
                        uid,
                    ],
                );

            if (
                result.rows.length ===
                0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Alert not found.',
                    code:
                        'ALERT_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                message:
                    'Alert deleted successfully.',
                deletedId:
                    alertId,
            });
        } catch (error: unknown) {
            const e = error as {
                message?: string;
            };

            console.error(
                '❌ Error deleting alert:',
                e,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to delete alert.',
                code:
                    'ALERT_DELETE_FAILED',
                error:
                    e.message,
            });
        }
    },
);

/* ==========================================================================
 * DELETE /api/passengers/alerts
 * ========================================================================== */

router.delete(
    '/alerts',
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
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const result =
                await pool.query(
                    `
                    DELETE FROM public.alerts
                    WHERE user_id = $1
                    RETURNING id
                    `,
                    [uid],
                );

            return res.status(200).json({
                success: true,
                message:
                    'All alerts cleared successfully.',
                deletedCount:
                    result.rows.length,
            });
        } catch (error: unknown) {
            const e = error as {
                message?: string;
            };

            console.error(
                '❌ Error clearing passenger alerts:',
                e,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to clear alerts.',
                code:
                    'ALERTS_CLEAR_FAILED',
                error:
                    e.message,
            });
        }
    },
);

/* ==========================================================================
 * POST /api/passengers/update-status
 * ========================================================================== */

router.post(
    '/update-status',
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
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const {
                isOnline,
                latitude,
                longitude,
            } =
                req.body ?? {};

            if (
                typeof isOnline !==
                'boolean'
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'isOnline must be a boolean.',
                    code:
                        'INVALID_STATUS',
                });
            }

            const hasCoords =
                latitude !==
                undefined &&
                longitude !==
                undefined &&
                Number.isFinite(
                    Number(latitude),
                ) &&
                Number.isFinite(
                    Number(longitude),
                );

            const result =
                hasCoords
                    ? await pool.query(
                        `
                        UPDATE public.passengers
                        SET
                            is_online = $1,
                            current_latitude = $2::numeric,
                            current_longitude = $3::numeric,
                            last_location_update = NOW(),
                            last_online_at = NOW(),
                            updated_at = NOW()
                        WHERE firebase_uid = $4
                        RETURNING
                            id,
                            firebase_uid,
                            is_online,
                            current_latitude,
                            current_longitude,
                            last_online_at,
                            last_location_update
                        `,
                        [
                            isOnline,
                            Number(latitude),
                            Number(longitude),
                            uid,
                        ],
                    )
                    : await pool.query(
                        `
                        UPDATE public.passengers
                        SET
                            is_online = $1,
                            last_online_at = NOW(),
                            updated_at = NOW()
                        WHERE firebase_uid = $2
                        RETURNING
                            id,
                            firebase_uid,
                            is_online,
                            last_online_at
                        `,
                        [
                            isOnline,
                            uid,
                        ],
                    );

            if (
                result.rows.length ===
                0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger not found.',
                    code:
                        'PASSENGER_NOT_FOUND',
                });
            }

            console.log(
                '✅ PASSENGER STATUS UPDATED',
                result.rows[0],
            );

            return res.status(200).json({
                success: true,
                message:
                    'Passenger status updated.',
                passenger:
                    result.rows[0],
            });
        } catch (error: unknown) {
            const e = error as {
                message?: string;
            };

            console.error(
                '❌ Error updating passenger status:',
                e,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to update passenger status.',
                code:
                    'STATUS_UPDATE_FAILED',
                error:
                    e.message,
            });
        }
    },
);

/* ==========================================================================
 * GET /api/passengers/nearby
 * ========================================================================== */

router.get(
    '/nearby',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const {
                lat,
                lng,
                radius = 5000,
            } =
                req.query;

            if (
                lat === undefined ||
                lng === undefined
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Missing required query params: lat and lng.',
                    code:
                        'MISSING_PARAMETERS',
                });
            }

            const latitude =
                Number(lat);

            const longitude =
                Number(lng);

            const searchRadius =
                Number(radius);

            if (
                !Number.isFinite(
                    latitude,
                ) ||
                !Number.isFinite(
                    longitude,
                ) ||
                !Number.isFinite(
                    searchRadius,
                ) ||
                searchRadius <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid numeric values for lat, lng, or radius.',
                    code:
                        'INVALID_PARAMETERS',
                });
            }

            const postgisQuery = `
                SELECT
                    id,
                    firebase_uid,
                    full_name,
                    phone,
                    profile_photo_url,
                    current_latitude,
                    current_longitude,
                    is_online,
                    last_online_at,
                    ROUND(
                        ST_Distance(
                            ST_SetSRID(
                                ST_MakePoint(
                                    current_longitude::double precision,
                                    current_latitude::double precision
                                ),
                                4326
                            )::geography,
                            ST_SetSRID(
                                ST_MakePoint(
                                    $1::double precision,
                                    $2::double precision
                                ),
                                4326
                            )::geography
                        )
                    )::int AS distance_meters
                FROM public.passengers
                WHERE is_online = true
                  AND account_status = 'active'
                  AND current_latitude IS NOT NULL
                  AND current_longitude IS NOT NULL
                  AND ST_DWithin(
                        ST_SetSRID(
                            ST_MakePoint(
                                current_longitude::double precision,
                                current_latitude::double precision
                            ),
                            4326
                        )::geography,
                        ST_SetSRID(
                            ST_MakePoint(
                                $1::double precision,
                                $2::double precision
                            ),
                            4326
                        )::geography,
                        $3::double precision
                    )
                ORDER BY distance_meters ASC
                LIMIT 50;
            `;

            const haversineQuery = `
                WITH candidates AS (
                    SELECT
                        id,
                        firebase_uid,
                        full_name,
                        phone,
                        profile_photo_url,
                        current_latitude,
                        current_longitude,
                        is_online,
                        last_online_at,
                        current_latitude::double precision AS lat_num,
                        current_longitude::double precision AS lng_num
                    FROM public.passengers
                    WHERE is_online = true
                      AND account_status = 'active'
                      AND current_latitude IS NOT NULL
                      AND current_longitude IS NOT NULL
                ),
                distances AS (
                    SELECT
                        *,
                        6371000 * 2 * ASIN(
                            SQRT(
                                POWER(
                                    SIN(
                                        RADIANS(
                                            lat_num -
                                            $2::double precision
                                        ) / 2
                                    ),
                                    2
                                ) +
                                COS(
                                    RADIANS(
                                        $2::double precision
                                    )
                                ) *
                                COS(
                                    RADIANS(lat_num)
                                ) *
                                POWER(
                                    SIN(
                                        RADIANS(
                                            lng_num -
                                            $1::double precision
                                        ) / 2
                                    ),
                                    2
                                )
                            )
                        ) AS distance_meters
                    FROM candidates
                )
                SELECT
                    id,
                    firebase_uid,
                    full_name,
                    phone,
                    profile_photo_url,
                    current_latitude,
                    current_longitude,
                    is_online,
                    last_online_at,
                    ROUND(distance_meters)::int AS distance_meters
                FROM distances
                WHERE distance_meters <= $3::double precision
                ORDER BY distance_meters ASC
                LIMIT 50;
            `;

            const params = [
                longitude,
                latitude,
                searchRadius,
            ];

            let result;

            try {
                result =
                    await pool.query(
                        postgisQuery,
                        params,
                    );
            } catch (
            postgisErr: unknown
            ) {
                const pe =
                    postgisErr as {
                        code?: string;
                        message?: string;
                    };

                if (
                    pe.code ===
                    '42883' ||
                    pe.code ===
                    '42703' ||
                    pe.code ===
                    '42804'
                ) {
                    console.warn(
                        '⚠️ PostGIS unavailable. Falling back to Haversine.',
                        pe.message,
                    );

                    result =
                        await pool.query(
                            haversineQuery,
                            params,
                        );
                } else {
                    throw postgisErr;
                }
            }

            return res.status(200).json({
                success: true,
                count:
                    result.rows.length,
                passengers:
                    result.rows,
            });
        } catch (error: unknown) {
            const e = error as {
                message?: string;
                code?: string;
            };

            console.error(
                '❌ Error fetching nearby passengers:',
                e,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to fetch nearby passengers.',
                code:
                    'NEARBY_PASSENGERS_FAILED',
                error:
                    e.message,
            });
        }
    },
);

/* ==========================================================================
 * GET /api/passengers/wallet
 * ========================================================================== */

router.get(
    '/wallet',
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
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const passengerResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        firebase_uid,
                        full_name,
                        phone,
                        email
                    FROM public.passengers
                    WHERE firebase_uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                passengerResult.rows.length ===
                0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger account not found.',
                    code:
                        'PASSENGER_NOT_FOUND',
                });
            }

            const passenger =
                passengerResult.rows[0];

            const walletResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        passenger_id,
                        balance,
                        pending_balance,
                        total_spent,
                        last_transaction_at,
                        created_at,
                        updated_at
                    FROM public.wallets
                    WHERE passenger_id = $1
                    LIMIT 1
                    `,
                    [passenger.id],
                );

            if (
                walletResult.rows.length ===
                0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Wallet not found.',
                    code:
                        'WALLET_NOT_FOUND',
                });
            }

            return res.status(200).json({
                success: true,
                wallet:
                    walletResult.rows[0],
            });
        } catch (error: unknown) {
            const e = error as {
                message?: string;
            };

            console.error(
                '❌ Error fetching passenger wallet:',
                e,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to fetch wallet.',
                code:
                    'WALLET_FETCH_FAILED',
                error:
                    e.message,
            });
        }
    },
);

/* ==========================================================================
 * POST /api/passengers/wallet
 * ========================================================================== */

router.post(
    '/wallet',
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
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const passengerResult =
                await pool.query(
                    `
                    SELECT id
                    FROM public.passengers
                    WHERE firebase_uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                passengerResult.rows.length ===
                0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger account not found.',
                    code:
                        'PASSENGER_NOT_FOUND',
                });
            }

            const passengerId =
                passengerResult.rows[0].id;

            const existingWallet =
                await pool.query(
                    `
                    SELECT
                        id,
                        passenger_id,
                        balance,
                        pending_balance,
                        total_spent,
                        last_transaction_at,
                        created_at,
                        updated_at
                    FROM public.wallets
                    WHERE passenger_id = $1
                    LIMIT 1
                    `,
                    [passengerId],
                );

            if (
                existingWallet.rows.length >
                0
            ) {
                return res.status(200).json({
                    success: true,
                    message:
                        'Wallet already exists.',
                    wallet:
                        existingWallet.rows[0],
                    alreadyExists:
                        true,
                });
            }

            const walletResult =
                await pool.query(
                    `
                    INSERT INTO public.wallets (
                        passenger_id,
                        balance,
                        pending_balance,
                        total_spent,
                        last_transaction_at,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        $1,
                        0.00,
                        0.00,
                        0.00,
                        NULL,
                        NOW(),
                        NOW()
                    )
                    RETURNING
                        id,
                        passenger_id,
                        balance,
                        pending_balance,
                        total_spent,
                        last_transaction_at,
                        created_at,
                        updated_at
                    `,
                    [passengerId],
                );

            return res.status(201).json({
                success: true,
                message:
                    'Wallet created successfully.',
                wallet:
                    walletResult.rows[0],
                alreadyExists:
                    false,
            });
        } catch (error: unknown) {
            const e = error as {
                message?: string;
                code?: string;
            };

            console.error(
                '❌ Error creating passenger wallet:',
                e,
            );

            if (
                e.code === '23505'
            ) {
                return res.status(409).json({
                    success: false,
                    message:
                        'Wallet already exists.',
                    code:
                        'WALLET_ALREADY_EXISTS',
                });
            }

            return res.status(500).json({
                success: false,
                message:
                    'Failed to create wallet.',
                code:
                    'WALLET_CREATE_FAILED',
                error:
                    e.message,
            });
        }
    },
);

/* ==========================================================================
 * GET /api/passengers/transactions
 * ========================================================================== */

router.get(
    '/transactions',
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
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const passengerResult =
                await pool.query(
                    `
                    SELECT id
                    FROM public.passengers
                    WHERE firebase_uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                passengerResult.rows.length ===
                0
            ) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger account not found.',
                    code:
                        'PASSENGER_NOT_FOUND',
                });
            }

            const passengerId =
                passengerResult.rows[0].id;

            let page =
                Number(
                    req.query.page ??
                    1,
                );

            let limit =
                Number(
                    req.query.limit ??
                    20,
                );

            if (
                !Number.isFinite(
                    page,
                ) ||
                page < 1
            ) {
                page = 1;
            }

            if (
                !Number.isFinite(
                    limit,
                ) ||
                limit < 1
            ) {
                limit = 20;
            }

            page =
                Math.floor(page);

            limit =
                Math.min(
                    Math.floor(
                        limit,
                    ),
                    100,
                );

            const offset =
                (page - 1) *
                limit;

            const type =
                typeof req.query.type ===
                    'string'
                    ? req.query.type.trim()
                    : null;

            const status =
                typeof req.query.status ===
                    'string'
                    ? req.query.status.trim()
                    : null;

            const conditions: string[] =
                [
                    't.passenger_id = $1',
                ];

            const values: unknown[] =
                [passengerId];

            let parameterIndex =
                2;

            if (type) {
                conditions.push(
                    `t.type = $${parameterIndex}`,
                );

                values.push(type);

                parameterIndex++;
            }

            if (status) {
                conditions.push(
                    `t.status = $${parameterIndex}`,
                );

                values.push(status);

                parameterIndex++;
            }

            const limitParameter =
                parameterIndex;

            const offsetParameter =
                parameterIndex + 1;

            values.push(limit);
            values.push(offset);

            const transactionQuery =
                `
                SELECT
                    t.id,
                    t.wallet_id,
                    t.passenger_id,
                    t.ride_id,
                    t.amount,
                    t.type,
                    t.status,
                    t.payment_method,
                    t.provider,
                    t.provider_reference,
                    t.balance_before,
                    t.balance_after,
                    t.description,
                    t.metadata,
                    t.created_at,
                    t.updated_at
                FROM public.transactions t
                WHERE ${conditions.join(
                    ' AND ',
                )}
                ORDER BY t.created_at DESC
                LIMIT $${limitParameter}
                OFFSET $${offsetParameter}
                `;

            const result =
                await pool.query(
                    transactionQuery,
                    values,
                );

            const countValues:
                unknown[] =
                [passengerId];

            const countConditions:
                string[] =
                [
                    'passenger_id = $1',
                ];

            let countParameterIndex =
                2;

            if (type) {
                countConditions.push(
                    `type = $${countParameterIndex}`,
                );

                countValues.push(
                    type,
                );

                countParameterIndex++;
            }

            if (status) {
                countConditions.push(
                    `status = $${countParameterIndex}`,
                );

                countValues.push(
                    status,
                );
            }

            const countResult =
                await pool.query(
                    `
                    SELECT
                        COUNT(*)::int AS total
                    FROM public.transactions
                    WHERE ${countConditions.join(
                        ' AND ',
                    )}
                    `,
                    countValues,
                );

            const total =
                Number(
                    countResult.rows[0]
                        ?.total ?? 0,
                );

            return res.status(200).json({
                success: true,
                transactions:
                    result.rows,
                count:
                    result.rows.length,
                page,
                limit,
                total,
                totalPages:
                    Math.ceil(
                        total / limit,
                    ),
            });
        } catch (error: unknown) {
            const e = error as {
                message?: string;
            };

            console.error(
                '❌ Error fetching wallet transactions:',
                e,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to fetch transactions.',
                code:
                    'TRANSACTIONS_FETCH_FAILED',
                error:
                    e.message,
            });
        }
    },
);

/* ==========================================================================
 * GET /api/passengers/wallet/pending-payment-ride
 *
 * Returns the passenger's most recent COMPLETED but UNPAID ride, together
 * with the assigned driver's details, so the "Pay for Ride" dialog can
 * pre-fill ride_id, amount, driver name, driver ID and vehicle info.
 *
 * Returns { success: true, ride: null } when there is nothing to pay.
 * ========================================================================== */

router.get(
    '/wallet/pending-payment-ride',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        try {
            const uid = getAuthenticatedUid(req);

            if (!uid) {
                return res.status(401).json({
                    success: false,
                    message: 'Authenticated user not found.',
                    code: 'AUTH_USER_MISSING',
                });
            }

            const passengerResult = await pool.query(
                `
                SELECT id
                FROM public.passengers
                WHERE firebase_uid = $1
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger account not found.',
                    code: 'PASSENGER_NOT_FOUND',
                });
            }

            const passengerId = passengerResult.rows[0].id;

            const rideResult = await pool.query(
                `
                SELECT
                    r.id                            AS ride_id,
                    r.fare                          AS amount,
                    r.driver_id                     AS driver_id,
                    r.completed_at                  AS completed_at,
                    r.payment_status                AS payment_status,

                    d.full_name                     AS driver_name,
                    d.profile_photo_url             AS driver_photo_url,
                    d.vehicle_type                  AS vehicle_type,
                    d.vehicle_model                 AS vehicle_model,
                    d.vehicle_color                 AS vehicle_color,
                    d.registration_number           AS vehicle_registration,
                    d.vehicle_year                  AS vehicle_year
                FROM public.rides r
                LEFT JOIN public.drivers d
                    ON d.uid = r.driver_id
                WHERE r.passenger_id = $1
                  AND r.status = 'completed'
                  AND COALESCE(r.payment_status, 'pending') <> 'paid'
                ORDER BY
                    r.completed_at DESC NULLS LAST,
                    r.id DESC
                LIMIT 1
                `,
                [passengerId],
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
                    ride_id: ride.ride_id,
                    amount: Number(ride.amount),
                    driver_id: ride.driver_id,
                    driver_name: ride.driver_name,
                    driver_photo_url: ride.driver_photo_url,
                    vehicle_type: ride.vehicle_type,
                    vehicle_model: ride.vehicle_model,
                    vehicle_color: ride.vehicle_color,
                    vehicle_registration: ride.vehicle_registration,
                    vehicle_year: ride.vehicle_year,
                    completed_at: ride.completed_at,
                    payment_status: ride.payment_status ?? 'pending',
                },
            });
        } catch (error: unknown) {
            const e = error as { message?: string };

            console.error(
                '❌ Error fetching pending payment ride:',
                e,
            );

            return res.status(500).json({
                success: false,
                message: 'Failed to load pending payment ride.',
                code: 'PENDING_RIDE_FETCH_FAILED',
                error: e.message,
            });
        }
    },
);

/* ==========================================================================
 * POST /api/passengers/wallet/topup
 *
 * DEVELOPMENT / TESTING VERSION
 *
 * Creates:
 *
 * 1. Wallet balance update
 * 2. Wallet transaction
 * 3. Persistent Alert Screen notification
 * 4. FCM notification after COMMIT
 * ========================================================================== */

router.post(
    '/wallet/topup',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        const client =
            await pool.connect();

        let transactionStarted =
            false;

        try {
            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                client.release();

                return res.status(401).json({
                    success: false,
                    message:
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const amount =
                Number(
                    req.body?.amount,
                );

            const paymentMethod =
                typeof req.body?.payment_method ===
                    'string'
                    ? req.body.payment_method.trim()
                    : null;

            const provider =
                typeof req.body?.provider ===
                    'string'
                    ? req.body.provider.trim()
                    : null;

            const providerReference =
                typeof req.body?.provider_reference ===
                    'string'
                    ? req.body.provider_reference.trim()
                    : null;

            if (
                !Number.isFinite(
                    amount,
                ) ||
                amount <= 0
            ) {
                client.release();

                return res.status(400).json({
                    success: false,
                    message:
                        'Top-up amount must be greater than zero.',
                    code:
                        'INVALID_AMOUNT',
                });
            }

            if (
                amount >
                100000
            ) {
                client.release();

                return res.status(400).json({
                    success: false,
                    message:
                        'Top-up amount is too large.',
                    code:
                        'AMOUNT_TOO_LARGE',
                });
            }

            await client.query(
                'BEGIN',
            );

            transactionStarted =
                true;

            const passengerResult =
                await client.query(
                    `
                    SELECT
                        id,
                        firebase_uid,
                        full_name
                    FROM public.passengers
                    WHERE firebase_uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                passengerResult.rows.length ===
                0
            ) {
                await client.query(
                    'ROLLBACK',
                );

                transactionStarted =
                    false;

                client.release();

                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger account not found.',
                    code:
                        'PASSENGER_NOT_FOUND',
                });
            }

            const passenger =
                passengerResult.rows[0];

            const passengerId =
                passenger.id;

            const walletResult =
                await client.query(
                    `
                    SELECT
                        id,
                        passenger_id,
                        balance,
                        pending_balance,
                        total_spent,
                        last_transaction_at,
                        created_at,
                        updated_at
                    FROM public.wallets
                    WHERE passenger_id = $1
                    FOR UPDATE
                    `,
                    [passengerId],
                );

            if (
                walletResult.rows.length ===
                0
            ) {
                await client.query(
                    'ROLLBACK',
                );

                transactionStarted =
                    false;

                client.release();

                return res.status(404).json({
                    success: false,
                    message:
                        'Wallet not found.',
                    code:
                        'WALLET_NOT_FOUND',
                });
            }

            const wallet =
                walletResult.rows[0];

            const balanceBefore =
                Number(
                    wallet.balance,
                );

            const balanceAfter =
                balanceBefore +
                amount;

            const updatedWalletResult =
                await client.query(
                    `
                    UPDATE public.wallets
                    SET
                        balance = $1,
                        last_transaction_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $2
                    RETURNING
                        id,
                        passenger_id,
                        balance,
                        pending_balance,
                        total_spent,
                        last_transaction_at,
                        created_at,
                        updated_at
                    `,
                    [
                        balanceAfter,
                        wallet.id,
                    ],
                );

            const transactionResult =
                await client.query(
                    `
                    INSERT INTO public.transactions (
                        wallet_id,
                        passenger_id,
                        ride_id,
                        amount,
                        type,
                        status,
                        payment_method,
                        provider,
                        provider_reference,
                        balance_before,
                        balance_after,
                        description,
                        metadata,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        $1,
                        $2,
                        NULL,
                        $3,
                        'topup',
                        'completed',
                        $4,
                        $5,
                        $6,
                        $7,
                        $8,
                        $9,
                        $10::jsonb,
                        NOW(),
                        NOW()
                    )
                    RETURNING
                        id,
                        wallet_id,
                        passenger_id,
                        ride_id,
                        amount,
                        type,
                        status,
                        payment_method,
                        provider,
                        provider_reference,
                        balance_before,
                        balance_after,
                        description,
                        metadata,
                        created_at,
                        updated_at
                    `,
                    [
                        wallet.id,
                        passengerId,
                        amount,
                        paymentMethod,
                        provider,
                        providerReference,
                        balanceBefore,
                        balanceAfter,
                        'Wallet top-up',
                        JSON.stringify({
                            firebase_uid:
                                uid,

                            provider_reference:
                                providerReference ??
                                '',
                        }),
                    ],
                );

            const transaction =
                transactionResult.rows[0];

            const alertTitle =
                'Wallet Funded';

            const alertBody =
                `Your wallet has been credited with GH₵${amount.toFixed(2)}. ` +
                `New balance: GH₵${balanceAfter.toFixed(2)}.`;

            await createAlert(
                client,
                uid,
                alertTitle,
                alertBody,
                'payment',
                'normal',
                'wallet',
                {
                    notificationType:
                        'wallet_topup_success',

                    amount:
                        amount,

                    transactionId:
                        String(
                            transaction.id,
                        ),

                    balanceBefore:
                        balanceBefore,

                    balanceAfter:
                        balanceAfter,

                    paymentMethod:
                        paymentMethod ??
                        '',

                    provider:
                        provider ??
                        '',

                    providerReference:
                        providerReference ??
                        '',

                    status:
                        'completed',
                },
            );

            await client.query(
                'COMMIT',
            );

            transactionStarted =
                false;

            client.release();

            const fcmToken =
                await getUserFcmToken(
                    uid,
                );

            if (fcmToken) {
                await sendFcmNotification(
                    fcmToken,
                    alertTitle,
                    alertBody,
                    {
                        role:
                            'passenger',

                        notificationType:
                            'wallet_topup_success',

                        targetScreen:
                            'wallet',

                        amount:
                            amount.toFixed(
                                2,
                            ),

                        transactionId:
                            String(
                                transaction.id,
                            ),

                        balance:
                            balanceAfter.toFixed(
                                2,
                            ),

                        status:
                            'completed',
                    },
                );
            }

            console.log(
                `💰 Passenger wallet top-up: ` +
                `passenger=${passengerId}, ` +
                `amount=GH₵${amount.toFixed(2)}, ` +
                `balance=GH₵${balanceAfter.toFixed(2)}`,
            );

            return res.status(201).json({
                success: true,

                message:
                    'Wallet topped up successfully.',

                wallet:
                    updatedWalletResult
                        .rows[0],

                transaction:
                    transaction,

                paymentDisplay: {
                    title:
                        alertTitle,

                    message:
                        alertBody,

                    amount:
                        amount,

                    currency:
                        'GHS',

                    status:
                        'completed',

                    type:
                        'wallet_topup',

                    paymentMethod:
                        paymentMethod ??
                        '',

                    provider:
                        provider ??
                        '',

                    providerReference:
                        providerReference ??
                        '',

                    balanceBefore:
                        balanceBefore,

                    balanceAfter:
                        balanceAfter,

                    transactionId:
                        transaction.id,
                },
            });
        } catch (error: unknown) {
            if (transactionStarted) {
                try {
                    await client.query(
                        'ROLLBACK',
                    );
                } catch (
                rollbackError
                ) {
                    console.error(
                        '❌ Rollback error:',
                        rollbackError,
                    );
                }
            }

            client.release();

            const e = error as {
                message?: string;
                code?: string;
                detail?: string;
                constraint?: string;
                hint?: string;
                table?: string;
                column?: string;
            };

            console.error(
                '❌ Error processing wallet top-up:',
            );

            console.error(
                '   code       :',
                e.code,
            );

            console.error(
                '   message    :',
                e.message,
            );

            console.error(
                '   detail     :',
                e.detail,
            );

            console.error(
                '   constraint :',
                e.constraint,
            );

            console.error(
                '   table      :',
                e.table,
            );

            console.error(
                '   column     :',
                e.column,
            );

            console.error(
                '   hint       :',
                e.hint,
            );

            return res.status(500).json({
                success: false,
                message:
                    'Failed to process wallet top-up.',
                code:
                    e.code ??
                    'WALLET_TOPUP_FAILED',
                error:
                    e.message ??
                    'Unknown database error',
                detail:
                    e.detail ??
                    null,
                constraint:
                    e.constraint ??
                    null,
                table:
                    e.table ??
                    null,
                column:
                    e.column ??
                    null,
            });
        }
    },
);

/* ==========================================================================
 * POST /api/passengers/wallet/pay
 *
 * Passenger pays for a completed ride using wallet.
 *
 * PASSENGER:
 *   - Wallet debit
 *   - Passenger transaction
 *   - Persistent payment alert
 *   - FCM payment notification
 *
 * DRIVER:
 *   - Pending earning settlement
 *   - Driver transaction
 *   - Persistent earning alert
 *   - FCM earning notification
 *
 * IMPORTANT:
 * Driver settlement is protected by SAVEPOINT.
 *
 * If driver settlement fails, passenger payment still succeeds.
 * ========================================================================== */

router.post(
    '/wallet/pay',
    verifyFirebaseToken,
    async (
        req: AuthenticatedRequest,
        res: Response,
    ) => {
        const client =
            await pool.connect();

        let transactionStarted =
            false;

        let driverSettlementSucceeded =
            false;

        let settledAmount =
            0;

        let driverBalanceBefore =
            0;

        let driverBalanceAfter =
            0;

        let driverFirebaseUid:
            string | null = null;

        try {
            const uid =
                getAuthenticatedUid(req);

            if (!uid) {
                client.release();

                return res.status(401).json({
                    success: false,
                    message:
                        'Authenticated user not found.',
                    code:
                        'AUTH_USER_MISSING',
                });
            }

            const rideId =
                Number(
                    req.body?.ride_id,
                );

            const clientAmount =
                Number(
                    req.body?.amount,
                );

            if (
                !Number.isInteger(
                    rideId,
                ) ||
                rideId <= 0
            ) {
                client.release();

                return res.status(400).json({
                    success: false,
                    message:
                        'Invalid ride ID.',
                    code:
                        'INVALID_RIDE_ID',
                });
            }

            if (
                !Number.isFinite(
                    clientAmount,
                ) ||
                clientAmount <= 0
            ) {
                client.release();

                return res.status(400).json({
                    success: false,
                    message:
                        'Payment amount must be greater than zero.',
                    code:
                        'INVALID_AMOUNT',
                });
            }

            await client.query(
                'BEGIN',
            );

            transactionStarted =
                true;

            /* ------------------------------------------------------------
             * PASSENGER
             * ------------------------------------------------------------ */

            const passengerResult =
                await client.query(
                    `
                    SELECT
                        id,
                        firebase_uid,
                        full_name
                    FROM public.passengers
                    WHERE firebase_uid = $1
                    LIMIT 1
                    `,
                    [uid],
                );

            if (
                passengerResult.rows.length ===
                0
            ) {
                await client.query(
                    'ROLLBACK',
                );

                transactionStarted =
                    false;

                client.release();

                return res.status(404).json({
                    success: false,
                    message:
                        'Passenger account not found.',
                    code:
                        'PASSENGER_NOT_FOUND',
                });
            }

            const passenger =
                passengerResult.rows[0];

            const passengerId =
                passenger.id;

            /* ------------------------------------------------------------
             * RIDE + LOCK
             * ------------------------------------------------------------ */

            const rideResult =
                await client.query(
                    `
                    SELECT
                        id,
                        passenger_id,
                        driver_id,
                        fare,
                        status,
                        payment_status,
                        driver_earnings,
                        tegaara_commission
                    FROM public.rides
                    WHERE id = $1
                      AND passenger_id = $2
                    LIMIT 1
                    FOR UPDATE
                    `,
                    [
                        rideId,
                        passengerId,
                    ],
                );

            if (
                rideResult.rows.length ===
                0
            ) {
                await client.query(
                    'ROLLBACK',
                );

                transactionStarted =
                    false;

                client.release();

                return res.status(404).json({
                    success: false,
                    message:
                        'Ride not found for this passenger.',
                    code:
                        'RIDE_NOT_FOUND',
                });
            }

            const ride =
                rideResult.rows[0];

            if (
                ride.status !==
                'completed'
            ) {
                await client.query(
                    'ROLLBACK',
                );

                transactionStarted =
                    false;

                client.release();

                return res.status(409).json({
                    success: false,
                    message:
                        'Only completed rides can be paid for.',
                    code:
                        'RIDE_NOT_COMPLETED',
                    status:
                        ride.status,
                });
            }

            if (
                ride.payment_status ===
                'paid'
            ) {
                await client.query(
                    'ROLLBACK',
                );

                transactionStarted =
                    false;

                client.release();

                return res.status(409).json({
                    success: false,
                    message:
                        'This ride has already been paid for.',
                    code:
                        'RIDE_ALREADY_PAID',
                    rideId,
                });
            }

            const amount =
                Number(
                    ride.fare,
                );

            if (
                !Number.isFinite(
                    amount,
                ) ||
                amount <= 0
            ) {
                await client.query(
                    'ROLLBACK',
                );

                transactionStarted =
                    false;

                client.release();

                return res.status(400).json({
                    success: false,
                    message:
                        'Ride fare is invalid.',
                    code:
                        'INVALID_RIDE_FARE',
                });
            }

            if (
                Math.abs(
                    amount -
                    clientAmount,
                ) >
                0.01
            ) {
                console.warn(
                    `⚠️ Client amount (${clientAmount}) differs from DB ` +
                    `fare (${amount}) for ride ${rideId}. Using DB fare.`,
                );
            }

            /* ------------------------------------------------------------
             * PASSENGER WALLET
             * ------------------------------------------------------------ */

            const walletResult =
                await client.query(
                    `
                    SELECT
                        id,
                        passenger_id,
                        balance,
                        pending_balance,
                        total_spent,
                        last_transaction_at,
                        created_at,
                        updated_at
                    FROM public.wallets
                    WHERE passenger_id = $1
                    FOR UPDATE
                    `,
                    [passengerId],
                );

            if (
                walletResult.rows.length ===
                0
            ) {
                await client.query(
                    'ROLLBACK',
                );

                transactionStarted =
                    false;

                client.release();

                return res.status(404).json({
                    success: false,
                    message:
                        'Wallet not found.',
                    code:
                        'WALLET_NOT_FOUND',
                });
            }

            const wallet =
                walletResult.rows[0];

            const balanceBefore =
                Number(
                    wallet.balance,
                );

            if (
                balanceBefore <
                amount
            ) {
                await client.query(
                    'ROLLBACK',
                );

                transactionStarted =
                    false;

                client.release();

                return res.status(400).json({
                    success: false,
                    message:
                        'Insufficient wallet balance.',
                    code:
                        'INSUFFICIENT_BALANCE',
                    balance:
                        balanceBefore,
                    required:
                        amount,
                });
            }

            const balanceAfter =
                balanceBefore -
                amount;

            const totalSpent =
                Number(
                    wallet.total_spent,
                ) +
                amount;

            /* ------------------------------------------------------------
             * DEBIT PASSENGER WALLET
             * ------------------------------------------------------------ */

            const updatedWalletResult =
                await client.query(
                    `
                    UPDATE public.wallets
                    SET
                        balance = $1,
                        total_spent = $2,
                        last_transaction_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $3
                    RETURNING
                        id,
                        passenger_id,
                        balance,
                        pending_balance,
                        total_spent,
                        last_transaction_at,
                        created_at,
                        updated_at
                    `,
                    [
                        balanceAfter,
                        totalSpent,
                        wallet.id,
                    ],
                );

            /* ------------------------------------------------------------
             * PASSENGER TRANSACTION
             * ------------------------------------------------------------ */

            const transactionResult =
                await client.query(
                    `
                    INSERT INTO public.transactions (
                        wallet_id,
                        passenger_id,
                        ride_id,
                        amount,
                        type,
                        status,
                        payment_method,
                        provider,
                        provider_reference,
                        balance_before,
                        balance_after,
                        description,
                        metadata,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        'ride_payment',
                        'completed',
                        'wallet',
                        NULL,
                        NULL,
                        $5,
                        $6,
                        $7,
                        $8::jsonb,
                        NOW(),
                        NOW()
                    )
                    RETURNING
                        id,
                        wallet_id,
                        passenger_id,
                        ride_id,
                        amount,
                        type,
                        status,
                        payment_method,
                        provider,
                        provider_reference,
                        balance_before,
                        balance_after,
                        description,
                        metadata,
                        created_at,
                        updated_at
                    `,
                    [
                        wallet.id,
                        passengerId,
                        rideId,
                        amount,
                        balanceBefore,
                        balanceAfter,
                        'Ride payment',
                        JSON.stringify({
                            firebase_uid:
                                uid,

                            ride_id:
                                rideId,

                            driver_id:
                                ride.driver_id ??
                                null,
                        }),
                    ],
                );

            const passengerTransaction =
                transactionResult.rows[0];

            /* ------------------------------------------------------------
             * DRIVER SETTLEMENT
             * ------------------------------------------------------------ */

            const driverEarnings =
                Number(
                    ride.driver_earnings,
                ) || 0;

            if (
                ride.driver_id &&
                driverEarnings >
                0
            ) {
                driverFirebaseUid =
                    String(
                        ride.driver_id,
                    );

                await client.query(
                    'SAVEPOINT driver_settlement',
                );

                try {
                    const driverResult =
                        await client.query(
                            `
                            SELECT
                                id,
                                uid,
                                full_name
                            FROM public.drivers
                            WHERE uid = $1::text
                            LIMIT 1
                            `,
                            [
                                ride.driver_id,
                            ],
                        );

                    if (
                        driverResult.rows
                            .length ===
                        0
                    ) {
                        throw new Error(
                            `Driver ${ride.driver_id} not found for settlement`,
                        );
                    }

                    const driver =
                        driverResult.rows[0];

                    const driverWalletResult =
                        await client.query(
                            `
                            SELECT
                                id,
                                balance,
                                pending_balance
                            FROM public.driver_wallets
                            WHERE driver_id = $1
                            FOR UPDATE
                            `,
                            [
                                driver.id,
                            ],
                        );

                    if (
                        driverWalletResult
                            .rows.length ===
                        0
                    ) {
                        throw new Error(
                            `Driver wallet not found for driver ${driver.id}`,
                        );
                    }

                    const driverWallet =
                        driverWalletResult
                            .rows[0];

                    const pendingBefore =
                        Number(
                            driverWallet.pending_balance,
                        ) || 0;

                    settledAmount =
                        Math.min(
                            pendingBefore,
                            driverEarnings,
                        );

                    driverBalanceBefore =
                        Number(
                            driverWallet.balance,
                        ) || 0;

                    driverBalanceAfter =
                        driverBalanceBefore +
                        settledAmount;

                    const pendingAfter =
                        pendingBefore -
                        settledAmount;

                    await client.query(
                        `
                        UPDATE public.driver_wallets
                        SET
                            balance = $1,
                            pending_balance = $2,
                            last_transaction_at = NOW(),
                            updated_at = NOW()
                        WHERE id = $3
                        `,
                        [
                            driverBalanceAfter,
                            pendingAfter,
                            driverWallet.id,
                        ],
                    );

                    await client.query(
                        `
                        INSERT INTO public.driver_transactions (
                            driver_id,
                            wallet_id,
                            ride_id,
                            amount,
                            type,
                            status,
                            balance_before,
                            balance_after,
                            transaction_reference,
                            description,
                            metadata,
                            created_at,
                            updated_at
                        )
                        VALUES (
                            $1,
                            $2,
                            $3,
                            $4,
                            'ride_earning',
                            'completed',
                            $5,
                            $6,
                            'SETTLE-' ||
                                $3 ||
                                '-' ||
                                extract(epoch from now())::bigint,
                            $7,
                            $8::jsonb,
                            NOW(),
                            NOW()
                        )
                        `,
                        [
                            driver.id,
                            driverWallet.id,
                            rideId,
                            settledAmount,
                            driverBalanceBefore,
                            driverBalanceAfter,
                            `Ride payment settled for ride #${rideId}`,
                            JSON.stringify({
                                ride_id:
                                    rideId,

                                passenger_id:
                                    passengerId,

                                settled_amount:
                                    settledAmount,

                                pending_before:
                                    pendingBefore,

                                pending_after:
                                    pendingAfter,
                            }),
                        ],
                    );

                    driverSettlementSucceeded =
                        true;

                    await client.query(
                        'RELEASE SAVEPOINT driver_settlement',
                    );

                    console.log(
                        `💵 Driver ${ride.driver_id} settled ` +
                        `GH₵${settledAmount.toFixed(2)} ` +
                        `(balance ${driverBalanceBefore.toFixed(2)} → ` +
                        `${driverBalanceAfter.toFixed(2)}, ` +
                        `pending ${pendingBefore.toFixed(2)} → ` +
                        `${pendingAfter.toFixed(2)})`,
                    );
                } catch (
                driverSettlementError
                ) {
                    await client.query(
                        'ROLLBACK TO SAVEPOINT driver_settlement',
                    );

                    driverSettlementSucceeded =
                        false;

                    settledAmount =
                        0;

                    driverBalanceBefore =
                        0;

                    driverBalanceAfter =
                        0;

                    const dse =
                        driverSettlementError as {
                            message?: string;
                            code?: string;
                            detail?: string;
                            constraint?: string;
                        };

                    console.error(
                        '⚠️ Driver settlement failed. ' +
                        'Passenger payment will still be processed:',
                        {
                            message:
                                dse.message,

                            code:
                                dse.code,

                            detail:
                                dse.detail,

                            constraint:
                                dse.constraint,
                        },
                    );
                }
            }

            /* ------------------------------------------------------------
             * PASSENGER PAYMENT ALERT
             * ------------------------------------------------------------ */

            const passengerAlertTitle =
                'Payment Successful';

            const passengerAlertBody =
                `Your payment of GH₵${amount.toFixed(2)} ` +
                `for ride #${rideId} was successful. ` +
                `Wallet balance: GH₵${balanceAfter.toFixed(2)}.`;

            await createAlert(
                client,
                uid,
                passengerAlertTitle,
                passengerAlertBody,
                'payment',
                'normal',
                'wallet',
                {
                    notificationType:
                        'ride_payment_success',

                    rideId:
                        String(
                            rideId,
                        ),

                    amount:
                        amount,

                    transactionId:
                        String(
                            passengerTransaction.id,
                        ),

                    balanceBefore:
                        balanceBefore,

                    balanceAfter:
                        balanceAfter,

                    paymentMethod:
                        'wallet',

                    status:
                        'completed',
                },
            );

            /* ------------------------------------------------------------
             * DRIVER PAYMENT ALERT
             * ------------------------------------------------------------ */

            if (
                driverSettlementSucceeded &&
                driverFirebaseUid &&
                settledAmount >
                0
            ) {
                const driverAlertTitle =
                    'Ride Payment Received';

                const driverAlertBody =
                    `You received GH₵${settledAmount.toFixed(2)} ` +
                    `from ride #${rideId}. ` +
                    `Wallet balance: GH₵${driverBalanceAfter.toFixed(2)}.`;

                await createAlert(
                    client,
                    driverFirebaseUid,
                    driverAlertTitle,
                    driverAlertBody,
                    'payment',
                    'normal',
                    'driver_wallet',
                    {
                        notificationType:
                            'ride_earning_received',

                        rideId:
                            String(
                                rideId,
                            ),

                        amount:
                            settledAmount,

                        balanceBefore:
                            driverBalanceBefore,

                        balanceAfter:
                            driverBalanceAfter,

                        passengerId:
                            String(
                                passengerId,
                            ),

                        status:
                            'completed',
                    },
                );
            }

            /* ------------------------------------------------------------
             * MARK RIDE AS PAID
             * ------------------------------------------------------------ */

            await client.query(
                `
                UPDATE public.rides
                SET
                    payment_status = 'paid',
                    paid_at = NOW()
                WHERE id = $1
                `,
                [rideId],
            );

            /* ------------------------------------------------------------
             * COMMIT
             * ------------------------------------------------------------ */

            await client.query(
                'COMMIT',
            );

            transactionStarted =
                false;

            client.release();

            console.log(
                `💳 Wallet payment completed: ` +
                `passenger=${passengerId}, ` +
                `ride=${rideId}, ` +
                `amount=GH₵${amount.toFixed(2)}, ` +
                `balance=GH₵${balanceAfter.toFixed(2)}`,
            );

            /* ------------------------------------------------------------
             * PASSENGER FCM
             * ------------------------------------------------------------ */

            const passengerFcmToken =
                await getUserFcmToken(
                    uid,
                );

            if (
                passengerFcmToken
            ) {
                await sendFcmNotification(
                    passengerFcmToken,
                    passengerAlertTitle,
                    passengerAlertBody,
                    {
                        role:
                            'passenger',

                        notificationType:
                            'ride_payment_success',

                        targetScreen:
                            'wallet',

                        rideId:
                            String(
                                rideId,
                            ),

                        amount:
                            amount.toFixed(
                                2,
                            ),

                        transactionId:
                            String(
                                passengerTransaction.id,
                            ),

                        balance:
                            balanceAfter.toFixed(
                                2,
                            ),

                        status:
                            'completed',
                    },
                );
            }

            /* ------------------------------------------------------------
             * DRIVER FCM
             * ------------------------------------------------------------ */

            if (
                driverSettlementSucceeded &&
                driverFirebaseUid &&
                settledAmount >
                0
            ) {
                const driverFcmToken =
                    await getUserFcmToken(
                        driverFirebaseUid,
                    );

                if (
                    driverFcmToken
                ) {
                    await sendFcmNotification(
                        driverFcmToken,
                        'Ride Payment Received',
                        `You received GH₵${settledAmount.toFixed(2)} ` +
                        `from ride #${rideId}.`,
                        {
                            role:
                                'driver',

                            notificationType:
                                'ride_earning_received',

                            targetScreen:
                                'driver_wallet',

                            rideId:
                                String(
                                    rideId,
                                ),

                            amount:
                                settledAmount.toFixed(
                                    2,
                                ),

                            balance:
                                driverBalanceAfter.toFixed(
                                    2,
                                ),

                            status:
                                'completed',
                        },
                    );
                }
            }

            /* ------------------------------------------------------------
             * RESPONSE
             * ------------------------------------------------------------ */

            return res.status(201).json({
                success: true,

                message:
                    'Ride payment completed successfully.',

                wallet:
                    updatedWalletResult
                        .rows[0],

                transaction:
                    passengerTransaction,

                ride: {
                    id:
                        rideId,

                    payment_status:
                        'paid',

                    status:
                        ride.status,
                },

                paymentDisplay: {
                    title:
                        'Payment Successful',

                    message:
                        passengerAlertBody,

                    amount:
                        amount,

                    currency:
                        'GHS',

                    status:
                        'completed',

                    paymentMethod:
                        'wallet',

                    rideId:
                        rideId,

                    transactionId:
                        passengerTransaction.id,

                    balanceBefore:
                        balanceBefore,

                    balanceAfter:
                        balanceAfter,
                },

                driverSettlement: {
                    successful:
                        driverSettlementSucceeded,

                    amount:
                        settledAmount,

                    balance:
                        driverBalanceAfter,
                },

                notifications: {
                    passengerAlert:
                        true,

                    passengerFcm:
                        Boolean(
                            passengerFcmToken,
                        ),

                    driverAlert:
                        driverSettlementSucceeded &&
                        Boolean(
                            driverFirebaseUid,
                        ) &&
                        settledAmount >
                        0,
                },
            });
        } catch (error: unknown) {
            if (transactionStarted) {
                try {
                    await client.query(
                        'ROLLBACK',
                    );
                } catch (
                rollbackError
                ) {
                    console.error(
                        '❌ Rollback error:',
                        rollbackError,
                    );
                }
            }

            client.release();

            const e = error as {
                message?: string;
                code?: string;
                detail?: string;
                constraint?: string;
                hint?: string;
                where?: string;
                table?: string;
                column?: string;
            };

            console.error(
                '❌ Error processing wallet payment:',
            );

            console.error(
                '   code       :',
                e.code,
            );

            console.error(
                '   message    :',
                e.message,
            );

            console.error(
                '   detail     :',
                e.detail,
            );

            console.error(
                '   constraint :',
                e.constraint,
            );

            console.error(
                '   table      :',
                e.table,
            );

            console.error(
                '   column     :',
                e.column,
            );

            console.error(
                '   hint       :',
                e.hint,
            );

            console.error(
                '   where      :',
                e.where,
            );

            return res.status(500).json({
                success: false,

                message:
                    'Failed to process wallet payment.',

                code:
                    e.code ??
                    'WALLET_PAYMENT_FAILED',

                error:
                    e.message ??
                    'Unknown database error',

                detail:
                    e.detail ??
                    null,

                constraint:
                    e.constraint ??
                    null,

                table:
                    e.table ??
                    null,

                column:
                    e.column ??
                    null,
            });
        }
    },
);

/* ==========================================================================
 * EXPORT ROUTER
 * ========================================================================== */

export default router;
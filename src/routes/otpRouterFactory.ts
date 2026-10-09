import { Router, Request, Response } from 'express';
import { sendOtp, verifyOtp, otpConfig } from '../services/otpService';
import { normalizeGhanaPhone } from '../services/sailup.service';
import { firebaseAuth } from '../config/firebase';
import pool from '../config/database';
import { findLatestOtp } from '../models/otpModel';
import type { OtpPurpose, OtpUserType } from '../models/otpModel';

const ALLOWED_PURPOSES: OtpPurpose[] = [
    'registration',
    'login',
    'phone_change',
    'password_reset',
    'general',
];

const normalisePurpose = (value: unknown): OtpPurpose => {
    const v = String(value ?? 'registration').trim() as OtpPurpose;

    return ALLOWED_PURPOSES.includes(v)
        ? v
        : 'registration';
};

/**
 * Find an existing driver/passenger by phone number.
 *
 * Drivers:
 *   drivers.uid
 *
 * Passengers:
 *   passengers.firebase_uid
 *
 * Phone numbers may be stored in different formats, so the
 * comparison uses the final 9 digits.
 */
const findExistingUser = async (
    userType: OtpUserType,
    normalizedPhone: string,
): Promise<{ uid: string } | null> => {
    const table =
        userType === 'driver'
            ? 'drivers'
            : 'passengers';

    const uidColumn =
        userType === 'driver'
            ? 'uid'
            : 'firebase_uid';

    const tail = normalizedPhone.slice(-9);

    const result = await pool.query(
        `
        SELECT ${uidColumn} AS uid
        FROM public.${table}
        WHERE RIGHT(
            REGEXP_REPLACE(phone, '\\D', '', 'g'),
            9
        ) = $1
        LIMIT 1
        `,
        [tail],
    );

    if (result.rows.length === 0) {
        return null;
    }

    const uid = String(
        result.rows[0].uid ?? '',
    ).trim();

    return uid
        ? { uid }
        : null;
};

export const createOtpRouter = (
    userType: OtpUserType,
): Router => {
    const router = Router();

    /* ================================================================
     * POST /otp/send
     *
     * Driver:
     * POST /api/drivers/otp/send
     *
     * Passenger:
     * POST /api/passengers/otp/send
     * ================================================================ */

    router.post(
        '/send',
        async (req: Request, res: Response) => {
            try {
                const {
                    phone,
                    purpose,
                    metadata,
                } = req.body ?? {};

                if (
                    !phone ||
                    typeof phone !== 'string'
                ) {
                    return res.status(400).json({
                        success: false,
                        message: 'phone is required.',
                        code: 'MISSING_PHONE',
                    });
                }

                const normalizedPurpose =
                    normalisePurpose(purpose);

                const revealCode =
                    process.env.NODE_ENV !== 'production' &&
                    process.env.OTP_REVEAL_IN_RESPONSE ===
                    'true';

                const result = await sendOtp({
                    phone,
                    purpose: normalizedPurpose,
                    userType,

                    metadata:
                        metadata &&
                            typeof metadata === 'object'
                            ? (
                                metadata as Record<
                                    string,
                                    unknown
                                >
                            )
                            : undefined,

                    revealCode,
                });

                if (!result.success) {
                    let status = 400;

                    if (
                        result.errorCode ===
                        'RESEND_COOLDOWN' ||
                        result.errorCode ===
                        'RATE_LIMITED'
                    ) {
                        status = 429;
                    } else if (
                        result.errorCode ===
                        'INVALID_PHONE'
                    ) {
                        status = 400;
                    } else if (
                        result.errorCode ===
                        'SMS_SEND_FAILED'
                    ) {
                        status = 502;
                    }

                    return res.status(status).json({
                        success: false,
                        message: result.message,
                        code: result.errorCode,

                        ...(result.cooldownSeconds !==
                            undefined
                            ? {
                                cooldownSeconds:
                                    result.cooldownSeconds,
                            }
                            : {}),
                    });
                }

                return res.status(200).json({
                    success: true,
                    message: result.message,
                    purpose: normalizedPurpose,
                    expiresAt: result.expiresAt,
                    ttlMinutes:
                        otpConfig.ttlMinutes,

                    ...(result.code
                        ? {
                            devCode: result.code,
                        }
                        : {}),
                });
            } catch (error: unknown) {
                const e = error as {
                    message?: string;
                };

                console.error(
                    `❌ OTP send error (${userType}):`,
                    error,
                );

                return res.status(500).json({
                    success: false,
                    message: 'Failed to send OTP.',
                    code: 'OTP_SEND_FAILED',

                    ...(e.message
                        ? {
                            error: e.message,
                        }
                        : {}),
                });
            }
        },
    );

    /* ================================================================
     * POST /otp/verify
     *
     * Driver:
     * POST /api/drivers/otp/verify
     *
     * Passenger:
     * POST /api/passengers/otp/verify
     * ================================================================ */

    router.post(
        '/verify',
        async (req: Request, res: Response) => {
            try {
                const {
                    phone,
                    otp,
                    code,
                    purpose,
                } = req.body ?? {};

                if (
                    !phone ||
                    typeof phone !== 'string'
                ) {
                    return res.status(400).json({
                        success: false,
                        message: 'phone is required.',
                        code: 'MISSING_PHONE',
                    });
                }

                // Support both:
                // { otp: "123456" }
                // and:
                // { code: "123456" }
                const otpValue = otp ?? code;

                if (!otpValue) {
                    return res.status(400).json({
                        success: false,
                        message: 'otp is required.',
                        code: 'MISSING_OTP',
                    });
                }

                const normalizedPurpose =
                    normalisePurpose(purpose);

                const result = await verifyOtp({
                    phone,
                    code: String(otpValue),
                    purpose: normalizedPurpose,
                });

                if (!result.success) {
                    const status =
                        result.errorCode ===
                            'OTP_NOT_FOUND'
                            ? 404
                            : 400;

                    return res.status(status).json({
                        success: false,
                        message: result.message,
                        code: result.errorCode,

                        ...(result.attemptsRemaining !==
                            undefined
                            ? {
                                attemptsRemaining:
                                    result.attemptsRemaining,
                            }
                            : {}),
                    });
                }

                /* ========================================================
                 * LOGIN
                 *
                 * After successful OTP verification:
                 *
                 * 1. Normalize phone
                 * 2. Find driver/passenger
                 * 3. Create Firebase custom token
                 * 4. Return token to Flutter
                 * ======================================================== */

                if (
                    normalizedPurpose === 'login'
                ) {
                    const normalizedPhone =
                        normalizeGhanaPhone(phone);

                    if (!normalizedPhone) {
                        return res.status(400).json({
                            success: false,
                            message:
                                'Invalid phone number.',
                            code: 'INVALID_PHONE',
                        });
                    }

                    const existing =
                        await findExistingUser(
                            userType,
                            normalizedPhone,
                        );

                    if (!existing) {
                        return res.status(200).json({
                            success: true,
                            message:
                                'OTP verified. No account found for this number.',
                            purpose:
                                normalizedPurpose,
                            phone,
                            userType,
                            notRegistered: true,
                            customToken: null,
                        });
                    }

                    const customToken =
                        await firebaseAuth.createCustomToken(
                            existing.uid,
                        );

                    return res.status(200).json({
                        success: true,
                        message:
                            'OTP verified successfully.',
                        purpose:
                            normalizedPurpose,
                        phone,
                        userType,
                        notRegistered: false,
                        uid: existing.uid,
                        customToken,
                    });
                }

                /* ========================================================
                 * REGISTRATION
                 *
                 * After successful OTP verification:
                 *
                 * 1. Normalize phone
                 * 2. Reject if the phone number is already registered
                 *    for this role (drivers/passengers).
                 * 3. Create (or reuse) the Firebase user tied to that
                 *    phone number.
                 * 4. Return a Firebase custom token so Flutter can
                 *    signInWithCustomToken() and then persist the
                 *    driver/passenger record via its own DB service.
                 * ======================================================== */

                if (
                    normalizedPurpose === 'registration'
                ) {
                    const normalizedPhone =
                        normalizeGhanaPhone(phone);

                    if (!normalizedPhone) {
                        return res.status(400).json({
                            success: false,
                            message:
                                'Invalid phone number.',
                            code: 'INVALID_PHONE',
                        });
                    }

                    // 1) Reject duplicate registration
                    //    (same phone, same role).
                    const existing =
                        await findExistingUser(
                            userType,
                            normalizedPhone,
                        );

                    if (existing) {
                        return res.status(409).json({
                            success: false,
                            message:
                                'This phone number is already registered. ' +
                                'Please register with a different phone number.',
                            code: 'PHONE_ALREADY_EXISTS',
                            uid: existing.uid,
                        });
                    }

                    // 2) Pull the metadata captured at /otp/send time.
                    //    findLatestOtp does NOT filter on consumed_at,
                    //    so this still works after verifyOtp() has
                    //    marked the row verified.
                    const latestOtp = await findLatestOtp(
                        normalizedPhone,
                        'registration',
                    );

                    const registrationMetadata =
                        (latestOtp?.metadata as Record<
                            string,
                            unknown
                        > | null) ?? {};

                    const fullName =
                        typeof registrationMetadata.fullName ===
                            'string'
                            ? (
                                registrationMetadata.fullName as string
                            ).trim()
                            : '';

                    const email =
                        typeof registrationMetadata.email ===
                            'string'
                            ? (
                                registrationMetadata.email as string
                            ).trim().toLowerCase()
                            : '';

                    // 3) Create the Firebase user (or reuse one already
                    //    tied to this phone number so we don't 500 on
                    //    client retries).
                    let firebaseUid: string;

                    try {
                        const firebaseUser =
                            await firebaseAuth.createUser({
                                phoneNumber:
                                    normalizedPhone,

                                displayName:
                                    fullName || undefined,

                                email:
                                    email || undefined,
                            });

                        firebaseUid = firebaseUser.uid;
                    } catch (createErr: unknown) {
                        const ce = createErr as {
                            code?: string;
                        };

                        if (
                            ce?.code ===
                            'auth/phone-number-already-exists' ||
                            ce?.code ===
                            'auth/email-already-exists'
                        ) {
                            // The auth user exists but is not yet in our
                            // drivers/passengers table. Reuse it and let
                            // the client persist the profile.
                            try {
                                const existingFb =
                                    await firebaseAuth.getUserByPhoneNumber(
                                        normalizedPhone,
                                    );

                                firebaseUid =
                                    existingFb.uid;
                            } catch {
                                return res.status(409).json({
                                    success: false,
                                    message:
                                        'This phone number is already registered. ' +
                                        'Please register with a different phone number.',
                                    code: 'PHONE_ALREADY_EXISTS',
                                });
                            }
                        } else {
                            throw createErr;
                        }
                    }

                    // 4) Return a custom token so Flutter can sign in
                    //    and persist the driver/passenger record via
                    //    its own DB service.
                    const customToken =
                        await firebaseAuth.createCustomToken(
                            firebaseUid,
                        );

                    return res.status(200).json({
                        success: true,
                        message:
                            'OTP verified successfully.',
                        purpose:
                            normalizedPurpose,
                        phone,
                        userType,
                        uid: firebaseUid,
                        customToken,
                    });
                }

                /* ========================================================
                 * NON-LOGIN / NON-REGISTRATION OTP
                 * (phone_change, password_reset, general)
                 * ======================================================== */

                return res.status(200).json({
                    success: true,
                    message: result.message,
                    purpose: normalizedPurpose,
                    phone,
                    userType,
                });
            } catch (error: unknown) {
                const e = error as {
                    message?: string;
                };

                console.error(
                    `❌ OTP verify error (${userType}):`,
                    error,
                );

                return res.status(500).json({
                    success: false,
                    message:
                        'Failed to verify OTP.',
                    code: 'OTP_VERIFY_FAILED',

                    ...(e.message
                        ? {
                            error: e.message,
                        }
                        : {}),
                });
            }
        },
    );

    return router;
};
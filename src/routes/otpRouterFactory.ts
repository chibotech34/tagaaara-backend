import { Router, Request, Response } from 'express';
import { sendOtp, verifyOtp, otpConfig } from '../services/otpService';
// ⬇️ Swapped from '../services/smsService' (Zavu) → Sailup
import { normalizeGhanaPhone } from '../services/sailup.service';
import { firebaseAuth } from '../config/firebase';
import pool from '../config/database';
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
     * Mounted as:
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
                            devCode:
                                result.code,
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
     * Mounted as:
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
                // and
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
                    normalizedPurpose ===
                    'login'
                ) {
                    const normalizedPhone =
                        normalizeGhanaPhone(
                            phone,
                        );

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
                 * NON-LOGIN OTP
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
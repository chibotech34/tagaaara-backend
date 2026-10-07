import { Router, Request, Response } from 'express';
import { sendOtp, verifyOtp, otpConfig } from '../services/otpService';
import { normalizeGhanaPhone } from '../services/smsService';
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
    return ALLOWED_PURPOSES.includes(v) ? v : 'registration';
};

/**
 * Look up an existing driver/passenger row by phone, tolerating the
 * different stored formats (`+233…` for drivers, `+233…` for passengers).
 * We compare the last 9 digits, which is stable across formats.
 */
const findExistingUser = async (
    userType: OtpUserType,
    normalizedPhone: string,
): Promise<{ uid: string } | null> => {
    const table = userType === 'driver' ? 'drivers' : 'passengers';
    const uidColumn = userType === 'driver' ? 'uid' : 'firebase_uid';
    const tail = normalizedPhone.slice(-9);

    const result = await pool.query(
        `
        SELECT ${uidColumn} AS uid
        FROM public.${table}
        WHERE RIGHT(REGEXP_REPLACE(phone, '\\D', '', 'g'), 9) = $1
        LIMIT 1
        `,
        [tail],
    );

    if (result.rows.length === 0) return null;
    const uid = String(result.rows[0].uid ?? '').trim();
    return uid ? { uid } : null;
};

export const createOtpRouter = (userType: OtpUserType): Router => {
    const router = Router();

    /* ---------------------------------------------------------------------
     * POST /otp/send
     * ------------------------------------------------------------------- */
    router.post('/send', async (req: Request, res: Response) => {
        try {
            const { phone, purpose, metadata } = req.body ?? {};

            if (!phone || typeof phone !== 'string') {
                return res.status(400).json({
                    success: false,
                    message: 'phone is required.',
                    code: 'MISSING_PHONE',
                });
            }

            const normalizedPurpose = normalisePurpose(purpose);
            const revealCode =
                process.env.NODE_ENV !== 'production' &&
                process.env.OTP_REVEAL_IN_RESPONSE === 'true';

            const result = await sendOtp({
                phone,
                purpose: normalizedPurpose,
                userType,
                metadata:
                    metadata && typeof metadata === 'object'
                        ? (metadata as Record<string, unknown>)
                        : undefined,
                revealCode,
            });

            if (!result.success) {
                const status =
                    result.errorCode === 'RESEND_COOLDOWN' ||
                        result.errorCode === 'RATE_LIMITED'
                        ? 429
                        : result.errorCode === 'INVALID_PHONE'
                            ? 400
                            : result.errorCode === 'SMS_SEND_FAILED'
                                ? 502
                                : 400;

                return res.status(status).json({
                    success: false,
                    message: result.message,
                    code: result.errorCode,
                    ...(result.cooldownSeconds !== undefined
                        ? { cooldownSeconds: result.cooldownSeconds }
                        : {}),
                });
            }

            return res.status(200).json({
                success: true,
                message: result.message,
                purpose: normalizedPurpose,
                expiresAt: result.expiresAt,
                ttlMinutes: otpConfig.ttlMinutes,
                ...(result.code ? { devCode: result.code } : {}),
            });
        } catch (error: unknown) {
            const e = error as { message?: string };
            console.error(`❌ OTP send error (${userType}):`, e);
            return res.status(500).json({
                success: false,
                message: 'Failed to send OTP.',
                code: 'OTP_SEND_FAILED',
                error: e.message,
            });
        }
    });

    /* ---------------------------------------------------------------------
     * POST /otp/verify
     * ------------------------------------------------------------------- */
    router.post('/verify', async (req: Request, res: Response) => {
        try {
            const { phone, otp, code, purpose } = req.body ?? {};

            if (!phone || typeof phone !== 'string') {
                return res.status(400).json({
                    success: false,
                    message: 'phone is required.',
                    code: 'MISSING_PHONE',
                });
            }

            const otpValue = otp ?? code;

            if (!otpValue) {
                return res.status(400).json({
                    success: false,
                    message: 'otp is required.',
                    code: 'MISSING_OTP',
                });
            }

            const normalizedPurpose = normalisePurpose(purpose);

            const result = await verifyOtp({
                phone,
                code: String(otpValue),
                purpose: normalizedPurpose,
            });

            if (!result.success) {
                const status = result.errorCode === 'OTP_NOT_FOUND' ? 404 : 400;
                return res.status(status).json({
                    success: false,
                    message: result.message,
                    code: result.errorCode,
                    ...(result.attemptsRemaining !== undefined
                        ? { attemptsRemaining: result.attemptsRemaining }
                        : {}),
                });
            }

            // -----------------------------------------------------------------
            // Login: try to mint a Firebase custom token for the matching user.
            // -----------------------------------------------------------------
            if (normalizedPurpose === 'login') {
                const normalizedPhone = normalizeGhanaPhone(phone);
                if (!normalizedPhone) {
                    return res.status(400).json({
                        success: false,
                        message: 'Invalid phone number.',
                        code: 'INVALID_PHONE',
                    });
                }

                const existing = await findExistingUser(userType, normalizedPhone);

                if (!existing) {
                    return res.status(200).json({
                        success: true,
                        message: 'OTP verified. No account found for this number.',
                        purpose: normalizedPurpose,
                        phone,
                        userType,
                        notRegistered: true,
                        customToken: null,
                    });
                }

                const customToken = await firebaseAuth.createCustomToken(existing.uid);

                return res.status(200).json({
                    success: true,
                    message: 'OTP verified successfully.',
                    purpose: normalizedPurpose,
                    phone,
                    userType,
                    notRegistered: false,
                    uid: existing.uid,
                    customToken,
                });
            }

            // Non-login purposes just return the verification result.
            return res.status(200).json({
                success: true,
                message: result.message,
                purpose: normalizedPurpose,
                phone,
                userType,
            });
        } catch (error: unknown) {
            const e = error as { message?: string };
            console.error(`❌ OTP verify error (${userType}):`, e);
            return res.status(500).json({
                success: false,
                message: 'Failed to verify OTP.',
                code: 'OTP_VERIFY_FAILED',
                error: e.message,
            });
        }
    });

    return router;
};
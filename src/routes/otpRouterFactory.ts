import { Router, Request, Response } from 'express';
import crypto from 'crypto';

import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';
import { sendZavuOtp } from '../services/zavuService';

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export type OtpPurpose =
    | 'registration'
    | 'login'
    | 'phone_change'
    | 'password_reset'
    | 'general';

export type OtpUserType = 'driver' | 'passenger';

const ALLOWED_PURPOSES: OtpPurpose[] = [
    'registration',
    'login',
    'phone_change',
    'password_reset',
    'general',
];

const OTP_TTL_MINUTES = 5;
const MAX_ATTEMPTS = 5;
const RESEND_COOLDOWN_SECONDS = 60;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

const normalisePurpose = (value: unknown): OtpPurpose => {
    const v = String(value ?? 'registration').trim() as OtpPurpose;
    return ALLOWED_PURPOSES.includes(v) ? v : 'registration';
};

/**
 * Normalize a Ghanaian phone number to E.164 (+233XXXXXXXXX).
 * `phone_otps.phone` stores numbers in this exact shape.
 */
export const normalizePhone = (phone: string): string => {
    let value = String(phone).trim().replace(/[^\d+]/g, '');
    if (value.startsWith('0')) {
        value = '+233' + value.substring(1);
    }
    if (!value.startsWith('+')) {
        value = '+' + value;
    }
    return value;
};

const generateOtp = (): string =>
    crypto.randomInt(100000, 1000000).toString();

const hashOtp = (otp: string): string =>
    crypto.createHash('sha256').update(otp).digest('hex');

/**
 * Look up a driver/passenger row by phone, comparing the last 9 digits
 * so the different stored formats (`+233…`, `0…`, etc.) all match.
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

/* ------------------------------------------------------------------ */
/*  Standalone verify helper (used by driver/passenger routers)        */
/* ------------------------------------------------------------------ */

export interface VerifyOtpInput {
    phone: string;
    code: string;
    purpose: OtpPurpose;
}

export interface VerifyOtpResult {
    success: boolean;
    message: string;
    errorCode?: string;
    attemptsRemaining?: number;
}

/**
 * Verify an OTP directly against public.phone_otps.
 * Matches the same semantics as the /otp/verify route so both share
 * one source of truth.
 */
export const verifyOtp = async (
    input: VerifyOtpInput,
): Promise<VerifyOtpResult> => {
    const normalizedPhone = normalizePhone(input.phone);

    const result = await pool.query(
        `
        SELECT id, otp_hash, expires_at, attempts, verified, consumed_at
        FROM public.phone_otps
        WHERE phone = $1 AND purpose = $2
        ORDER BY created_at DESC
        LIMIT 1
        `,
        [normalizedPhone, input.purpose],
    );

    if (result.rows.length === 0) {
        return {
            success: false,
            message: 'No OTP request found for this number.',
            errorCode: 'OTP_NOT_FOUND',
        };
    }

    const record = result.rows[0];

    if (record.verified || record.consumed_at) {
        return {
            success: false,
            message: 'This OTP has already been used.',
            errorCode: 'OTP_ALREADY_USED',
        };
    }

    if (new Date(record.expires_at).getTime() < Date.now()) {
        await pool.query(
            `UPDATE public.phone_otps
             SET consumed_at = NOW(), updated_at = NOW()
             WHERE id = $1`,
            [record.id],
        );
        return {
            success: false,
            message: 'OTP has expired. Please request a new one.',
            errorCode: 'OTP_EXPIRED',
        };
    }

    if (record.attempts >= MAX_ATTEMPTS) {
        return {
            success: false,
            message: 'Too many verification attempts. Please request a new OTP.',
            errorCode: 'OTP_TOO_MANY_ATTEMPTS',
        };
    }

    const providedHash = hashOtp(String(input.code));
    if (providedHash !== record.otp_hash) {
        const newAttempts = record.attempts + 1;
        await pool.query(
            `UPDATE public.phone_otps
             SET attempts = $1, updated_at = NOW()
             WHERE id = $2`,
            [newAttempts, record.id],
        );
        return {
            success: false,
            message: 'Invalid OTP.',
            errorCode: 'OTP_INVALID',
            attemptsRemaining: Math.max(0, MAX_ATTEMPTS - newAttempts),
        };
    }

    await pool.query(
        `UPDATE public.phone_otps
         SET verified = TRUE, consumed_at = NOW(), updated_at = NOW()
         WHERE id = $1`,
        [record.id],
    );

    return { success: true, message: 'OTP verified successfully.' };
};

/* ------------------------------------------------------------------ */
/*  Router factory                                                     */
/* ------------------------------------------------------------------ */

export const createOtpRouter = (userType: OtpUserType): Router => {
    const router = Router();

    /* -----------------------------------------------------------------
     * POST /otp/send
     * --------------------------------------------------------------- */
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
            const normalizedPhone = normalizePhone(phone);

            if (!/^\+233\d{9}$/.test(normalizedPhone)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid Ghanaian phone number.',
                    code: 'INVALID_PHONE',
                });
            }

            /* --- Resend cooldown ------------------------------------- */
            const recent = await pool.query(
                `SELECT last_sent_at
                 FROM public.phone_otps
                 WHERE phone = $1 AND purpose = $2
                 ORDER BY created_at DESC
                 LIMIT 1`,
                [normalizedPhone, normalizedPurpose],
            );

            if (recent.rows.length > 0) {
                const lastSent = new Date(
                    recent.rows[0].last_sent_at,
                ).getTime();
                const elapsed = (Date.now() - lastSent) / 1000;

                if (elapsed < RESEND_COOLDOWN_SECONDS) {
                    const remaining = Math.ceil(
                        RESEND_COOLDOWN_SECONDS - elapsed,
                    );
                    return res.status(429).json({
                        success: false,
                        message: `Please wait ${remaining}s before requesting a new OTP.`,
                        code: 'RESEND_COOLDOWN',
                        cooldownSeconds: remaining,
                    });
                }
            }

            /* --- Invalidate any previous unconsumed OTPs ------------- */
            await pool.query(
                `UPDATE public.phone_otps
                 SET verified = TRUE,
                     consumed_at = NOW(),
                     updated_at  = NOW()
                 WHERE phone   = $1
                   AND purpose = $2
                   AND verified = FALSE
                   AND consumed_at IS NULL`,
                [normalizedPhone, normalizedPurpose],
            );

            /* --- Generate + store fresh OTP -------------------------- */
            const otp = generateOtp();
            const otpHash = hashOtp(otp);
            const expiresAt = new Date(
                Date.now() + OTP_TTL_MINUTES * 60 * 1000,
            );

            await pool.query(
                `INSERT INTO public.phone_otps (
                    phone,
                    otp_hash,
                    expires_at,
                    attempts,
                    verified,
                    purpose,
                    user_type,
                    metadata,
                    created_at,
                    last_sent_at,
                    updated_at
                 )
                 VALUES (
                    $1,
                    $2,
                    $3,
                    0,
                    FALSE,
                    $4,
                    $5,
                    $6::jsonb,
                    NOW(),
                    NOW(),
                    NOW()
                 )`,
                [
                    normalizedPhone,
                    otpHash,
                    expiresAt,
                    normalizedPurpose,
                    userType,
                    metadata && typeof metadata === 'object'
                        ? JSON.stringify(metadata)
                        : null,
                ],
            );

            /* --- Send SMS -------------------------------------------- */
            await sendZavuOtp(normalizedPhone, otp);

            const revealCode =
                process.env.NODE_ENV !== 'production' &&
                process.env.OTP_REVEAL_IN_RESPONSE === 'true';

            return res.status(200).json({
                success: true,
                message: 'OTP sent successfully.',
                purpose: normalizedPurpose,
                expiresAt,
                ttlMinutes: OTP_TTL_MINUTES,
                ...(revealCode ? { devCode: otp } : {}),
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

    /* -----------------------------------------------------------------
     * POST /otp/verify
     * --------------------------------------------------------------- */
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
            const normalizedPhone = normalizePhone(phone);

            const check = await verifyOtp({
                phone: normalizedPhone,
                code: String(otpValue),
                purpose: normalizedPurpose,
            });

            if (!check.success) {
                const status =
                    check.errorCode === 'OTP_NOT_FOUND'
                        ? 404
                        : check.errorCode === 'OTP_TOO_MANY_ATTEMPTS'
                            ? 429
                            : 400;

                return res.status(status).json({
                    success: false,
                    message: check.message,
                    code: check.errorCode,
                    ...(check.attemptsRemaining !== undefined
                        ? { attemptsRemaining: check.attemptsRemaining }
                        : {}),
                });
            }

            /* --- Login: mint a Firebase custom token --------------- */
            if (normalizedPurpose === 'login') {
                const existing = await findExistingUser(
                    userType,
                    normalizedPhone,
                );

                if (!existing) {
                    return res.status(200).json({
                        success: true,
                        message:
                            'OTP verified. No account found for this number.',
                        purpose: normalizedPurpose,
                        phone: normalizedPhone,
                        userType,
                        notRegistered: true,
                        customToken: null,
                    });
                }

                const customToken = await firebaseAuth.createCustomToken(
                    existing.uid,
                );

                return res.status(200).json({
                    success: true,
                    message: 'OTP verified successfully.',
                    purpose: normalizedPurpose,
                    phone: normalizedPhone,
                    userType,
                    notRegistered: false,
                    uid: existing.uid,
                    customToken,
                });
            }

            return res.status(200).json({
                success: true,
                message: 'OTP verified successfully.',
                purpose: normalizedPurpose,
                phone: normalizedPhone,
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
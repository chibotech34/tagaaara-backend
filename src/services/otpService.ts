import crypto from 'crypto';

import {
    createOtp,
    findActiveOtp,
    findLatestOtp,
    incrementAttempts,
    markVerified,
    invalidateOtps,
    countOtpsSince,
    deleteExpiredOtps,
    type OtpPurpose,
    type OtpUserType,
} from '../models/otpModel';

import { sendOtpSms, normalizeGhanaPhone } from './smsService';

const OTP_LENGTH = Number(process.env.OTP_LENGTH ?? 6) || 6;
const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES ?? 5) || 5;
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS ?? 5) || 5;
const OTP_RESEND_COOLDOWN_SECONDS =
    Number(process.env.OTP_RESEND_COOLDOWN_SECONDS ?? 60) || 60;
const OTP_MAX_PER_HOUR = Number(process.env.OTP_MAX_PER_HOUR ?? 5) || 5;
const OTP_SECRET = process.env.OTP_SECRET ?? 'insecure-default-change-me';

export const otpConfig = {
    length: OTP_LENGTH,
    ttlMinutes: OTP_TTL_MINUTES,
    maxAttempts: OTP_MAX_ATTEMPTS,
    resendCooldownSeconds: OTP_RESEND_COOLDOWN_SECONDS,
    maxPerHour: OTP_MAX_PER_HOUR,
};

const generateCode = (): string => {
    const max = 10 ** OTP_LENGTH;
    const num = crypto.randomInt(0, max);
    return num.toString().padStart(OTP_LENGTH, '0');
};

const hashOtp = (phone: string, code: string, purpose: OtpPurpose): string =>
    crypto
        .createHmac('sha256', OTP_SECRET)
        .update(`${phone}:${purpose}:${code}`)
        .digest('hex');

const safeEqual = (a: string, b: string): boolean => {
    const bufA = Buffer.from(a, 'hex');
    const bufB = Buffer.from(b, 'hex');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
};

export interface SendOtpResult {
    success: boolean;
    message: string;
    code?: string;
    expiresAt?: Date;
    cooldownSeconds?: number;
    errorCode?: string;
}

export interface SendOtpOptions {
    phone: string;
    purpose: OtpPurpose;
    userType?: OtpUserType;
    userUid?: string;
    metadata?: Record<string, unknown>;
    revealCode?: boolean;
}

export const sendOtp = async (options: SendOtpOptions): Promise<SendOtpResult> => {
    const { phone, purpose, userType, userUid, metadata, revealCode = false } = options;

    const normalized = normalizeGhanaPhone(phone);

    if (!normalized) {
        return {
            success: false,
            message: 'Invalid phone number. Use a valid Ghana number.',
            errorCode: 'INVALID_PHONE',
        };
    }

    const latest = await findLatestOtp(normalized, purpose);

    if (latest) {
        const secondsSinceLastSend =
            (Date.now() - new Date(latest.last_sent_at).getTime()) / 1000;

        if (secondsSinceLastSend < OTP_RESEND_COOLDOWN_SECONDS) {
            const wait = Math.ceil(OTP_RESEND_COOLDOWN_SECONDS - secondsSinceLastSend);
            return {
                success: false,
                message: `Please wait ${wait} seconds before requesting a new code.`,
                cooldownSeconds: wait,
                errorCode: 'RESEND_COOLDOWN',
            };
        }
    }

    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const recent = await countOtpsSince(normalized, oneHourAgo);

    if (recent >= OTP_MAX_PER_HOUR) {
        return {
            success: false,
            message: 'Too many OTP requests for this number. Please try again later.',
            errorCode: 'RATE_LIMITED',
        };
    }

    await invalidateOtps(normalized, purpose);

    const code = generateCode();
    const otpHash = hashOtp(normalized, code, purpose);
    const expiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000);

    await createOtp({
        phone: normalized,
        otpHash,
        purpose,
        userType: userType ?? null,
        userUid: userUid ?? null,
        expiresAt,
        maxAttempts: OTP_MAX_ATTEMPTS,
        metadata: metadata ?? {},
    });

    const smsResult = await sendOtpSms(normalized, code, OTP_TTL_MINUTES);

    if (!smsResult.success) {
        return {
            success: false,
            message: smsResult.error ?? 'Failed to send OTP SMS. Please try again.',
            errorCode: 'SMS_SEND_FAILED',
        };
    }

    return {
        success: true,
        message: 'OTP sent successfully.',
        expiresAt,
        code: revealCode ? code : undefined,
    };
};

export interface VerifyOtpResult {
    success: boolean;
    message: string;
    errorCode?: string;
    attemptsRemaining?: number;
}

export const verifyOtp = async (params: {
    phone: string;
    code: string;
    purpose: OtpPurpose;
}): Promise<VerifyOtpResult> => {
    const { phone, code, purpose } = params;

    const normalized = normalizeGhanaPhone(phone);

    if (!normalized) {
        return { success: false, message: 'Invalid phone number.', errorCode: 'INVALID_PHONE' };
    }

    if (!code || !/^\d+$/.test(String(code))) {
        return { success: false, message: 'Invalid OTP format.', errorCode: 'INVALID_OTP_FORMAT' };
    }

    const record = await findActiveOtp(normalized, purpose);

    if (!record) {
        return {
            success: false,
            message: 'No active OTP found. Please request a new code.',
            errorCode: 'OTP_NOT_FOUND',
        };
    }

    if (record.attempts >= record.max_attempts) {
        return {
            success: false,
            message: 'Too many invalid attempts. Please request a new code.',
            errorCode: 'OTP_MAX_ATTEMPTS',
        };
    }

    const expected = hashOtp(normalized, String(code), purpose);
    const matches = safeEqual(expected, record.otp_hash);

    if (!matches) {
        const attempts = await incrementAttempts(record.id);
        const remaining = Math.max(record.max_attempts - attempts, 0);

        return {
            success: false,
            message: `Incorrect OTP. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`,
            errorCode: 'OTP_MISMATCH',
            attemptsRemaining: remaining,
        };
    }

    await markVerified(record.id);

    return { success: true, message: 'OTP verified successfully.' };
};

export const purgeExpiredOtps = async (): Promise<number> => deleteExpiredOtps();
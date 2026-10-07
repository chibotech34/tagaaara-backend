/*
|--------------------------------------------------------------------------
| OTP Model — backed by public.phone_otps (existing table, extended)
|--------------------------------------------------------------------------
*/

import pool from '../config/database';

export type OtpPurpose =
    | 'registration'
    | 'login'
    | 'phone_change'
    | 'password_reset'
    | 'general';

export type OtpUserType = 'driver' | 'passenger';

export interface OtpRow {
    id: number;
    phone: string;
    otp_hash: string;
    purpose: OtpPurpose;
    user_type: OtpUserType | null;
    user_uid: string | null;
    expires_at: Date;
    verified: boolean;
    attempts: number;
    max_attempts: number;
    last_sent_at: Date;
    metadata: Record<string, unknown>;
    created_at: Date;
    updated_at: Date;
}

export interface CreateOtpInput {
    phone: string;
    otpHash: string;
    purpose: OtpPurpose;
    userType?: OtpUserType | null;
    userUid?: string | null;
    expiresAt: Date;
    maxAttempts: number;
    metadata?: Record<string, unknown>;
}

export const createOtp = async (input: CreateOtpInput): Promise<OtpRow> => {
    const result = await pool.query<OtpRow>(
        `
        INSERT INTO public.phone_otps (
            phone, otp_hash, purpose, user_type, user_uid,
            expires_at, verified, attempts, max_attempts,
            last_sent_at, metadata, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5,
            $6, false, 0, $7,
            NOW(), $8::jsonb, NOW(), NOW()
        )
        RETURNING *
        `,
        [
            input.phone,
            input.otpHash,
            input.purpose,
            input.userType ?? null,
            input.userUid ?? null,
            input.expiresAt,
            input.maxAttempts,
            JSON.stringify(input.metadata ?? {}),
        ],
    );

    return result.rows[0];
};

export const findActiveOtp = async (
    phone: string,
    purpose: OtpPurpose,
): Promise<OtpRow | null> => {
    const result = await pool.query<OtpRow>(
        `
        SELECT *
        FROM public.phone_otps
        WHERE phone = $1
          AND purpose = $2
          AND verified = false
          AND expires_at > NOW()
        ORDER BY created_at DESC
        LIMIT 1
        `,
        [phone, purpose],
    );

    return result.rows[0] ?? null;
};

export const findLatestOtp = async (
    phone: string,
    purpose: OtpPurpose,
): Promise<OtpRow | null> => {
    const result = await pool.query<OtpRow>(
        `
        SELECT *
        FROM public.phone_otps
        WHERE phone = $1
          AND purpose = $2
        ORDER BY created_at DESC
        LIMIT 1
        `,
        [phone, purpose],
    );

    return result.rows[0] ?? null;
};

export const incrementAttempts = async (id: number): Promise<number> => {
    const result = await pool.query<{ attempts: number }>(
        `
        UPDATE public.phone_otps
        SET attempts = attempts + 1,
            updated_at = NOW()
        WHERE id = $1
        RETURNING attempts
        `,
        [id],
    );

    return result.rows[0]?.attempts ?? 0;
};

export const markVerified = async (id: number): Promise<void> => {
    await pool.query(
        `
        UPDATE public.phone_otps
        SET verified = true,
            updated_at = NOW()
        WHERE id = $1
        `,
        [id],
    );
};

export const invalidateOtps = async (
    phone: string,
    purpose: OtpPurpose,
): Promise<void> => {
    await pool.query(
        `
        UPDATE public.phone_otps
        SET verified = true,
            updated_at = NOW()
        WHERE phone = $1
          AND purpose = $2
          AND verified = false
        `,
        [phone, purpose],
    );
};

export const countOtpsSince = async (
    phone: string,
    since: Date,
): Promise<number> => {
    const result = await pool.query<{ count: string }>(
        `
        SELECT COUNT(*)::text AS count
        FROM public.phone_otps
        WHERE phone = $1
          AND created_at >= $2
        `,
        [phone, since],
    );

    return Number(result.rows[0]?.count ?? 0);
};

export const deleteExpiredOtps = async (): Promise<number> => {
    const result = await pool.query(
        `
        DELETE FROM public.phone_otps
        WHERE expires_at < NOW() - INTERVAL '1 day'
        RETURNING id
        `,
    );

    return result.rowCount ?? 0;
};
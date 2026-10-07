import pool from '../config/database';

export type OtpPurpose =
    | 'registration'
    | 'login'
    | 'phone_change'
    | 'password_reset'
    | 'general';

export type OtpUserType = 'driver' | 'passenger' | 'admin';

export interface PhoneOtpRow {
    id: number;
    phone: string;
    otp_hash: string;
    expires_at: Date;
    attempts: number;
    verified: boolean;
    created_at: Date;
    last_sent_at: Date;
    purpose: OtpPurpose;
    user_type: OtpUserType;
    user_uid: string | null;
    max_attempts: number;
    metadata: Record<string, unknown> | null;
    consumed_at: Date | null;
    updated_at: Date;
}

/* -------------------------------------------------------------------------- */
/* create                                                                     */
/* -------------------------------------------------------------------------- */

export const createOtp = async (params: {
    phone: string;
    otpHash: string;
    purpose: OtpPurpose;
    userType: OtpUserType | null;
    userUid: string | null;
    expiresAt: Date;
    maxAttempts: number;
    metadata: Record<string, unknown>;
}): Promise<PhoneOtpRow> => {
    const result = await pool.query<PhoneOtpRow>(
        `
        INSERT INTO public.phone_otps
            (phone, otp_hash, purpose, user_type, user_uid,
             expires_at, max_attempts, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        `,
        [
            params.phone,
            params.otpHash,
            params.purpose,
            params.userType ?? 'passenger',
            params.userUid,
            params.expiresAt,
            params.maxAttempts,
            params.metadata ?? {},
        ],
    );

    return result.rows[0];
};

/* -------------------------------------------------------------------------- */
/* read                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * The row a verify attempt should be checked against: not yet consumed, not
 * yet verified, and not yet expired.
 */
export const findActiveOtp = async (
    phone: string,
    purpose: OtpPurpose,
): Promise<PhoneOtpRow | null> => {
    const result = await pool.query<PhoneOtpRow>(
        `
        SELECT *
        FROM public.phone_otps
        WHERE phone = $1
          AND purpose = $2
          AND verified = false
          AND consumed_at IS NULL
          AND expires_at > now()
        ORDER BY created_at DESC
        LIMIT 1
        `,
        [phone, purpose],
    );

    return result.rows[0] ?? null;
};

/**
 * Most recent row regardless of liveness. Used for the resend-cooldown check,
 * which cares about `last_sent_at`, not about whether the code still works.
 */
export const findLatestOtp = async (
    phone: string,
    purpose: OtpPurpose,
): Promise<PhoneOtpRow | null> => {
    const result = await pool.query<PhoneOtpRow>(
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

/**
 * Hourly rate-limit counter. Counts *issuance* attempts, so it must filter on
 * created_at, not last_sent_at — otherwise a code that was never re-sent but
 * was retried within the cooldown window would not be counted here.
 */
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

/* -------------------------------------------------------------------------- */
/* write                                                                      */
/* -------------------------------------------------------------------------- */

export const incrementAttempts = async (id: number): Promise<number> => {
    const result = await pool.query<{ attempts: number }>(
        `
        UPDATE public.phone_otps
        SET attempts   = attempts + 1,
            updated_at = now()
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
        SET verified    = true,
            consumed_at = now(),
            updated_at  = now()
        WHERE id = $1
        `,
        [id],
    );
};

/**
 * Retire every still-live code for this phone/purpose. Used by sendOtp before
 * inserting a new one, and would be used by any "revoke" admin path.
 */
export const invalidateOtps = async (
    phone: string,
    purpose: OtpPurpose,
): Promise<void> => {
    await pool.query(
        `
        UPDATE public.phone_otps
        SET verified    = true,
            consumed_at = now(),
            updated_at  = now()
        WHERE phone = $1
          AND purpose = $2
          AND consumed_at IS NULL
        `,
        [phone, purpose],
    );
};

/* -------------------------------------------------------------------------- */
/* maintenance                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Delete rows well past their expiry. The 1-day grace keeps recently-expired
 * codes around for debugging / fraud review without letting the table grow
 * without bound.
 */
export const deleteExpiredOtps = async (): Promise<number> => {
    const result = await pool.query(
        `
        DELETE FROM public.phone_otps
        WHERE expires_at < now() - interval '1 day'
        `,
    );

    return result.rowCount ?? 0;
};
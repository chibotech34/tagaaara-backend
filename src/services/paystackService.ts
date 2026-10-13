// src/services/paystackService.ts
import axios, { AxiosError } from 'axios';
import crypto from 'crypto';

const PAYSTACK_BASE_URL = 'https://api.paystack.co';

function getSecretKey(): string {
    const key = process.env.PAYSTACK_SECRET_KEY;

    if (!key || !key.trim()) {
        throw new Error('PAYSTACK_SECRET_KEY is not configured.');
    }

    return key.trim();
}

/* ==========================================================================
 * TYPES
 * ========================================================================== */

export type PaystackProvider = 'mtn' | 'vod' | 'atl';

export interface PaystackChargeResult {
    reference: string;
    status: string;
    displayText: string;
    raw: Record<string, unknown>;
}

export interface PaystackVerifyResult {
    reference: string;
    status: string;
    amountPesewas: number;
    amountGHS: number;
    currency: string;
    channel: string;
    paidAt: string | null;
    raw: Record<string, unknown>;
}

/* ==========================================================================
 * HELPERS
 * ========================================================================== */

export function generateReference(
    purpose: 'topup' | 'ride',
    userId: string
): string {
    const suffix = crypto.randomBytes(6).toString('hex');
    const userPart = userId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 10);
    return `TEG-${purpose.toUpperCase()}-${userPart}-${Date.now()}-${suffix}`;
}

export function toPesewas(amountGHS: number): number {
    return Math.round(Number(amountGHS) * 100);
}

export function fromPesewas(pesewas: number): number {
    return Math.round(Number(pesewas)) / 100;
}

/* ==========================================================================
 * INITIATE MOBILE MONEY CHARGE
 * ========================================================================== */

export async function initializeMobileMoneyCharge(params: {
    email: string;
    amountGHS: number;
    phone: string;
    provider: PaystackProvider;
    reference: string;
    metadata?: Record<string, unknown>;
}): Promise<PaystackChargeResult> {
    const { email, amountGHS, phone, provider, reference, metadata } = params;

    if (!email || !email.trim()) {
        throw new Error('A valid email is required for Paystack charges.');
    }

    if (!Number.isFinite(amountGHS) || amountGHS <= 0) {
        throw new Error('Amount must be a positive number.');
    }

    if (!phone || phone.trim().length < 6) {
        throw new Error('A valid mobile money phone number is required.');
    }

    const body = {
        email: email.trim(),
        amount: toPesewas(amountGHS),
        currency: 'GHS',
        reference,
        channels: ['mobile_money'] as const,
        mobile_money: {
            phone: phone.trim(),
            provider,
        },
        metadata: metadata ?? {},
    };

    try {
        const response = await axios.post(
            `${PAYSTACK_BASE_URL}/charge`,
            body,
            {
                headers: {
                    Authorization: `Bearer ${getSecretKey()}`,
                    'Content-Type': 'application/json',
                },
                timeout: 20_000,
            }
        );

        const data = response.data?.data ?? {};

        return {
            reference: data.reference ?? reference,
            status: String(data.status ?? 'pending'),
            displayText: String(
                data.display_text ??
                'Please approve the payment prompt on your phone.'
            ),
            raw: response.data,
        };
    } catch (error) {
        const err = error as AxiosError<any>;
        const message =
            err.response?.data?.message ||
            err.message ||
            'Failed to initiate mobile money charge.';

        throw new Error(message);
    }
}

/* ==========================================================================
 * VERIFY TRANSACTION
 * ========================================================================== */

export async function verifyTransaction(
    reference: string
): Promise<PaystackVerifyResult> {
    if (!reference || !reference.trim()) {
        throw new Error('Reference is required.');
    }

    try {
        const response = await axios.get(
            `${PAYSTACK_BASE_URL}/transaction/verify/${encodeURIComponent(
                reference
            )}`,
            {
                headers: {
                    Authorization: `Bearer ${getSecretKey()}`,
                },
                timeout: 20_000,
            }
        );

        const data = response.data?.data ?? {};

        const amountPesewas = Number(data.amount) || 0;

        return {
            reference: data.reference ?? reference,
            status: String(data.status ?? 'pending'),
            amountPesewas,
            amountGHS: fromPesewas(amountPesewas),
            currency: String(data.currency ?? 'GHS'),
            channel: String(data.channel ?? ''),
            paidAt: data.paid_at ?? data.paidAt ?? null,
            raw: response.data,
        };
    } catch (error) {
        const err = error as AxiosError<any>;
        const message =
            err.response?.data?.message ||
            err.message ||
            'Failed to verify transaction.';

        throw new Error(message);
    }
}

/* ==========================================================================
 * WEBHOOK SIGNATURE VERIFICATION
 * ========================================================================== */

export function verifyWebhookSignature(
    rawBody: Buffer | string,
    signature: string | undefined
): boolean {
    if (!signature) return false;

    const hash = crypto
        .createHmac('sha512', getSecretKey())
        .update(rawBody)
        .digest('hex');

    const a = Buffer.from(hash, 'utf8');
    const b = Buffer.from(signature, 'utf8');

    if (a.length !== b.length) return false;

    return crypto.timingSafeEqual(a, b);
}

// src/routes/driverSubscriptionRoutes.ts

import { Router, Request, Response, NextFunction } from 'express';

import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';

// ── Paystack config ─────────────────────────────────────────────────

const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY || '';
const PAYSTACK_BASE = 'https://api.paystack.co';

const router = Router();

// ── Request types ────────────────────────────────────────────────────

interface AuthedRequest extends Request {
    driverId?: number;
    driverUid?: string;
}

// ── Authentication middleware ────────────────────────────────────────

const requireDriver = async (
    req: AuthedRequest,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    const header = req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
        res.status(401).json({
            success: false,
            message: 'Missing Authorization header.',
            code: 'AUTH_HEADER_MISSING',
        });
        return;
    }

    const token = header.substring('Bearer '.length).trim();

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

        const driver = await pool.query(
            `SELECT id
               FROM public.drivers
              WHERE uid = $1
              LIMIT 1`,
            [decoded.uid],
        );

        if (driver.rows.length === 0) {
            res.status(404).json({
                success: false,
                message: 'Driver not found.',
                code: 'DRIVER_NOT_FOUND',
            });
            return;
        }

        req.driverUid = decoded.uid;
        req.driverId = Number(driver.rows[0].id);

        next();
    } catch (err: any) {
        console.error(
            '❌ Firebase verify failed:',
            err?.message ?? err,
        );

        res.status(401).json({
            success: false,
            message: 'Firebase authentication failed.',
            code: 'AUTH_TOKEN_INVALID',
        });
    }
};

// ── General helpers ──────────────────────────────────────────────────

const firstParam = (
    value: string | string[] | undefined,
): string => {
    if (value === undefined) return '';
    return Array.isArray(value) ? (value[0] ?? '') : value;
};

function toPaystackProvider(
    code: string,
): 'mtn' | 'vod' | 'atl' | null {
    const lower = String(code || '').toLowerCase().trim();

    if (lower.includes('mtn')) return 'mtn';

    if (
        lower.includes('vod') ||
        lower.includes('telecel') ||
        lower.includes('vodafone')
    ) {
        return 'vod';
    }

    if (
        lower.includes('atl') ||
        lower.includes('airtel') ||
        lower.includes('tigo')
    ) {
        return 'atl';
    }

    return null;
}

// ── Paystack request helper ──────────────────────────────────────────

interface PaystackResult {
    ok: boolean;
    status: number;
    data: any;
}

async function paystackRequest(
    path: string,
    method: 'GET' | 'POST' = 'GET',
    body?: Record<string, unknown>,
): Promise<PaystackResult> {
    if (!PAYSTACK_SECRET) {
        throw new Error('PAYSTACK_SECRET_KEY is not configured.');
    }

    const response = await fetch(`${PAYSTACK_BASE}${path}`, {
        method,
        headers: {
            Authorization: `Bearer ${PAYSTACK_SECRET}`,
            'Content-Type': 'application/json',
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(20000),
    });

    let data: any = {};

    try {
        data = await response.json();
    } catch {
        data = {};
    }

    return {
        ok: response.ok,
        status: response.status,
        data,
    };
}

// ── Paystack error interpretation ───────────────────────────────────

interface PaystackFailure {
    code: string;
    message: string;
    insufficientFunds: boolean;
}

function resolvePaystackFailure(
    response: PaystackResult,
): PaystackFailure {
    const root = response?.data ?? {};
    const data = root?.data ?? {};

    const rawCode = String(
        data.code ??
        root.code ??
        '',
    );

    const rawMessage = String(
        data.display_text ??
        data.gateway_response ??
        data.message ??
        root.message ??
        '',
    );

    const combined = [
        rawCode,
        rawMessage,
        String(data.status ?? ''),
    ]
        .join(' ')
        .toUpperCase();

    const insufficientFunds =
        combined.includes(
            'LOW_BALANCE_OR_PAYEE_LIMIT_REACHED_OR_NOT_ALLOWED',
        ) ||
        combined.includes('INSUFFICIENT_FUNDS') ||
        combined.includes('INSUFFICIENT_BALANCE') ||
        combined.includes('LOW_BALANCE');

    if (insufficientFunds) {
        return {
            code: 'INSUFFICIENT_FUNDS',
            message:
                'Insufficient balance or Mobile Money transaction limit reached. Please check your wallet balance and transaction limits, then try again.',
            insufficientFunds: true,
        };
    }

    return {
        code:
            rawCode
                .trim()
                .toUpperCase()
                .replace(/[^A-Z0-9_]+/g, '_') ||
            'PAYMENT_FAILED',

        message:
            rawMessage ||
            'Your Mobile Money payment could not be completed.',

        insufficientFunds: false,
    };
}

// ── Payment database helpers ─────────────────────────────────────────

async function markDriverPaymentFailed(
    reference: string,
    driverId: number,
): Promise<void> {
    await pool.query(
        `UPDATE public.driver_subscription_payments
            SET status = 'failed',
                updated_at = NOW()
          WHERE reference = $1
            AND driver_id = $2
            AND status <> 'success'`,
        [reference, driverId],
    );
}

/** Load the latest driver subscription with plan and driver information. */
async function loadSubscription(
    driverId: number,
): Promise<any | null> {
    const result = await pool.query(
        `SELECT
            ds.id,
            ds.driver_id,
            ds.plan_id,
            ds.status,
            ds.starts_at,
            ds.expires_at,
            ds.created_at,
            ds.updated_at,
            sp.name AS plan_name,
            sp.type AS plan_type,
            sp.price AS plan_price,
            sp.currency AS plan_currency,
            sp.duration_days AS plan_duration_days,
            d.trial_used
         FROM public.driver_subscriptions ds
         JOIN public.subscription_plans sp
           ON sp.id = ds.plan_id
         JOIN public.drivers d
           ON d.id = ds.driver_id
         WHERE ds.driver_id = $1
         ORDER BY ds.created_at DESC
         LIMIT 1`,
        [driverId],
    );

    if (result.rows.length === 0) return null;

    const row = result.rows[0];

    // Automatically expire stale active subscriptions.
    if (
        row.status === 'active' &&
        row.expires_at &&
        new Date(row.expires_at).getTime() <= Date.now()
    ) {
        await pool.query(
            `UPDATE public.driver_subscriptions
                SET status = 'expired',
                    updated_at = NOW()
              WHERE id = $1`,
            [row.id],
        );

        row.status = 'expired';
    }

    return {
        ...row,
        type: row.plan_type,
        trial_used: !!row.trial_used,
    };
}

// ── GET /plans ───────────────────────────────────────────────────────

router.get('/plans', async (_req: Request, res: Response) => {
    try {
        const result = await pool.query(
            `SELECT
                id,
                name,
                type,
                price,
                currency,
                duration_days,
                is_active,
                sort_order
             FROM public.subscription_plans
             WHERE is_active = true
             ORDER BY sort_order NULLS LAST, id ASC`,
        );

        return res.status(200).json({
            success: true,
            plans: result.rows,
        });
    } catch (err: any) {
        console.error('❌ /plans:', err?.message ?? err);

        return res.status(500).json({
            success: false,
            message: 'Failed to fetch subscription plans.',
        });
    }
});

// ── GET /current ─────────────────────────────────────────────────────

router.get(
    '/current',
    requireDriver,
    async (req: AuthedRequest, res: Response) => {
        try {
            const subscription = await loadSubscription(
                req.driverId!,
            );

            return res.status(200).json({
                success: true,
                subscription,
            });
        } catch (err: any) {
            console.error('❌ /current:', err?.message ?? err);

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch current subscription.',
            });
        }
    },
);

// ── POST /trial ──────────────────────────────────────────────────────

router.post(
    '/trial',
    requireDriver,
    async (req: AuthedRequest, res: Response) => {
        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const driver = await client.query(
                `SELECT id, trial_used
                   FROM public.drivers
                  WHERE id = $1
                  FOR UPDATE`,
                [req.driverId!],
            );

            if (driver.rows.length === 0) {
                await client.query('ROLLBACK');

                return res.status(404).json({
                    success: false,
                    message: 'Driver not found.',
                });
            }

            if (driver.rows[0].trial_used === true) {
                await client.query('ROLLBACK');

                return res.status(409).json({
                    success: false,
                    message: 'The free trial has already been used.',
                    code: 'TRIAL_ALREADY_USED',
                });
            }

            const active = await client.query(
                `SELECT id
                   FROM public.driver_subscriptions
                  WHERE driver_id = $1
                    AND status = 'active'
                    AND (
                        expires_at IS NULL
                        OR expires_at > NOW()
                    )
                  LIMIT 1`,
                [req.driverId!],
            );

            if (active.rows.length > 0) {
                await client.query('ROLLBACK');

                return res.status(409).json({
                    success: false,
                    message: 'You already have an active subscription.',
                    code: 'SUBSCRIPTION_ALREADY_ACTIVE',
                });
            }

            const plan = await client.query(
                `SELECT id
                   FROM public.subscription_plans
                  WHERE type = 'trial'
                    AND is_active = true
                  ORDER BY sort_order NULLS LAST, id ASC
                  LIMIT 1`,
            );

            if (plan.rows.length === 0) {
                await client.query('ROLLBACK');

                return res.status(503).json({
                    success: false,
                    message: 'Trial plan is not configured.',
                    code: 'TRIAL_PLAN_MISSING',
                });
            }

            await client.query(
                `INSERT INTO public.driver_subscriptions
                    (driver_id, plan_id, status, starts_at, expires_at)
                 VALUES (
                    $1,
                    $2,
                    'active',
                    NOW(),
                    NOW() + INTERVAL '7 days'
                 )`,
                [req.driverId!, plan.rows[0].id],
            );

            await client.query(
                `UPDATE public.drivers
                    SET trial_used = true,
                        updated_at = NOW()
                  WHERE id = $1`,
                [req.driverId!],
            );

            await client.query('COMMIT');

            const subscription = await loadSubscription(
                req.driverId!,
            );

            return res.status(201).json({
                success: true,
                subscription,
            });
        } catch (err: any) {
            await client.query('ROLLBACK');

            console.error('❌ /trial:', err?.message ?? err);

            return res.status(500).json({
                success: false,
                message: 'Could not activate free trial.',
                code: 'TRIAL_ACTIVATION_FAILED',
            });
        } finally {
            client.release();
        }
    },
);

// ── POST /initialize ─────────────────────────────────────────────────

router.post(
    '/initialize',
    requireDriver,
    async (req: AuthedRequest, res: Response) => {
        try {
            const { plan_id, provider, phone } = req.body ?? {};

            if (!plan_id) {
                return res.status(400).json({
                    success: false,
                    message: 'plan_id is required.',
                    code: 'PLAN_ID_MISSING',
                });
            }

            const psProvider = toPaystackProvider(
                String(provider || ''),
            );

            if (!psProvider) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid Mobile Money provider.',
                    code: 'INVALID_PROVIDER',
                });
            }

            if (
                !phone ||
                String(phone).replace(/\D/g, '').length < 10
            ) {
                return res.status(400).json({
                    success: false,
                    message: 'A valid phone number is required.',
                    code: 'INVALID_PHONE',
                });
            }

            const plan = await pool.query(
                `SELECT id, price, currency
                   FROM public.subscription_plans
                  WHERE id = $1
                    AND is_active = true`,
                [plan_id],
            );

            if (plan.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Plan not found.',
                    code: 'PLAN_NOT_FOUND',
                });
            }

            const p = plan.rows[0];
            const amountPesewas = Math.round(
                Number(p.price) * 100,
            );

            if (!amountPesewas || amountPesewas < 100) {
                return res.status(400).json({
                    success: false,
                    message: 'Plan amount is invalid.',
                    code: 'INVALID_AMOUNT',
                });
            }

            const currency = String(p.currency || 'GHS').toUpperCase();

            if (currency !== 'GHS') {
                return res.status(400).json({
                    success: false,
                    message: 'Mobile Money subscriptions must be charged in GHS.',
                    code: 'INVALID_CURRENCY',
                });
            }

            const driver = await pool.query(
                `SELECT email
                   FROM public.drivers
                  WHERE id = $1`,
                [req.driverId!],
            );

            const email =
                driver.rows[0]?.email ||
                `driver-${req.driverId}@tegaara.app`;

            const charge = await paystackRequest(
                '/charge',
                'POST',
                {
                    email,
                    amount: amountPesewas,
                    currency,
                    mobile_money: {
                        phone: String(phone).replace(/\D/g, ''),
                        provider: psProvider,
                    },
                },
            );

            const data = charge.data?.data ?? {};
            const reference: string = data.reference || '';
            const status = String(data.status || '').toLowerCase();

            const failure = resolvePaystackFailure(charge);

            const isInsufficientFunds =
                failure.insufficientFunds;

            const isDefiniteFailure =
                isInsufficientFunds ||
                status === 'failed';

            // A provider-declined payment must not remain pending.
            if (isDefiniteFailure) {
                if (reference) {
                    await pool.query(
                        `INSERT INTO public.driver_subscription_payments
                            (
                                driver_id,
                                plan_id,
                                reference,
                                amount,
                                currency,
                                provider,
                                phone,
                                status,
                                created_at,
                                updated_at
                            )
                         VALUES (
                            $1, $2, $3, $4, $5, $6, $7,
                            'failed', NOW(), NOW()
                         )
                         ON CONFLICT (reference) DO UPDATE
                            SET status = 'failed',
                                updated_at = NOW()
                          WHERE public.driver_subscription_payments.status
                                <> 'success'`,
                        [
                            req.driverId!,
                            p.id,
                            reference,
                            Number(p.price),
                            currency,
                            psProvider,
                            String(phone),
                        ],
                    );
                }

                return res.status(
                    isInsufficientFunds ? 402 : 400,
                ).json({
                    success: false,
                    status: 'failed',
                    code: failure.code,
                    reference: reference || null,
                    message: isInsufficientFunds
                        ? failure.message
                        : (
                            data.display_text ||
                            charge.data?.message ||
                            'Your payment could not be completed.'
                        ),
                });
            }

            if (!charge.ok && !reference) {
                return res.status(502).json({
                    success: false,
                    status: 'failed',
                    code: failure.code,
                    message:
                        charge.data?.message ||
                        'Could not start the payment. Please try again.',
                });
            }

            if (!reference) {
                return res.status(502).json({
                    success: false,
                    status: 'failed',
                    code: 'PAYSTACK_REFERENCE_MISSING',
                    message:
                        charge.data?.message ||
                        'Payment provider did not return a reference.',
                });
            }

            // Save the pending payment attempt.
            await pool.query(
                `INSERT INTO public.driver_subscription_payments
                    (
                        driver_id,
                        plan_id,
                        reference,
                        amount,
                        currency,
                        provider,
                        phone,
                        status,
                        created_at
                    )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW())
                 ON CONFLICT (reference) DO NOTHING`,
                [
                    req.driverId!,
                    p.id,
                    reference,
                    Number(p.price),
                    currency,
                    psProvider,
                    String(phone),
                ],
            );

            const needsOtp =
                status === 'send_otp' ||
                status === 'send-otp' ||
                status === 'otp';

            return res.status(200).json({
                success: true,
                reference,
                status: status || 'pending',
                needs_otp: needsOtp,
                message:
                    data.display_text ||
                    charge.data?.message ||
                    '',
                displayText:
                    data.display_text ||
                    charge.data?.message ||
                    '',
            });
        } catch (err: any) {
            console.error(
                '❌ /initialize:',
                err?.message ?? err,
            );

            return res.status(500).json({
                success: false,
                status: 'failed',
                code: 'PAYMENT_INITIALIZATION_FAILED',
                message: 'Could not start the payment.',
            });
        }
    },
);

// ── POST /submit-otp ─────────────────────────────────────────────────

router.post(
    '/submit-otp',
    requireDriver,
    async (req: AuthedRequest, res: Response) => {
        try {
            const { reference, otp } = req.body ?? {};

            if (!reference || !otp) {
                return res.status(400).json({
                    success: false,
                    status: 'send_otp',
                    code: 'OTP_SUBMISSION_FAILED',
                    message: 'reference and otp are required.',
                });
            }

            // Make sure the payment belongs to this driver.
            const payment = await pool.query(
                `SELECT id, status
                   FROM public.driver_subscription_payments
                  WHERE reference = $1
                    AND driver_id = $2
                  LIMIT 1`,
                [reference, req.driverId!],
            );

            if (payment.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    status: 'failed',
                    code: 'PAYMENT_NOT_FOUND',
                    message: 'Payment reference not found.',
                });
            }

            if (payment.rows[0].status === 'success') {
                const subscription = await loadSubscription(
                    req.driverId!,
                );

                return res.status(200).json({
                    success: true,
                    status: 'success',
                    alreadyApplied: true,
                    subscription,
                });
            }

            const otpRes = await paystackRequest(
                '/charge/submit_otp',
                'POST',
                {
                    reference,
                    otp,
                },
            );

            const data = otpRes.data?.data ?? {};
            const status = String(data.status || '').toLowerCase();

            const failure = resolvePaystackFailure(otpRes);

            // Insufficient balance or provider transaction limit.
            if (failure.insufficientFunds) {
                await markDriverPaymentFailed(
                    reference,
                    req.driverId!,
                );

                return res.status(402).json({
                    success: false,
                    status: 'failed',
                    code: 'INSUFFICIENT_FUNDS',
                    reference,
                    message: failure.message,
                });
            }

            // Incorrect OTP or another OTP retry response.
            // Do not permanently fail the payment here.
            if (
                status === 'send_otp' ||
                status === 'send-otp' ||
                (!otpRes.ok && otpRes.status === 400)
            ) {
                return res.status(400).json({
                    success: false,
                    status: 'send_otp',
                    code: 'OTP_SUBMISSION_FAILED',
                    reference,
                    message:
                        otpRes.data?.message ||
                        'Incorrect OTP. Please try again.',
                });
            }

            // Only a provider-reported failed charge is final.
            if (status === 'failed' || status === 'reversed') {
                await markDriverPaymentFailed(
                    reference,
                    req.driverId!,
                );

                return res.status(400).json({
                    success: false,
                    status: 'failed',
                    code: failure.code,
                    reference,
                    message:
                        data.display_text ||
                        otpRes.data?.message ||
                        'Your payment could not be completed.',
                });
            }

            if (
                status === 'success' ||
                status === 'successful' ||
                status === 'completed'
            ) {
                return await finalizeSuccessfulCharge(
                    reference,
                    req.driverId!,
                    res,
                );
            }

            return res.status(200).json({
                success: false,
                status: status || 'pending',
                needs_otp: false,
                reference,
                message:
                    otpRes.data?.message ||
                    'Payment is being processed.',
            });
        } catch (err: any) {
            console.error(
                '❌ /submit-otp:',
                err?.message ?? err,
            );

            return res.status(500).json({
                success: false,
                status: 'pending',
                code: 'OTP_SUBMISSION_ERROR',
                message: 'Could not submit verification code.',
            });
        }
    },
);

// ── GET /verify/:reference ───────────────────────────────────────────

router.get(
    '/verify/:reference',
    requireDriver,
    async (req: AuthedRequest, res: Response) => {
        try {
            const reference = firstParam(
                req.params.reference,
            );

            if (!reference) {
                return res.status(400).json({
                    success: false,
                    status: 'failed',
                    message: 'Missing payment reference.',
                });
            }

            // Find the payment and confirm ownership.
            const payment = await pool.query(
                `SELECT status, plan_id
                   FROM public.driver_subscription_payments
                  WHERE reference = $1
                    AND driver_id = $2
                  LIMIT 1`,
                [reference, req.driverId!],
            );

            if (payment.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    status: 'failed',
                    message: 'Payment reference not found.',
                });
            }

            if (payment.rows[0].status === 'success') {
                const subscription = await loadSubscription(
                    req.driverId!,
                );

                return res.status(200).json({
                    success: true,
                    status: 'success',
                    alreadyApplied: true,
                    subscription,
                });
            }

            if (payment.rows[0].status === 'failed') {
                return res.status(200).json({
                    success: false,
                    status: 'failed',
                    code: 'PAYMENT_FAILED',
                    reference,
                    message:
                        'This payment attempt failed. Please start a new payment.',
                });
            }

            // Ask Paystack for the current charge status.
            const check = await paystackRequest(
                `/charge/${encodeURIComponent(reference)}`,
                'GET',
            );

            const data = check.data?.data ?? {};
            const status = String(data.status || '').toLowerCase();

            const failure = resolvePaystackFailure(check);

            // Provider has explicitly rejected the payment.
            if (failure.insufficientFunds) {
                await markDriverPaymentFailed(
                    reference,
                    req.driverId!,
                );

                return res.status(402).json({
                    success: false,
                    status: 'failed',
                    code: 'INSUFFICIENT_FUNDS',
                    reference,
                    message: failure.message,
                });
            }

            // Do not mark a payment failed just because the Paystack
            // verification API itself returned an error.
            if (!check.ok) {
                return res.status(200).json({
                    success: false,
                    status: 'pending',
                    code: 'PAYMENT_VERIFICATION_PENDING',
                    reference,
                    message:
                        check.data?.message ||
                        'Could not confirm the payment yet. Please try again.',
                });
            }

            if (
                status === 'success' ||
                status === 'successful' ||
                status === 'completed'
            ) {
                return await finalizeSuccessfulCharge(
                    reference,
                    req.driverId!,
                    res,
                    payment.rows[0].plan_id,
                );
            }

            if (
                status === 'send_otp' ||
                status === 'send-otp'
            ) {
                return res.status(200).json({
                    success: false,
                    status: 'send_otp',
                    needs_otp: true,
                    reference,
                    message: data.display_text || '',
                });
            }

            if (status === 'failed' || status === 'reversed') {
                await markDriverPaymentFailed(
                    reference,
                    req.driverId!,
                );

                return res.status(200).json({
                    success: false,
                    status: 'failed',
                    code: failure.code,
                    reference,
                    message:
                        data.display_text ||
                        check.data?.message ||
                        'Payment failed.',
                });
            }

            return res.status(200).json({
                success: false,
                status: status || 'pending',
                reference,
                message:
                    check.data?.message ||
                    'Payment is pending. Please wait.',
            });
        } catch (err: any) {
            console.error(
                '❌ /verify:',
                err?.message ?? err,
            );

            return res.status(500).json({
                success: false,
                status: 'pending',
                code: 'PAYMENT_VERIFICATION_ERROR',
                message: 'Could not verify payment.',
            });
        }
    },
);

// ── Finalize successful payment ──────────────────────────────────────

async function finalizeSuccessfulCharge(
    reference: string,
    driverId: number,
    res: Response,
    knownPlanId?: number,
): Promise<Response> {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const pay = await client.query(
            `SELECT id, plan_id, status
               FROM public.driver_subscription_payments
              WHERE reference = $1
                AND driver_id = $2
              FOR UPDATE`,
            [reference, driverId],
        );

        if (pay.rows.length === 0) {
            await client.query('ROLLBACK');

            return res.status(404).json({
                success: false,
                status: 'failed',
                message: 'Payment record not found.',
            });
        }

        const row = pay.rows[0];

        if (row.status === 'success') {
            await client.query('COMMIT');

            const subscription = await loadSubscription(
                driverId,
            );

            return res.status(200).json({
                success: true,
                status: 'success',
                alreadyApplied: true,
                subscription,
            });
        }

        const planId = knownPlanId ?? row.plan_id;

        const plan = await client.query(
            `SELECT duration_days
               FROM public.subscription_plans
              WHERE id = $1`,
            [planId],
        );

        if (plan.rows.length === 0) {
            await client.query('ROLLBACK');

            return res.status(404).json({
                success: false,
                status: 'pending',
                code: 'SUBSCRIPTION_PLAN_NOT_FOUND',
                message: 'The subscription plan could not be found.',
            });
        }

        const days = Math.max(
            1,
            Number(plan.rows[0].duration_days) || 30,
        );

        // Extend from the current active expiry if one exists.
        // Otherwise start the new subscription immediately.
        await client.query(
            `INSERT INTO public.driver_subscriptions
                (
                    driver_id,
                    plan_id,
                    status,
                    starts_at,
                    expires_at
                )
             VALUES (
                $1,
                $2,
                'active',
                NOW(),
                NOW() + make_interval(days => $3)
             )`,
            [driverId, planId, days],
        );

        await client.query(
            `UPDATE public.driver_subscription_payments
                SET status = 'success',
                    paid_at = NOW(),
                    updated_at = NOW()
              WHERE id = $1`,
            [row.id],
        );

        await client.query('COMMIT');

        const subscription = await loadSubscription(
            driverId,
        );

        return res.status(200).json({
            success: true,
            status: 'success',
            alreadyApplied: false,
            subscription,
        });
    } catch (err: any) {
        await client.query('ROLLBACK');

        console.error(
            '❌ finalizeSuccessfulCharge:',
            err?.message ?? err,
        );

        return res.status(503).json({
            success: false,
            status: 'pending',
            code: 'PAYMENT_CREDIT_PENDING',
            message:
                'Payment confirmed. Activating subscription. Please check again shortly.',
        });
    } finally {
        client.release();
    }
}

// ── GET /payments ────────────────────────────────────────────────────

router.get(
    '/payments',
    requireDriver,
    async (req: AuthedRequest, res: Response) => {
        try {
            const limit = Math.min(
                Math.max(Number(req.query.limit) || 50, 1),
                200,
            );

            const result = await pool.query(
                `SELECT
                    dsp.id,
                    dsp.reference,
                    dsp.amount,
                    dsp.currency,
                    dsp.provider,
                    dsp.status,
                    dsp.paid_at,
                    dsp.created_at,
                    sp.name AS plan_name
                 FROM public.driver_subscription_payments dsp
                 LEFT JOIN public.subscription_plans sp
                   ON sp.id = dsp.plan_id
                 WHERE dsp.driver_id = $1
                 ORDER BY dsp.created_at DESC
                 LIMIT $2`,
                [req.driverId!, limit],
            );

            return res.status(200).json({
                success: true,
                payments: result.rows,
            });
        } catch (err: any) {
            console.error(
                '❌ /payments:',
                err?.message ?? err,
            );

            return res.status(500).json({
                success: false,
                message: 'Failed to fetch payment history.',
            });
        }
    },
);

export default router;

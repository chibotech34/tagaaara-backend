// src/routes/driverSubscriptionRoutes.ts
import { Router, Request, Response, NextFunction } from 'express';

import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';

// ── Paystack config ─────────────────────────────────────────────────
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY || '';
const PAYSTACK_BASE = 'https://api.paystack.co';

// ── Router ──────────────────────────────────────────────────────────
const router = Router();

/* ===================================================================
 * Auth middleware
 * ================================================================ */

interface AuthedRequest extends Request {
    driverId?: number;
    driverUid?: string;
}

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
            `SELECT id FROM public.drivers WHERE uid = $1 LIMIT 1`,
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
        req.driverId = driver.rows[0].id;
        next();
    } catch (err: any) {
        console.error('❌ Firebase verify failed:', err?.message ?? err);
        res.status(401).json({
            success: false,
            message: 'Firebase authentication failed.',
            code: 'AUTH_TOKEN_INVALID',
        });
    }
};

/* ===================================================================
 * Helpers
 * ================================================================ */

/**
 * Express types `req.params.x` as `string | string[]` (repeatable params).
 * Everything we pass to Postgres / Paystack / fetch must be a single
 * string, so collapse the array case here once instead of at every
 * call site.
 */
const firstParam = (v: string | string[] | undefined): string => {
    if (v === undefined) return '';
    return Array.isArray(v) ? (v[0] ?? '') : v;
};

function toPaystackProvider(code: string): 'mtn' | 'vod' | 'atl' | null {
    const lower = String(code || '').toLowerCase();
    if (lower.includes('mtn')) return 'mtn';
    if (lower.includes('vod') || lower.includes('telecel')) return 'vod';
    if (
        lower.includes('atl') ||
        lower.includes('airtel') ||
        lower.includes('tigo')
    ) {
        return 'atl';
    }
    return null;
}

async function paystackRequest(
    path: string,
    method: 'GET' | 'POST' = 'GET',
    body?: Record<string, unknown>,
): Promise<{ ok: boolean; status: number; data: any }> {
    const res = await fetch(`${PAYSTACK_BASE}${path}`, {
        method,
        headers: {
            Authorization: `Bearer ${PAYSTACK_SECRET}`,
            'Content-Type': 'application/json',
        },
        body: body ? JSON.stringify(body) : undefined,
    });

    let data: any = {};
    try {
        data = await res.json();
    } catch {
        /* ignore */
    }
    return { ok: res.ok, status: res.status, data };
}

/** Load a driver subscription with its plan & driver info joined in. */
async function loadSubscription(driverId: number): Promise<any | null> {
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
        sp.name          AS plan_name,
        sp.type          AS plan_type,
        sp.price         AS plan_price,
        sp.currency      AS plan_currency,
        sp.duration_days AS plan_duration_days,
        d.trial_used
     FROM public.driver_subscriptions ds
     JOIN public.subscription_plans sp ON sp.id = ds.plan_id
     JOIN public.drivers d             ON d.id  = ds.driver_id
     WHERE ds.driver_id = $1
     ORDER BY ds.created_at DESC
     LIMIT 1`,
        [driverId],
    );

    if (result.rows.length === 0) return null;

    const row = result.rows[0];

    // Auto-expire stale active subscriptions so the client sees the truth.
    if (
        row.status === 'active' &&
        row.expires_at &&
        new Date(row.expires_at).getTime() <= Date.now()
    ) {
        await pool.query(
            `UPDATE public.driver_subscriptions
          SET status = 'expired', updated_at = NOW()
        WHERE id = $1`,
            [row.id],
        );
        row.status = 'expired';
    }

    // Normalise the shape Flutter expects.
    return {
        ...row,
        type: row.plan_type,        // DriverSubscription reads `type`
        trial_used: !!row.trial_used,
    };
}

/* ===================================================================
 * GET /api/drivers/subscription/plans
 * ================================================================ */

router.get('/plans', async (_req: Request, res: Response) => {
    try {
        const result = await pool.query(
            `SELECT id, name, type, price, currency, duration_days,
              is_active, sort_order
         FROM public.subscription_plans
        WHERE is_active = true
        ORDER BY sort_order NULLS LAST, id ASC`,
        );

        return res.status(200).json({ success: true, plans: result.rows });
    } catch (err: any) {
        console.error('❌ /plans:', err?.message ?? err);
        return res.status(500).json({
            success: false,
            message: 'Failed to fetch subscription plans.',
        });
    }
});

/* ===================================================================
 * GET /api/drivers/subscription/current
 * ================================================================ */

router.get(
    '/current',
    requireDriver,
    async (req: AuthedRequest, res: Response) => {
        try {
            const subscription = await loadSubscription(req.driverId!);
            return res.status(200).json({ success: true, subscription });
        } catch (err: any) {
            console.error('❌ /current:', err?.message ?? err);
            return res.status(500).json({
                success: false,
                message: 'Failed to fetch current subscription.',
            });
        }
    },
);

/* ===================================================================
 * POST /api/drivers/subscription/trial     ← THE MISSING ROUTE
 * ================================================================ */

router.post(
    '/trial',
    requireDriver,
    async (req: AuthedRequest, res: Response) => {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const driver = await client.query(
                `SELECT id, trial_used FROM public.drivers WHERE id = $1 FOR UPDATE`,
                [req.driverId!],
            );

            if (driver.rows.length === 0) {
                await client.query('ROLLBACK');
                return res
                    .status(404)
                    .json({ success: false, message: 'Driver not found.' });
            }

            if (driver.rows[0].trial_used === true) {
                await client.query('ROLLBACK');
                return res.status(409).json({
                    success: false,
                    message: 'The free trial has already been used.',
                    code: 'TRIAL_ALREADY_USED',
                });
            }

            // Block re-activation if any active subscription already exists.
            const active = await client.query(
                `SELECT id FROM public.driver_subscriptions
          WHERE driver_id = $1
            AND status = 'active'
            AND (expires_at IS NULL OR expires_at > NOW())
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
                `SELECT id FROM public.subscription_plans
          WHERE type = 'trial' AND is_active = true
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
         VALUES ($1, $2, 'active', NOW(), NOW() + INTERVAL '7 days')`,
                [req.driverId!, plan.rows[0].id],
            );

            await client.query(
                `UPDATE public.drivers
            SET trial_used = true, updated_at = NOW()
          WHERE id = $1`,
                [req.driverId!],
            );

            await client.query('COMMIT');

            const subscription = await loadSubscription(req.driverId!);
            return res.status(201).json({ success: true, subscription });
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

/* ===================================================================
 * POST /api/drivers/subscription/initialize
 * ================================================================ */

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

            const psProvider = toPaystackProvider(String(provider || ''));
            if (!psProvider) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid Mobile Money provider.',
                    code: 'INVALID_PROVIDER',
                });
            }

            if (!phone || String(phone).replace(/\D/g, '').length < 10) {
                return res.status(400).json({
                    success: false,
                    message: 'A valid phone number is required.',
                    code: 'INVALID_PHONE',
                });
            }

            const plan = await pool.query(
                `SELECT id, price, currency FROM public.subscription_plans
          WHERE id = $1 AND is_active = true`,
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
            const amountPesewas = Math.round(Number(p.price) * 100);
            if (!amountPesewas || amountPesewas < 100) {
                return res.status(400).json({
                    success: false,
                    message: 'Plan amount is invalid.',
                    code: 'INVALID_AMOUNT',
                });
            }

            // Email is required by Paystack.
            const driver = await pool.query(
                `SELECT email FROM public.drivers WHERE id = $1`,
                [req.driverId!],
            );
            const email =
                driver.rows[0]?.email || `driver-${req.driverId}@tegaara.app`;

            const charge = await paystackRequest('/charge', 'POST', {
                email,
                amount: amountPesewas,
                currency: p.currency || 'GHS',
                mobile_money: {
                    phone: String(phone).replace(/\D/g, ''),
                    provider: psProvider,
                },
            });

            const data = charge.data?.data ?? {};
            const reference: string = data.reference || '';
            const status: string = (data.status || '').toLowerCase();

            if (!charge.ok && !reference) {
                return res.status(502).json({
                    success: false,
                    status: 'failed',
                    message:
                        charge.data?.message ||
                        'Could not start the payment. Please try again.',
                });
            }

            if (!reference) {
                return res.status(502).json({
                    success: false,
                    status: 'failed',
                    message: 'Payment provider did not return a reference.',
                });
            }

            // Persist a pending payment record so verify/webhook can reconcile.
            await pool.query(
                `INSERT INTO public.driver_subscription_payments
            (driver_id, plan_id, reference, amount, currency, provider, phone,
             status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW())
         ON CONFLICT (reference) DO NOTHING`,
                [
                    req.driverId!,
                    p.id,
                    reference,
                    Number(p.price),
                    p.currency || 'GHS',
                    psProvider,
                    String(phone),
                ],
            );

            const needsOtp =
                status === 'send_otp' || status === 'send-otp' || status === 'otp';

            return res.status(200).json({
                success: true,
                reference,
                status: status || 'pending',
                needs_otp: needsOtp,
                message: data.display_text || charge.data?.message || '',
                displayText: data.display_text || charge.data?.message || '',
            });
        } catch (err: any) {
            console.error('❌ /initialize:', err?.message ?? err);
            return res.status(500).json({
                success: false,
                status: 'failed',
                message: 'Could not start the payment.',
            });
        }
    },
);

/* ===================================================================
 * POST /api/drivers/subscription/submit-otp
 * ================================================================ */

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

            const otpRes = await paystackRequest('/charge/submit_otp', 'POST', {
                reference,
                otp,
            });

            const data = otpRes.data?.data ?? {};
            const status: string = (data.status || '').toLowerCase();

            // Wrong OTP → still needs a fresh code
            if (!otpRes.ok && (status === 'send_otp' || otpRes.status === 400)) {
                return res.status(400).json({
                    success: false,
                    status: 'send_otp',
                    code: 'OTP_SUBMISSION_FAILED',
                    message: otpRes.data?.message || 'Incorrect OTP. Try again.',
                });
            }

            if (
                status === 'success' ||
                status === 'successful' ||
                status === 'completed'
            ) {
                return await finalizeSuccessfulCharge(reference, req.driverId!, res);
            }

            return res.status(200).json({
                success: false,
                status: status || 'pending',
                needs_otp: false,
                message: otpRes.data?.message || '',
            });
        } catch (err: any) {
            console.error('❌ /submit-otp:', err?.message ?? err);
            return res.status(500).json({
                success: false,
                status: 'pending',
                message: 'Could not submit verification code.',
            });
        }
    },
);

/* ===================================================================
 * GET /api/drivers/subscription/verify/:reference
 * ================================================================ */

router.get(
    '/verify/:reference',
    requireDriver,
    async (req: AuthedRequest, res: Response) => {
        try {
            // ⭐ req.params.reference is `string | string[]` — collapse it here.
            const reference = firstParam(req.params.reference);

            if (!reference) {
                return res.status(400).json({
                    success: false,
                    status: 'failed',
                    message: 'Missing payment reference.',
                });
            }

            // 1) Already applied?
            const payment = await pool.query(
                `SELECT status, plan_id FROM public.driver_subscription_payments
          WHERE reference = $1 AND driver_id = $2
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
                const subscription = await loadSubscription(req.driverId!);
                return res.status(200).json({
                    success: true,
                    status: 'success',
                    alreadyApplied: true,
                    subscription,
                });
            }

            // 2) Ask Paystack
            const check = await paystackRequest(
                `/charge/${encodeURIComponent(reference)}`,
                'GET',
            );
            const data = check.data?.data ?? {};
            const status: string = (data.status || '').toLowerCase();

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

            if (status === 'send_otp' || status === 'send-otp') {
                return res.status(200).json({
                    success: false,
                    status: 'send_otp',
                    needs_otp: true,
                    message: data.display_text || '',
                });
            }

            if (status === 'failed' || status === 'reversed') {
                await pool.query(
                    `UPDATE public.driver_subscription_payments
              SET status = $2, updated_at = NOW()
            WHERE reference = $1`,
                    [reference, status],
                );
                return res.status(200).json({
                    success: false,
                    status,
                    message: check.data?.message || 'Payment failed.',
                });
            }

            return res.status(200).json({
                success: false,
                status: status || 'pending',
                message: check.data?.message || 'Payment pending.',
            });
        } catch (err: any) {
            console.error('❌ /verify:', err?.message ?? err);
            return res.status(500).json({
                success: false,
                status: 'pending',
                message: 'Could not verify payment.',
            });
        }
    },
);

/** Shared "charge is paid → activate subscription" tail. */
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
            `SELECT id, plan_id, status FROM public.driver_subscription_payments
        WHERE reference = $1 AND driver_id = $2
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
            const subscription = await loadSubscription(driverId);
            return res.status(200).json({
                success: true,
                status: 'success',
                alreadyApplied: true,
                subscription,
            });
        }

        const planId = knownPlanId ?? row.plan_id;
        const plan = await client.query(
            `SELECT duration_days FROM public.subscription_plans WHERE id = $1`,
            [planId],
        );
        const days = Number(plan.rows[0]?.duration_days) || 30;

        await client.query(
            `INSERT INTO public.driver_subscriptions
          (driver_id, plan_id, status, starts_at, expires_at)
       VALUES ($1, $2, 'active', NOW(), NOW() + ($3 || ' days')::interval)`,
            [driverId, planId, String(days)],
        );

        await client.query(
            `UPDATE public.driver_subscription_payments
          SET status = 'success', paid_at = NOW(), updated_at = NOW()
        WHERE id = $1`,
            [row.id],
        );

        await client.query('COMMIT');

        const subscription = await loadSubscription(driverId);
        return res.status(200).json({
            success: true,
            status: 'success',
            alreadyApplied: false,
            subscription,
        });
    } catch (err: any) {
        await client.query('ROLLBACK');
        console.error('❌ finalizeSuccessfulCharge:', err?.message ?? err);
        return res.status(503).json({
            success: false,
            status: 'pending',
            code: 'PAYMENT_CREDIT_PENDING',
            message: 'Payment confirmed. Activating subscription…',
        });
    } finally {
        client.release();
    }
}

/* ===================================================================
 * GET /api/drivers/subscription/payments
 * ================================================================ */

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
         LEFT JOIN public.subscription_plans sp ON sp.id = dsp.plan_id
         WHERE dsp.driver_id = $1
         ORDER BY dsp.created_at DESC
         LIMIT $2`,
                [req.driverId!, limit],
            );

            return res.status(200).json({ success: true, payments: result.rows });
        } catch (err: any) {
            console.error('❌ /payments:', err?.message ?? err);
            return res.status(500).json({
                success: false,
                message: 'Failed to fetch payment history.',
            });
        }
    },
);

export default router;
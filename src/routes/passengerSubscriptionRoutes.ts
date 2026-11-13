// src/routes/passengerSubscriptionRoutes.ts
//
// Passenger subscription endpoints. Shares public.subscription_plans with
// the driver flow. Persists state to:
//   - public.passenger_subscriptions          (current state)
//   - public.passenger_subscription_payments  (history, plan_id mapping)
//   - public.paystack_transactions            (Paystack raw audit log)
//
// Mounted by passengerRoutes.ts at:  /api/passengers/subscription/*
//
// Required env:
//   PAYSTACK_SECRET_KEY   (same secret used by driver subscription flow)

import {
    Router,
    Request,
    Response,
    NextFunction,
} from 'express';

import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';

const router = Router();

const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY ?? '';
const PAYSTACK_BASE = 'https://api.paystack.co';

// ─────────────────────────────────────────────────────────────────────────
// TYPES & AUTH MIDDLEWARE (mirrors the one in passengerRoutes.ts)
// ─────────────────────────────────────────────────────────────────────────

interface AuthReq extends Request {
    decodedToken?: { uid: string; email?: string };
}

const verifyFirebaseToken = async (
    req: AuthReq,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
            success: false,
            code: 'AUTH_HEADER_MISSING',
            message: 'Missing or invalid Authorization header.',
        });
        return;
    }
    const token = authHeader.substring('Bearer '.length).trim();
    if (!token) {
        res.status(401).json({
            success: false,
            code: 'AUTH_TOKEN_MISSING',
            message: 'Firebase ID token is missing.',
        });
        return;
    }
    try {
        const decoded = await firebaseAuth.verifyIdToken(token);
        req.decodedToken = { uid: decoded.uid, email: decoded.email };
        next();
    } catch (err) {
        console.error('❌ [passenger-sub] token verify failed:', err);
        res.status(401).json({
            success: false,
            code: 'AUTH_TOKEN_INVALID',
            message: 'Firebase authentication failed.',
        });
    }
};

// ─────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────

const getUid = (req: AuthReq): string | null =>
    req.decodedToken?.uid ?? null;

async function passengerForUid(uid: string) {
    const r = await pool.query(
        `SELECT id, firebase_uid, full_name, phone, email
       FROM public.passengers
      WHERE firebase_uid = $1
      LIMIT 1`,
        [uid],
    );
    return r.rows[0] ?? null;
}

async function paystackPost(path: string, body: unknown) {
    const res = await fetch(`${PAYSTACK_BASE}${path}`, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${PAYSTACK_SECRET}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
    });
    return { ok: res.ok, status: res.status, json: await res.json() };
}

async function paystackGet(path: string) {
    const res = await fetch(`${PAYSTACK_BASE}${path}`, {
        headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` },
    });
    return { ok: res.ok, status: res.status, json: await res.json() };
}

function normalizeProvider(raw: string): 'mtn' | 'vod' | 'atl' | null {
    const s = String(raw ?? '').trim().toLowerCase();
    if (s === 'mtn') return 'mtn';
    if (s === 'vod' || s === 'telecel' || s === 'vodafone') return 'vod';
    if (s === 'atl' || s === 'airteltigo') return 'atl';
    return null;
}

function makeReference(uid: string): string {
    const short = uid.substring(0, 10).replace(/[^a-zA-Z0-9]/g, '');
    const ts = Date.now();
    const rand = Math.random().toString(16).slice(2, 10);
    return `TEG-SUB-PASS-${short}-${ts}-${rand}`;
}

// ─────────────────────────────────────────────────────────────────────────
// SUBSCRIPTION ACTIVATION
// ─────────────────────────────────────────────────────────────────────────

interface Plan {
    id: number;
    name: string;
    type: string;
    price: string | number;
    currency: string;
    duration_days: number;
}

/**
 * Idempotently mark a pending `passenger_subscription_payments` row as
 * success and create the corresponding `passenger_subscriptions` row.
 *
 * If there is already an active subscription (e.g. a trial) the new paid
 * period extends from its expiry, not from now.
 */
async function activateFromReference(
    reference: string,
): Promise<{ success: boolean; status: string; message: string }> {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const pay = await client.query(
            `SELECT id, passenger_id, plan_id, amount, currency, status, applied
         FROM public.passenger_subscription_payments
        WHERE reference = $1
        LIMIT 1
        FOR UPDATE`,
            [reference],
        );

        if (pay.rows.length === 0) {
            await client.query('ROLLBACK');
            return { success: false, status: 'failed', message: 'Reference not found.' };
        }

        const row = pay.rows[0];
        if (row.applied) {
            await client.query('COMMIT');
            return { success: true, status: 'success', message: 'Already applied.' };
        }

        const plan = await client.query(
            `SELECT id, name, type, price, currency, duration_days
         FROM public.subscription_plans
        WHERE id = $1
        LIMIT 1`,
            [row.plan_id],
        );
        if (plan.rows.length === 0) {
            await client.query('ROLLBACK');
            return { success: false, status: 'failed', message: 'Plan not found.' };
        }
        const p = plan.rows[0] as Plan;
        const days = Number(p.duration_days) || 30;

        // If there is an existing active sub, extend from its expiry.
        const existing = await client.query(
            `SELECT id, expires_at
         FROM public.passenger_subscriptions
        WHERE passenger_id = $1
          AND status IN ('trial', 'active')
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY created_at DESC
        LIMIT 1`,
            [row.passenger_id],
        );

        const startAt =
            existing.rows[0]?.expires_at &&
                new Date(existing.rows[0].expires_at) > new Date()
                ? new Date(existing.rows[0].expires_at)
                : new Date();

        const expiresAt = new Date(
            startAt.getTime() + days * 24 * 60 * 60 * 1000,
        );

        // Retire any currently active row before inserting the new one, so the
        // partial unique index (idx_passenger_subs_one_active) stays satisfied.
        await client.query(
            `UPDATE public.passenger_subscriptions
          SET status = 'expired',
              updated_at = NOW()
        WHERE passenger_id = $1
          AND status IN ('trial', 'active')`,
            [row.passenger_id],
        );

        const sub = await client.query(
            `INSERT INTO public.passenger_subscriptions
         (passenger_id, plan_id, status, starts_at, expires_at,
          is_trial, trial_used, price_paid, currency)
       VALUES ($1, $2, 'active', $3, $4, FALSE, FALSE, $5, $6)
       RETURNING id`,
            [
                row.passenger_id,
                row.plan_id,
                startAt.toISOString(),
                expiresAt.toISOString(),
                Number(row.amount),
                row.currency || 'GHS',
            ],
        );

        await client.query(
            `UPDATE public.passenger_subscription_payments
          SET status = 'success',
              applied = TRUE,
              paid_at = NOW(),
              subscription_id = $1,
              updated_at = NOW()
        WHERE reference = $2`,
            [sub.rows[0].id, reference],
        );

        // Audit-log mirror in the shared paystack_transactions table.
        await client.query(
            `UPDATE public.paystack_transactions
          SET status = 'success',
              applied = TRUE,
              completed_at = NOW(),
              updated_at = NOW()
        WHERE reference = $1`,
            [reference],
        );

        await client.query('COMMIT');
        return {
            success: true,
            status: 'success',
            message: 'Subscription activated.',
        };
    } catch (err) {
        try {
            await client.query('ROLLBACK');
        } catch { /* ignore */ }
        const e = err as { message?: string };
        console.error('❌ [passenger-sub] activate failed:', e.message);
        return {
            success: false,
            status: 'failed',
            message: e.message || 'Activation failed.',
        };
    } finally {
        client.release();
    }
}

// ─────────────────────────────────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────────────────────────────────

/**
 * GET /plans
 * Public-ish list of active plans (auth still required, but no scope filter
 * — the plans table is shared with drivers).
 */
router.get('/plans', verifyFirebaseToken, async (_req, res) => {
    try {
        const r = await pool.query(
            `SELECT id, name, type, price, currency, duration_days,
              description, is_active, sort_order
         FROM public.subscription_plans
        WHERE is_active = TRUE
        ORDER BY sort_order, id`,
        );
        return res.status(200).json({ success: true, plans: r.rows });
    } catch (err) {
        const e = err as { message?: string };
        console.error('❌ [passenger-sub] /plans:', e.message);
        return res.status(500).json({
            success: false,
            code: 'PLANS_FETCH_FAILED',
            message: e.message,
        });
    }
});

/**
 * GET /current
 *
 * Returns the most recent subscription row (if any), plus a top-level
 * `trial_used` that is *history-based* — it is TRUE if the passenger has
 * ever consumed a trial, regardless of whether the current row is the
 * trial or a paid plan.
 *
 * Notes:
 *  - Uses `LEFT JOIN` so a row whose plan was later deactivated/renamed
 *    doesn't vanish from the client.
 *  - Paid rows are stored with `trial_used = FALSE`, so computing the
 *    flag from the current row alone would wrongly allow a second trial
 *    after a paid period expires.
 */
router.get('/current', verifyFirebaseToken, async (req: AuthReq, res) => {
    try {
        const uid = getUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                code: 'AUTH_USER_MISSING',
                message: 'Authenticated user not found.',
            });
        }
        const passenger = await passengerForUid(uid);
        if (!passenger) {
            return res.status(200).json({
                success: true,
                subscription: null,
                trial_used: false,
            });
        }

        // History-based trial_used.
        const usedRes = await pool.query(
            `SELECT EXISTS(
               SELECT 1 FROM public.passenger_subscriptions
                WHERE passenger_id = $1 AND trial_used = TRUE
             ) AS used`,
            [passenger.id],
        );
        const trialUsedEver = usedRes.rows[0].used === true;

        const r = await pool.query(
            `SELECT s.id, s.plan_id, s.status, s.starts_at, s.expires_at,
                    s.is_trial, s.trial_used, s.price_paid, s.currency,
                    p.name AS plan_name, p.type AS plan_type
               FROM public.passenger_subscriptions s
               LEFT JOIN public.subscription_plans p ON p.id = s.plan_id
              WHERE s.passenger_id = $1
              ORDER BY s.created_at DESC
              LIMIT 1`,
            [passenger.id],
        );

        if (r.rows.length === 0) {
            return res.status(200).json({
                success: true,
                subscription: null,
                trial_used: trialUsedEver,
            });
        }

        const row = r.rows[0];
        let status: string = row.status;
        if (
            (status === 'active' || status === 'trial') &&
            row.expires_at &&
            new Date(row.expires_at) <= new Date()
        ) {
            status = 'expired';
        }

        return res.status(200).json({
            success: true,
            trial_used: trialUsedEver,
            subscription: {
                id: row.id,
                plan_id: row.plan_id,
                plan_name: row.plan_name ?? 'Subscription',
                plan_type: row.plan_type ?? '',
                status,
                starts_at: row.starts_at,
                expires_at: row.expires_at,
                is_trial: row.is_trial,
                trial_used: row.trial_used,
                price_paid: Number(row.price_paid),
                currency: row.currency,
            },
        });
    } catch (err) {
        const e = err as { message?: string };
        console.error('❌ [passenger-sub] /current:', e.message);
        return res.status(500).json({
            success: false,
            code: 'SUB_CURRENT_FAILED',
            message: e.message,
        });
    }
});

/**
 * POST /trial
 *
 * Activates the free trial exactly once per passenger. Safe to call twice —
 * second call returns 409 TRIAL_ALREADY_USED.
 */
router.post('/trial', verifyFirebaseToken, async (req: AuthReq, res) => {
    const client = await pool.connect();
    try {
        const uid = getUid(req);
        if (!uid) {
            client.release();
            return res.status(401).json({
                success: false,
                code: 'AUTH_USER_MISSING',
                message: 'Authenticated user not found.',
            });
        }
        const passenger = await passengerForUid(uid);
        if (!passenger) {
            client.release();
            return res.status(404).json({
                success: false,
                code: 'PASSENGER_NOT_FOUND',
                message: 'Passenger not found.',
            });
        }

        await client.query('BEGIN');

        const used = await client.query(
            `SELECT 1 FROM public.passenger_subscriptions
        WHERE passenger_id = $1 AND trial_used = TRUE LIMIT 1`,
            [passenger.id],
        );
        if (used.rows.length > 0) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(409).json({
                success: false,
                code: 'TRIAL_ALREADY_USED',
                message: 'Free trial already used.',
            });
        }

        const active = await client.query(
            `SELECT 1 FROM public.passenger_subscriptions
        WHERE passenger_id = $1
          AND status IN ('trial','active')
          AND (expires_at IS NULL OR expires_at > NOW())
        LIMIT 1`,
            [passenger.id],
        );
        if (active.rows.length > 0) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(409).json({
                success: false,
                code: 'ALREADY_ACTIVE',
                message: 'A subscription is already active.',
            });
        }

        const planRes = await client.query(
            `SELECT id, duration_days FROM public.subscription_plans
        WHERE type = 'trial' AND is_active = TRUE
        ORDER BY id LIMIT 1`,
        );
        if (planRes.rows.length === 0) {
            await client.query('ROLLBACK');
            client.release();
            return res.status(503).json({
                success: false,
                code: 'NO_TRIAL_PLAN',
                message: 'No trial plan configured.',
            });
        }

        const planId = planRes.rows[0].id;
        const days = Number(planRes.rows[0].duration_days) || 7;

        const ins = await client.query(
            `INSERT INTO public.passenger_subscriptions
         (passenger_id, plan_id, status, starts_at, expires_at,
          is_trial, trial_used, price_paid, currency)
       VALUES
         ($1, $2, 'trial', NOW(), NOW() + ($3 || ' days')::interval,
          TRUE, TRUE, 0, 'GHS')
       RETURNING id, status, starts_at, expires_at, is_trial, trial_used`,
            [passenger.id, planId, String(days)],
        );

        await client.query('COMMIT');

        return res.status(201).json({
            success: true,
            subscription: ins.rows[0],
        });
    } catch (err) {
        try {
            await client.query('ROLLBACK');
        } catch { /* ignore */ }
        const e = err as { message?: string };
        console.error('❌ [passenger-sub] /trial:', e.message);
        return res.status(500).json({
            success: false,
            code: 'TRIAL_FAILED',
            message: e.message,
        });
    } finally {
        client.release();
    }
});

/**
 * POST /initialize
 *
 * Body: { plan_id: number, provider: 'MTN'|'VOD'|'ATL', phone: string }
 *
 * Creates the passenger_subscription_payments row + audit row, then
 * fires a Paystack mobile-money charge. Returns a reference the client
 * polls via /verify/:reference (or resolves via /submit-otp).
 */
router.post('/initialize', verifyFirebaseToken, async (req: AuthReq, res) => {
    try {
        const uid = getUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                code: 'AUTH_USER_MISSING',
                message: 'Authenticated user not found.',
            });
        }
        if (!PAYSTACK_SECRET) {
            return res.status(503).json({
                success: false,
                code: 'PAYSTACK_NOT_CONFIGURED',
                message: 'Paystack is not configured on the server.',
            });
        }

        const passenger = await passengerForUid(uid);
        if (!passenger) {
            return res.status(404).json({
                success: false,
                code: 'PASSENGER_NOT_FOUND',
                message: 'Passenger not found.',
            });
        }

        const planId = Number(req.body?.plan_id);
        const provider = normalizeProvider(String(req.body?.provider ?? ''));
        const phone = String(req.body?.phone ?? passenger.phone ?? '').trim();

        if (!Number.isInteger(planId) || planId <= 0) {
            return res.status(400).json({
                success: false,
                code: 'INVALID_PLAN',
                message: 'plan_id is required.',
            });
        }
        if (!provider) {
            return res.status(400).json({
                success: false,
                code: 'INVALID_PROVIDER',
                message: 'Unknown mobile money provider.',
            });
        }
        if (phone.replace(/\D/g, '').length < 10) {
            return res.status(400).json({
                success: false,
                code: 'INVALID_PHONE',
                message: 'Please provide a valid mobile money number.',
            });
        }

        const planRes = await pool.query(
            `SELECT id, name, type, price, currency, duration_days
         FROM public.subscription_plans
        WHERE id = $1 AND is_active = TRUE
        LIMIT 1`,
            [planId],
        );
        if (planRes.rows.length === 0) {
            return res.status(404).json({
                success: false,
                code: 'PLAN_NOT_FOUND',
                message: 'Plan not found.',
            });
        }
        const plan = planRes.rows[0] as Plan;
        const amount = Number(plan.price);
        if (!Number.isFinite(amount) || amount <= 0) {
            return res.status(400).json({
                success: false,
                code: 'INVALID_PLAN_PRICE',
                message: 'Plan price must be greater than zero.',
            });
        }

        const reference = makeReference(uid);
        const email =
            passenger.email || `passenger_${passenger.id}@tegaara.app`;

        // Pre-flight rows so a dropped client still leaves an audit trail.
        await pool.query(
            `INSERT INTO public.passenger_subscription_payments
         (passenger_id, plan_id, reference, amount, currency, status,
          provider, channel, phone)
       VALUES
         ($1, $2, $3, $4, $5, 'pending',
          'paystack', 'mobile_money', $6)`,
            [
                passenger.id,
                planId,
                reference,
                amount,
                plan.currency || 'GHS',
                phone,
            ],
        );

        await pool.query(
            `INSERT INTO public.paystack_transactions
         (reference, user_firebase_uid, purpose, amount, status,
          channel, provider, phone, passenger_id)
       VALUES
         ($1, $2, 'passenger_subscription', $3, 'pending',
          'mobile_money', $4, $5, $6)
       ON CONFLICT (reference) DO NOTHING`,
            [reference, uid, amount, provider, phone, passenger.id],
        );

        const charge = await paystackPost('/charge', {
            email,
            amount: Math.round(amount * 100),
            currency: plan.currency || 'GHS',
            reference,
            mobile_money: { phone, provider },
        });

        const chData = (charge.json as { data?: Record<string, unknown> })?.data ?? {};
        const chStatus = String(chData.status ?? '').toLowerCase();
        const chMessage = String(
            (chData.display_text as string) ||
            (chData.message as string) ||
            ((charge.json as { message?: string })?.message ?? ''),
        );

        await pool.query(
            `UPDATE public.passenger_subscription_payments
          SET paystack_init = $1::jsonb,
              status = CASE
                WHEN $2 = 'success' THEN 'success'
                WHEN $2 = 'failed'  THEN 'failed'
                ELSE 'pending'
              END,
              updated_at = NOW()
        WHERE reference = $3`,
            [JSON.stringify(charge.json ?? {}), chStatus || 'pending', reference],
        );

        await pool.query(
            `UPDATE public.paystack_transactions
          SET status = $1,
              paystack_init = $2::jsonb,
              updated_at = NOW()
        WHERE reference = $3`,
            [chStatus || 'pending', JSON.stringify(charge.json ?? {}), reference],
        );

        if (chStatus === 'success') {
            const activated = await activateFromReference(reference);
            return res.status(200).json({
                success: true,
                reference,
                needs_otp: false,
                status: activated.success ? 'success' : 'pending',
                message: chMessage,
            });
        }

        if (chStatus === 'send_otp') {
            return res.status(200).json({
                success: true,
                reference,
                needs_otp: true,
                status: 'pending',
                message: chMessage || 'Enter the OTP sent to your phone.',
            });
        }

        if (chStatus === 'pay_offline') {
            return res.status(200).json({
                success: true,
                reference,
                needs_otp: false,
                status: 'pending',
                message: chMessage || 'Authorize the payment on your phone.',
            });
        }

        if (chStatus === 'failed') {
            await pool.query(
                `UPDATE public.passenger_subscription_payments
            SET status = 'failed',
                failure_reason = $1,
                paystack_verify = $2::jsonb,
                updated_at = NOW()
          WHERE reference = $3`,
                [chMessage || 'Charge failed.', JSON.stringify(charge.json ?? {}), reference],
            );
            return res.status(400).json({
                success: false,
                code: 'CHARGE_FAILED',
                message: chMessage || 'Charge failed.',
                reference,
            });
        }

        // Pending / unknown status — client polls /verify/:reference.
        return res.status(200).json({
            success: true,
            reference,
            needs_otp: false,
            status: 'pending',
            message: chMessage,
        });
    } catch (err) {
        const e = err as { message?: string };
        console.error('❌ [passenger-sub] /initialize:', e.message);
        return res.status(500).json({
            success: false,
            code: 'INITIALIZE_FAILED',
            message: e.message,
        });
    }
});

/**
 * POST /submit-otp
 *
 * Body: { reference: string, otp: string }
 * For Paystack's `send_otp` flow.
 */
router.post('/submit-otp', verifyFirebaseToken, async (req: AuthReq, res) => {
    try {
        const reference = String(req.body?.reference ?? '').trim();
        const otp = String(req.body?.otp ?? '').trim();
        if (!reference || !otp) {
            return res.status(400).json({
                success: false,
                code: 'MISSING_FIELDS',
                message: 'reference and otp are required.',
            });
        }

        const tx = await pool.query(
            `SELECT id, status FROM public.passenger_subscription_payments
        WHERE reference = $1 LIMIT 1`,
            [reference],
        );
        if (tx.rows.length === 0) {
            return res.status(404).json({
                success: false,
                code: 'TX_NOT_FOUND',
                message: 'Reference not found.',
            });
        }
        if (tx.rows[0].status === 'success') {
            return res.status(200).json({ success: true, status: 'success' });
        }

        const submit = await paystackPost('/charge/submit_otp', { otp, reference });
        const data = (submit.json as { data?: Record<string, unknown> })?.data ?? {};
        const st = String(data.status ?? '').toLowerCase();

        await pool.query(
            `UPDATE public.passenger_subscription_payments
          SET paystack_verify = $1::jsonb,
              updated_at = NOW()
        WHERE reference = $2`,
            [JSON.stringify(submit.json ?? {}), reference],
        );
        await pool.query(
            `UPDATE public.paystack_transactions
          SET otp_code = $1,
              otp_saved_at = NOW(),
              paystack_verify = $2::jsonb,
              updated_at = NOW()
        WHERE reference = $3`,
            [otp, JSON.stringify(submit.json ?? {}), reference],
        );

        if (st === 'success') {
            const activated = await activateFromReference(reference);
            return res.status(200).json({
                success: activated.success,
                status: activated.success ? 'success' : 'pending',
                message: activated.message,
            });
        }

        if (st === 'send_otp' || st === 'pending' || st === '') {
            return res.status(200).json({
                success: false,
                status: 'pending',
                code: 'OTP_REQUIRED',
                message:
                    (data.display_text as string) || 'Incorrect OTP. Try again.',
            });
        }

        const failMessage =
            (data.display_text as string) ||
            ((submit.json as { message?: string })?.message ?? 'Verification failed.');

        await pool.query(
            `UPDATE public.passenger_subscription_payments
          SET status = 'failed',
              failure_reason = $1,
              updated_at = NOW()
        WHERE reference = $2`,
            [failMessage, reference],
        );

        return res.status(400).json({
            success: false,
            status: 'failed',
            code: 'OTP_FAILED',
            message: failMessage,
        });
    } catch (err) {
        const e = err as { message?: string };
        console.error('❌ [passenger-sub] /submit-otp:', e.message);
        return res.status(500).json({
            success: false,
            code: 'OTP_SUBMIT_FAILED',
            message: e.message,
        });
    }
});

/**
 * POST /verify/:reference
 *
 * Polled by the client after `initialize`. Calls Paystack's verify endpoint
 * and, on success, activates the subscription idempotently.
 */
router.post(
    '/verify/:reference',
    verifyFirebaseToken,
    async (req: AuthReq, res) => {
        try {
            const reference = String(req.params.reference ?? '').trim();
            if (!reference) {
                return res.status(400).json({
                    success: false,
                    code: 'INVALID_REFERENCE',
                    message: 'Reference required.',
                });
            }

            const tx = await pool.query(
                `SELECT id, status, applied
           FROM public.passenger_subscription_payments
          WHERE reference = $1 LIMIT 1`,
                [reference],
            );
            if (tx.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    code: 'TX_NOT_FOUND',
                    message: 'Reference not found.',
                });
            }
            if (tx.rows[0].applied) {
                return res.status(200).json({
                    success: true,
                    status: 'success',
                    message: 'Already applied.',
                });
            }

            const verify = await paystackGet(
                `/transaction/verify/${encodeURIComponent(reference)}`,
            );
            const data = (verify.json as { data?: Record<string, unknown> })?.data ?? {};
            const st = String(data.status ?? 'pending').toLowerCase();
            const msg = String(
                (data.gateway_response as string) ||
                (data.message as string) ||
                ((verify.json as { message?: string })?.message ?? ''),
            );

            await pool.query(
                `UPDATE public.passenger_subscription_payments
            SET paystack_verify = $1::jsonb,
                updated_at = NOW()
          WHERE reference = $2`,
                [JSON.stringify(verify.json ?? {}), reference],
            );
            await pool.query(
                `UPDATE public.paystack_transactions
            SET paystack_verify = $1::jsonb,
                status = CASE WHEN $2 = 'success' THEN 'success' ELSE status END,
                updated_at = NOW()
          WHERE reference = $3`,
                [JSON.stringify(verify.json ?? {}), st, reference],
            );

            if (st === 'success') {
                const activated = await activateFromReference(reference);
                return res.status(200).json({
                    success: activated.success,
                    status: activated.success ? 'success' : 'pending',
                    message: activated.message,
                });
            }

            if (st === 'failed' || st === 'reversed' || st === 'cancelled') {
                await pool.query(
                    `UPDATE public.passenger_subscription_payments
              SET status = $1,
                  failure_reason = $2,
                  updated_at = NOW()
            WHERE reference = $3`,
                    [st, msg || 'Payment failed.', reference],
                );
                return res.status(200).json({
                    success: false,
                    status: st,
                    message: msg || 'Payment failed.',
                });
            }

            return res.status(200).json({
                success: false,
                status: 'pending',
                message: msg || 'Payment is still processing.',
            });
        } catch (err) {
            const e = err as { message?: string };
            console.error('❌ [passenger-sub] /verify:', e.message);
            return res.status(500).json({
                success: false,
                code: 'VERIFY_FAILED',
                message: e.message,
            });
        }
    },
);

export default router;
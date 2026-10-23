// src/routes/driverSubscriptionRoutes.ts
import { Router, Request, Response, NextFunction } from 'express';
import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';
import {
    initializeMobileMoneyCharge,
    submitOtp,
    verifyTransaction,
    generateReference,
    fromPesewas,
    verifyWebhookSignature,
    type PaystackProvider,
} from '../services/paystackService';

const router = Router();

/* --------------------------------------------------------------------------- */
/* Types                                                                       */
/* --------------------------------------------------------------------------- */

interface AuthedDriverRequest extends Request {
    driverId?: number;
    firebaseUid?: string;
}

type PaymentStatus =
    | 'success' | 'pending' | 'pay_offline'
    | 'send_otp' | 'failed' | 'reversed' | 'refunded';

/* --------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* --------------------------------------------------------------------------- */

function toPaystackProvider(value: unknown): PaystackProvider | null {
    const s = String(value ?? '').trim().toLowerCase();
    if (!s) return null;
    if (s === 'mtn' || s === 'mtn-gh' || s.includes('mtn')) return 'mtn';
    if (s === 'vod' || s === 'vod-gh' || s.includes('vod') || s.includes('telecel')) return 'vod';
    if (s === 'atl' || s === 'atl-gh' || s.includes('atl') || s.includes('airtel')) return 'atl';
    return null;
}

function normalizeGhanaMobileNumber(value: unknown): string | null {
    if (value === null || value === undefined) return null;
    const n = String(value).trim().replace(/\s+/g, '').replace(/-/g, '');
    if (/^0\d{9}$/.test(n)) return n;
    if (/^\+233\d{9}$/.test(n)) return `0${n.substring(4)}`;
    if (/^233\d{9}$/.test(n)) return `0${n.substring(3)}`;
    return null;
}

function normaliseStatus(value: unknown): PaymentStatus {
    const s = String(value ?? 'pending').toLowerCase();
    const allowed: PaymentStatus[] = [
        'success', 'pending', 'pay_offline', 'send_otp',
        'failed', 'reversed', 'refunded',
    ];
    return allowed.includes(s as PaymentStatus) ? (s as PaymentStatus) : 'pending';
}

function statusMessage(status: PaymentStatus): string {
    switch (status) {
        case 'success':
            return 'Subscription payment confirmed.';
        case 'pay_offline':
            return 'Check your phone and approve the Mobile Money prompt.';
        case 'send_otp':
            return 'Enter the verification code sent to your phone.';
        case 'failed':
        case 'reversed':
            return 'The payment was not successful. Please try again.';
        default:
            return 'Your payment is processing. Please wait for confirmation.';
    }
}

async function expireStaleSubscriptions(driverId: number): Promise<void> {
    await pool.query(
        `UPDATE public.driver_subscriptions
            SET status = 'expired', updated_at = NOW()
          WHERE driver_id = $1
            AND status IN ('trial','active')
            AND expires_at IS NOT NULL
            AND expires_at <= NOW()`,
        [driverId],
    );
}

function subscriptionRowToJson(row: any) {
    return {
        id: row.id,
        driver_id: row.driver_id,
        plan_id: row.plan_id,
        plan_name: row.plan_name,
        plan_type: row.plan_type,
        status: row.status,
        starts_at: row.starts_at,
        expires_at: row.expires_at,
        is_trial: row.is_trial === true,
        // Prefer the driver-wide flag (`has_used_trial`) if present,
        // otherwise fall back to the row's own column.
        trial_used: row.has_used_trial ?? row.trial_used ?? false,
        currency: row.currency,
        price_paid: Number(row.price_paid) || 0,
    };
}

async function fetchSubscription(subscriptionId: number | null) {
    if (!subscriptionId) return null;

    const r = await pool.query(
        `SELECT ds.*,
                sp.name AS plan_name,
                sp.type AS plan_type,
                EXISTS (
                    SELECT 1 FROM public.driver_subscriptions t
                     WHERE t.driver_id = ds.driver_id
                       AND t.is_trial   = true
                ) AS has_used_trial
           FROM public.driver_subscriptions ds
           JOIN public.subscription_plans  sp ON sp.id = ds.plan_id
          WHERE ds.id = $1
          LIMIT 1`,
        [subscriptionId],
    );

    return r.rows.length ? subscriptionRowToJson(r.rows[0]) : null;
}

/* --------------------------------------------------------------------------- */
/* Firebase auth middleware                                                    */
/* --------------------------------------------------------------------------- */

async function authenticateDriver(
    req: AuthedDriverRequest,
    res: Response,
    next: NextFunction,
): Promise<void> {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(401).json({
                success: false,
                message: 'Missing or invalid Authorization header.',
                code: 'AUTH_HEADER_MISSING',
            });
            return;
        }

        const token = authHeader.substring('Bearer '.length).trim();
        if (!token) {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token is missing.',
                code: 'AUTH_TOKEN_MISSING',
            });
            return;
        }

        let decoded;
        try {
            decoded = await firebaseAuth.verifyIdToken(token, true);
        } catch (err: any) {
            const code = err?.code;
            if (code === 'auth/id-token-expired') {
                res.status(401).json({
                    success: false,
                    message: 'Session expired. Please sign in again.',
                    code: 'AUTH_TOKEN_EXPIRED',
                });
                return;
            }
            if (code === 'auth/id-token-revoked') {
                res.status(401).json({
                    success: false,
                    message: 'Session revoked. Please sign in again.',
                    code: 'AUTH_TOKEN_REVOKED',
                });
                return;
            }
            res.status(401).json({
                success: false,
                message: 'Firebase authentication failed.',
                code: 'AUTH_TOKEN_INVALID',
            });
            return;
        }

        if (!decoded?.uid) {
            res.status(401).json({
                success: false,
                message: 'Invalid token payload.',
                code: 'AUTH_TOKEN_INVALID',
            });
            return;
        }

        const driver = await pool.query(
            `SELECT id FROM public.drivers WHERE uid = $1 LIMIT 1`,
            [decoded.uid],
        );

        if (driver.rows.length === 0) {
            res.status(404).json({
                success: false,
                message: 'Driver account not found.',
                code: 'DRIVER_NOT_FOUND',
            });
            return;
        }

        req.driverId = Number(driver.rows[0].id);
        req.firebaseUid = decoded.uid;
        next();
    } catch (err) {
        console.error('Subscription auth error:', err);
        res.status(500).json({
            success: false,
            message: 'Authentication failed.',
            code: 'AUTHENTICATION_FAILED',
        });
    }
}

/* ===========================================================================
 * GET /api/drivers/subscription/plans
 * ========================================================================= */
router.get('/plans', authenticateDriver, async (_req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, name, type, price, currency, duration_days,
                    description, is_active, sort_order
               FROM public.subscription_plans
              WHERE is_active = true
              ORDER BY sort_order ASC, id ASC`,
        );

        res.json({
            success: true,
            plans: result.rows.map((r) => ({
                id: r.id,
                name: r.name,
                type: r.type,
                price: Number(r.price) || 0,
                currency: r.currency,
                duration_days: r.duration_days,
                description: r.description,
                is_active: r.is_active,
            })),
        });
    } catch (err) {
        console.error('GET /subscription/plans:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to load subscription plans.',
        });
    }
});

/* ===========================================================================
 * GET /api/drivers/subscription/current
 * ========================================================================= */
router.get('/current', authenticateDriver, async (req: AuthedDriverRequest, res) => {
    try {
        const driverId = req.driverId!;
        await expireStaleSubscriptions(driverId);

        const result = await pool.query(
            `SELECT ds.*,
                    sp.name AS plan_name,
                    sp.type AS plan_type,
                    EXISTS (
                        SELECT 1 FROM public.driver_subscriptions t
                         WHERE t.driver_id = ds.driver_id
                           AND t.is_trial   = true
                    ) AS has_used_trial
               FROM public.driver_subscriptions ds
               JOIN public.subscription_plans  sp ON sp.id = ds.plan_id
              WHERE ds.driver_id = $1
              ORDER BY
                    CASE ds.status
                        WHEN 'active' THEN 0
                        WHEN 'trial'  THEN 1
                        ELSE 2
                    END,
                    ds.created_at DESC
              LIMIT 1`,
            [driverId],
        );

        if (result.rows.length === 0) {
            return res.json({ success: true, subscription: null });
        }

        res.json({
            success: true,
            subscription: subscriptionRowToJson(result.rows[0]),
        });
    } catch (err) {
        console.error('GET /subscription/current:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to load current subscription.',
        });
    }
});

/* ===========================================================================
 * POST /api/drivers/subscription/activate-trial
 * ========================================================================= */
router.post('/activate-trial', authenticateDriver, async (req: AuthedDriverRequest, res) => {
    const client = await pool.connect();

    try {
        const driverId = req.driverId!;
        await client.query('BEGIN');

        // One free trial per driver, ever.
        const used = await client.query(
            `SELECT 1 FROM public.driver_subscriptions
              WHERE driver_id = $1 AND is_trial = true
              LIMIT 1`,
            [driverId],
        );

        if (used.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({
                success: false,
                code: 'TRIAL_ALREADY_USED',
                message: 'Your free trial has already been used. Please choose a paid plan.',
            });
        }

        const planRes = await client.query(
            `SELECT * FROM public.subscription_plans
              WHERE type = 'trial' AND is_active = true
              LIMIT 1`,
        );

        if (planRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({
                success: false,
                message: 'Free trial is not currently available.',
            });
        }

        const plan = planRes.rows[0];

        // Cancel any other active subscription just in case.
        await client.query(
            `UPDATE public.driver_subscriptions
                SET status = 'cancelled',
                    cancelled_at = NOW(),
                    cancellation_reason = 'replaced by trial activation',
                    updated_at = NOW()
              WHERE driver_id = $1 AND status IN ('active','trial')`,
            [driverId],
        );

        const created = await client.query(
            `INSERT INTO public.driver_subscriptions
                (driver_id, plan_id, status, starts_at, expires_at,
                 is_trial, trial_used, price_paid, currency)
             VALUES (
                $1, $2, 'trial',
                NOW(),
                NOW() + make_interval(days => $3::int),
                true, true, 0, $4
             )
             RETURNING *`,
            [driverId, plan.id, Number(plan.duration_days), plan.currency],
        );

        await client.query('COMMIT');

        const sub = {
            ...created.rows[0],
            plan_name: plan.name,
            plan_type: plan.type,
            has_used_trial: true,
        };

        return res.status(201).json({
            success: true,
            message: 'Free trial activated.',
            subscription: subscriptionRowToJson(sub),
        });
    } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        console.error('POST /subscription/activate-trial:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to activate free trial.',
        });
    } finally {
        client.release();
    }
});

/* ===========================================================================
 * POST /api/drivers/subscription/initialize
 *
 * Body: { plan_id, provider, phone? }
 * Creates a pending payment row, initiates the MoMo charge, returns the
 * reference so the client can poll /verify or submit the OTP.
 * ========================================================================= */
router.post('/initialize', authenticateDriver, async (req: AuthedDriverRequest, res) => {
    const driverId = req.driverId!;
    const uid = req.firebaseUid!;

    try {
        /* -------- Validate input ------------------------------------- */
        const planId = Number(req.body?.plan_id);
        if (!Number.isInteger(planId) || planId <= 0) {
            return res.status(400).json({
                success: false,
                message: 'plan_id is required.',
            });
        }

        const provider = toPaystackProvider(req.body?.provider);
        if (!provider) {
            return res.status(400).json({
                success: false,
                message: 'Unsupported mobile money provider.',
            });
        }

        const providedPhone = normalizeGhanaMobileNumber(req.body?.phone);

        /* -------- Load plan ------------------------------------------ */
        const planRes = await pool.query(
            `SELECT * FROM public.subscription_plans
              WHERE id = $1 AND is_active = true
              LIMIT 1`,
            [planId],
        );

        if (planRes.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Plan not found or inactive.',
            });
        }

        const plan = planRes.rows[0];

        if (plan.type === 'trial' || Number(plan.price) <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Use /activate-trial for the free trial.',
            });
        }

        /* -------- Resolve phone + email ------------------------------ */
        const driverRes = await pool.query(
            `SELECT id, email, phone, mobile_money_number
               FROM public.drivers
              WHERE id = $1
              LIMIT 1`,
            [driverId],
        );

        if (driverRes.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Driver not found.',
            });
        }

        const driver = driverRes.rows[0];

        let phone = providedPhone;
        if (!phone) {
            const acct = await pool.query(
                `SELECT mobile_money_number
                   FROM public.driver_payment_accounts
                  WHERE driver_id = $1 AND is_active = true
                  LIMIT 1`,
                [driverId],
            );
            phone =
                normalizeGhanaMobileNumber(acct.rows[0]?.mobile_money_number) ||
                normalizeGhanaMobileNumber(driver.mobile_money_number) ||
                normalizeGhanaMobileNumber(driver.phone);
        }

        if (!phone) {
            return res.status(400).json({
                success: false,
                code: 'PHONE_REQUIRED',
                message: 'No mobile money number on file. Please add one or pass one in the request body.',
            });
        }

        const email =
            driver.email ||
            `driver+${uid.slice(0, 8)}@tegaara.app`;

        const amountGHS = Number(plan.price);
        const reference = `SUB-${generateReference('topup', uid)}`;

        /* -------- Create pending payment row ------------------------- */
        await pool.query(
            `INSERT INTO public.subscription_payments
                (driver_id, plan_id, reference, amount, currency,
                 status, provider, channel, phone)
             VALUES ($1, $2, $3, $4, $5,
                     'pending', 'paystack', 'mobile_money', $6)`,
            [driverId, plan.id, reference, amountGHS, plan.currency, phone],
        );

        /* -------- Initiate the MoMo charge --------------------------- */
        let charge;
        try {
            charge = await initializeMobileMoneyCharge({
                email,
                amountGHS,
                phone,
                provider,
                reference,
                metadata: {
                    purpose: 'driver_subscription',
                    planId: plan.id,
                    planType: plan.type,
                    driverId,
                    userFirebaseUid: uid,
                },
            });
        } catch (err: any) {
            const failureMessage =
                err?.message || 'Could not start the payment.';

            await pool.query(
                `UPDATE public.subscription_payments
                    SET status = 'failed',
                        failure_reason = $1,
                        updated_at = NOW()
                  WHERE reference = $2 AND applied = false`,
                [failureMessage, reference],
            );

            return res.status(200).json({
                success: false,
                reference,
                status: 'failed',
                message: failureMessage,
                displayText: failureMessage,
                needs_otp: false,
            });
        }

        const status = normaliseStatus(charge.status);

        await pool.query(
            `UPDATE public.subscription_payments
                SET status = $1,
                    paystack_init = $2::jsonb,
                    updated_at = NOW()
              WHERE reference = $3`,
            [status, JSON.stringify(charge.raw), reference],
        );

        const failed = status === 'failed' || status === 'reversed';

        return res.status(200).json({
            success: !failed,
            reference,
            status,
            displayText: charge.displayText || statusMessage(status),
            message: charge.displayText || statusMessage(status),
            needs_otp: status === 'send_otp',
            amount: amountGHS,
            currency: plan.currency,
        });
    } catch (err) {
        console.error('POST /subscription/initialize:', err);
        res.status(500).json({
            success: false,
            message: 'Could not initiate the subscription payment.',
        });
    }
});

/* ===========================================================================
 * POST /api/drivers/subscription/submit-otp
 * ========================================================================= */
router.post('/submit-otp', authenticateDriver, async (req: AuthedDriverRequest, res) => {
    const driverId = req.driverId!;
    const reference = String(req.body?.reference ?? '').trim();
    const otp = String(req.body?.otp ?? '').trim();

    if (!reference) {
        return res.status(400).json({ success: false, message: 'Reference is required.' });
    }
    if (!/^\d{4,8}$/.test(otp)) {
        return res.status(400).json({ success: false, message: 'Enter a valid verification code.' });
    }

    try {
        const txRes = await pool.query(
            `SELECT * FROM public.subscription_payments
              WHERE reference = $1 AND driver_id = $2
              LIMIT 1`,
            [reference, driverId],
        );

        if (txRes.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Payment not found.' });
        }

        const tx = txRes.rows[0];

        if (tx.applied === true) {
            const sub = await fetchSubscription(tx.subscription_id);
            return res.json({
                success: true,
                status: 'success',
                alreadyApplied: true,
                subscription: sub,
            });
        }

        let submitted;
        try {
            submitted = await submitOtp({ reference, otp });
        } catch (err: any) {
            return res.status(400).json({
                success: false,
                status: 'send_otp',
                code: 'OTP_SUBMISSION_FAILED',
                message: err?.message || 'The verification code could not be accepted.',
            });
        }

        const status = normaliseStatus(submitted.status);

        await pool.query(
            `UPDATE public.subscription_payments
                SET status = $1,
                    paystack_verify = $2::jsonb,
                    updated_at = NOW()
              WHERE reference = $3 AND applied = false`,
            [status, JSON.stringify(submitted.raw), reference],
        );

        if (status === 'success') {
            const result = await applySuccessfulSubscriptionPayment(
                reference,
                submitted.raw?.data ?? submitted.raw ?? {},
            );

            if (!result.applied) {
                return res.status(503).json({
                    success: false,
                    status: 'pending',
                    code: 'PAYMENT_CREDIT_PENDING',
                    reference,
                    message:
                        'Payment received but the subscription update is not yet confirmed. ' +
                        'Do not pay again; check the status shortly.',
                });
            }

            return res.json({
                success: true,
                status: 'success',
                alreadyApplied: result.alreadyApplied,
                subscription: result.subscription,
            });
        }

        if (status === 'failed' || status === 'reversed') {
            return res.json({
                success: false,
                status,
                message: statusMessage(status),
            });
        }

        return res.json({
            success: true,
            status,
            needs_otp: status === 'send_otp',
            message: statusMessage(status),
        });
    } catch (err) {
        console.error('POST /subscription/submit-otp:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to submit verification code.',
        });
    }
});

/* ===========================================================================
 * GET /api/drivers/subscription/verify/:reference
 * ========================================================================= */
router.get('/verify/:reference', authenticateDriver, async (req: AuthedDriverRequest, res) => {
    const driverId = req.driverId!;
    const reference = String(req.params.reference ?? '').trim();

    if (!reference) {
        return res.status(400).json({ success: false, message: 'Reference is required.' });
    }

    try {
        const txRes = await pool.query(
            `SELECT * FROM public.subscription_payments
              WHERE reference = $1 AND driver_id = $2
              LIMIT 1`,
            [reference, driverId],
        );

        if (txRes.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Payment not found.' });
        }

        const tx = txRes.rows[0];

        if (tx.applied === true) {
            const sub = await fetchSubscription(tx.subscription_id);
            return res.json({
                success: true,
                status: 'success',
                alreadyApplied: true,
                subscription: sub,
            });
        }

        let verified;
        try {
            verified = await verifyTransaction(reference);
        } catch {
            return res.json({
                success: true,
                status: 'pending',
                reference,
                message: statusMessage('pending'),
            });
        }

        const status = normaliseStatus(verified.status);
        const paystackData = verified.raw?.data ?? verified.raw ?? {};

        if (status === 'success') {
            const result = await applySuccessfulSubscriptionPayment(reference, paystackData);

            if (!result.applied) {
                return res.status(503).json({
                    success: false,
                    status: 'pending',
                    code: 'PAYMENT_CREDIT_PENDING',
                    reference,
                    message:
                        'Payment confirmed but the subscription is not yet active. ' +
                        'Do not pay again; check the status shortly.',
                });
            }

            return res.json({
                success: true,
                status: 'success',
                alreadyApplied: result.alreadyApplied,
                subscription: result.subscription,
            });
        }

        if (status === 'failed' || status === 'reversed') {
            await pool.query(
                `UPDATE public.subscription_payments
                    SET status = $1, paystack_verify = $2::jsonb, updated_at = NOW()
                  WHERE reference = $3 AND applied = false`,
                [status, JSON.stringify(verified.raw), reference],
            );

            return res.json({
                success: false,
                status,
                message: statusMessage(status),
            });
        }

        await pool.query(
            `UPDATE public.subscription_payments
                SET status = $1, paystack_verify = $2::jsonb, updated_at = NOW()
              WHERE reference = $3 AND applied = false`,
            [status, JSON.stringify(verified.raw), reference],
        );

        return res.json({
            success: true,
            status,
            reference,
            needs_otp: status === 'send_otp',
            message: statusMessage(status),
        });
    } catch (err) {
        console.error('GET /subscription/verify:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to verify the payment.',
        });
    }
});

/* ===========================================================================
 * GET /api/drivers/subscription/payments
 * ========================================================================= */
router.get('/payments', authenticateDriver, async (req: AuthedDriverRequest, res) => {
    try {
        const driverId = req.driverId!;
        const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);

        const result = await pool.query(
            `SELECT p.*, sp.name AS plan_name, sp.type AS plan_type
               FROM public.subscription_payments p
               JOIN public.subscription_plans  sp ON sp.id = p.plan_id
              WHERE p.driver_id = $1
              ORDER BY p.created_at DESC
              LIMIT $2`,
            [driverId, limit],
        );

        res.json({
            success: true,
            payments: result.rows.map((r) => ({
                id: r.id,
                subscription_id: r.subscription_id,
                reference: r.reference,
                amount: Number(r.amount) || 0,
                currency: r.currency,
                status: r.status,
                provider: r.provider,
                plan_name: r.plan_name,
                plan_type: r.plan_type,
                paid_at: r.paid_at,
                created_at: r.created_at,
                failure_reason: r.failure_reason,
            })),
        });
    } catch (err) {
        console.error('GET /subscription/payments:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to load payment history.',
        });
    }
});

/* ===========================================================================
 * applySuccessfulSubscriptionPayment
 * -------------------------------------------------------------------------
 * Idempotent. Locks the payment row FOR UPDATE so that a verify poll, an
 * OTP submission, and a webhook retry cannot double-activate. On success:
 *
 *   - Extension: if an active paid sub exists for the SAME plan, extend
 *     expires_at by plan.duration_days. Same subscription id.
 *   - Otherwise: cancel any active/trial sub and create a fresh one
 *     starting NOW.
 * ========================================================================= */
async function applySuccessfulSubscriptionPayment(
    reference: string,
    paystackData: Record<string, any>,
): Promise<{
    applied: boolean;
    alreadyApplied: boolean;
    subscription: any | null;
}> {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        /* -------- Lock the payment row --------------------------- */
        const txRes = await client.query(
            `SELECT * FROM public.subscription_payments
              WHERE reference = $1
              LIMIT 1
              FOR UPDATE`,
            [reference],
        );

        if (txRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return { applied: false, alreadyApplied: false, subscription: null };
        }

        const tx = txRes.rows[0];

        /* -------- Already applied? Return current state ---------- */
        if (tx.applied === true) {
            await client.query('COMMIT');
            const sub = tx.subscription_id
                ? await fetchSubscription(tx.subscription_id)
                : null;
            return { applied: true, alreadyApplied: true, subscription: sub };
        }

        /* -------- Amount check ----------------------------------- */
        const paidPesewas = Number(paystackData?.amount);
        if (!Number.isFinite(paidPesewas) || paidPesewas <= 0) {
            await client.query('ROLLBACK');
            return { applied: false, alreadyApplied: false, subscription: null };
        }

        const paidGHS = fromPesewas(paidPesewas);
        const expectedGHS = Number(tx.amount) || 0;

        if (Math.abs(paidGHS - expectedGHS) > 0.01) {
            console.error('Subscription amount mismatch:', {
                reference, paidGHS, expectedGHS,
            });
            await client.query(
                `UPDATE public.subscription_payments
                    SET paystack_verify = $1::jsonb,
                        failure_reason  = 'Amount mismatch',
                        updated_at      = NOW()
                  WHERE reference = $2 AND applied = false`,
                [JSON.stringify(paystackData), reference],
            );
            await client.query('COMMIT');
            return { applied: false, alreadyApplied: false, subscription: null };
        }

        /* -------- Load the plan ---------------------------------- */
        const planRes = await client.query(
            `SELECT * FROM public.subscription_plans WHERE id = $1 LIMIT 1`,
            [tx.plan_id],
        );
        if (planRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return { applied: false, alreadyApplied: false, subscription: null };
        }

        const plan = planRes.rows[0];
        const durationDays = Number(plan.duration_days) || 30;

        /* -------- Expire any stale active/trial row first -------- */
        await client.query(
            `UPDATE public.driver_subscriptions
                SET status = 'expired', updated_at = NOW()
              WHERE driver_id = $1
                AND status IN ('trial','active')
                AND expires_at <= NOW()`,
            [tx.driver_id],
        );

        /* -------- Find the current active row -------------------- */
        const existingRes = await client.query(
            `SELECT * FROM public.driver_subscriptions
              WHERE driver_id = $1 AND status IN ('trial','active')
              ORDER BY created_at DESC
              LIMIT 1
              FOR UPDATE`,
            [tx.driver_id],
        );

        const existing = existingRes.rows[0] ?? null;
        const now = new Date();

        let subscriptionId: number;

        const isRenewal =
            existing != null &&
            existing.status === 'active' &&
            existing.is_trial !== true &&
            Number(existing.plan_id) === Number(plan.id) &&
            existing.expires_at != null;

        if (isRenewal) {
            /* -------- Renewal: extend the existing subscription -- */
            const currentExpiry = new Date(existing.expires_at);
            const base = currentExpiry > now ? currentExpiry : now;
            const newExpiry = new Date(base.getTime() + durationDays * 86_400_000);

            await client.query(
                `UPDATE public.driver_subscriptions
                    SET expires_at  = $1,
                        price_paid  = price_paid + $2,
                        updated_at  = NOW()
                  WHERE id = $3`,
                [newExpiry, expectedGHS, existing.id],
            );

            subscriptionId = Number(existing.id);
        } else {
            /* -------- Fresh subscription ------------------------- */
            if (existing) {
                await client.query(
                    `UPDATE public.driver_subscriptions
                        SET status = 'cancelled',
                            cancelled_at        = NOW(),
                            cancellation_reason = 'replaced by new plan purchase',
                            updated_at          = NOW()
                      WHERE id = $1`,
                    [existing.id],
                );
            }

            const expiresAt = new Date(now.getTime() + durationDays * 86_400_000);

            const created = await client.query(
                `INSERT INTO public.driver_subscriptions
                    (driver_id, plan_id, status, starts_at, expires_at,
                     is_trial, trial_used, price_paid, currency)
                 VALUES ($1, $2, 'active', $3, $4,
                         false, false, $5, $6)
                 RETURNING id`,
                [
                    tx.driver_id,
                    plan.id,
                    now,
                    expiresAt,
                    expectedGHS,
                    plan.currency,
                ],
            );

            subscriptionId = Number(created.rows[0].id);
        }

        /* -------- Mark payment applied --------------------------- */
        await client.query(
            `UPDATE public.subscription_payments
                SET applied         = true,
                    status          = 'success',
                    subscription_id = $1,
                    paystack_verify = $2::jsonb,
                    paid_at         = NOW(),
                    updated_at      = NOW()
              WHERE reference = $3 AND applied = false`,
            [subscriptionId, JSON.stringify(paystackData), reference],
        );

        await client.query('COMMIT');

        const sub = await fetchSubscription(subscriptionId);
        return { applied: true, alreadyApplied: false, subscription: sub };
    } catch (err) {
        try { await client.query('ROLLBACK'); } catch { /* ignore */ }
        console.error(`Failed to apply subscription payment ${reference}:`, err);
        return { applied: false, alreadyApplied: false, subscription: null };
    } finally {
        client.release();
    }
}

/* ===========================================================================
 * Paystack webhook handler (exported — wire it in server.ts, see notes).
 *
 * Only subscription references (prefix "SUB-") are handled here; wallet
 * webhooks are handled by the wallet module. Idempotent: if a verify poll
 * already credited the subscription, this is a no-op.
 * ========================================================================= */
export async function handleSubscriptionWebhook(
    rawBody: Buffer,
    signature: string | undefined,
): Promise<{ status: number; body: any }> {
    if (!verifyWebhookSignature(rawBody, signature)) {
        return { status: 401, body: { success: false, message: 'Invalid signature.' } };
    }

    let payload: any;
    try {
        payload = JSON.parse(rawBody.toString('utf8'));
    } catch {
        return { status: 400, body: { success: false, message: 'Invalid JSON.' } };
    }

    const event = String(payload?.event ?? '');
    const data = payload?.data ?? {};
    const reference = String(data?.reference ?? '');

    if (!reference) {
        return { status: 200, body: { received: true } };
    }

    // Wallet top-ups have their own webhook. Ignore anything else.
    if (!reference.startsWith('SUB-')) {
        return { status: 200, body: { received: true, skipped: true } };
    }

    const txRes = await pool.query(
        `SELECT * FROM public.subscription_payments WHERE reference = $1 LIMIT 1`,
        [reference],
    );

    if (txRes.rows.length === 0) {
        return { status: 200, body: { received: true, unknown: true } };
    }

    if (event === 'charge.success') {
        const result = await applySuccessfulSubscriptionPayment(reference, data);
        return { status: 200, body: { received: true, applied: result.applied } };
    }

    if (event === 'charge.failed') {
        await pool.query(
            `UPDATE public.subscription_payments
                SET status = 'failed',
                    paystack_verify = $1::jsonb,
                    updated_at = NOW()
              WHERE reference = $2 AND applied = false`,
            [JSON.stringify(payload), reference],
        );
    }

    return { status: 200, body: { received: true } };
}

export default router;
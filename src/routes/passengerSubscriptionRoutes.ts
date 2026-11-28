import {
    Router,
    Request,
    Response,
    NextFunction,
} from 'express';

import { randomBytes } from 'crypto';
import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';

const router = Router();

const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY ?? '';
const PAYSTACK_BASE = 'https://api.paystack.co';
const PAYSTACK_TIMEOUT_MS = 20_000;

interface AuthReq extends Request {
    decodedToken?: {
        uid: string;
        email?: string;
    };
}

interface PaystackResponse {
    status?: boolean;
    message?: string;
    data?: Record<string, any>;
}

interface Plan {
    id: number;
    name: string;
    type: string;
    price: string | number;
    currency: string;
    duration_days: number;
}

interface PaymentForVerification {
    reference: string;
    amount: string | number;
    currency: string;
}

/* -------------------------------------------------------------------------- */
/* Authentication                                                            */
/* -------------------------------------------------------------------------- */

const verifyFirebaseToken = async (
    req: AuthReq,
    res: Response,
    next: NextFunction,
): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
        res.status(401).json({
            success: false,
            code: 'AUTH_HEADER_MISSING',
            message: 'Authentication required.',
        });
        return;
    }

    const token = authHeader.substring(7).trim();

    if (!token) {
        res.status(401).json({
            success: false,
            code: 'AUTH_TOKEN_MISSING',
            message: 'Authentication token is missing.',
        });
        return;
    }

    try {
        const decoded = await firebaseAuth.verifyIdToken(token);

        req.decodedToken = {
            uid: decoded.uid,
            email: decoded.email,
        };

        next();
    } catch (error) {
        console.error(
            '[passenger-sub] Firebase token verification failed:',
            (error as Error).message,
        );

        res.status(401).json({
            success: false,
            code: 'AUTH_TOKEN_INVALID',
            message: 'Authentication failed. Please log in again.',
        });
    }
};

function getUid(req: AuthReq): string | null {
    return req.decodedToken?.uid ?? null;
}

/* -------------------------------------------------------------------------- */
/* Paystack helpers                                                           */
/* -------------------------------------------------------------------------- */

async function paystackRequest(
    path: string,
    method: 'GET' | 'POST',
    body?: unknown,
): Promise<{ ok: boolean; status: number; json: PaystackResponse }> {
    if (!PAYSTACK_SECRET) {
        throw new Error('PAYSTACK_SECRET_KEY is not configured.');
    }

    const controller = new AbortController();
    const timeout = setTimeout(
        () => controller.abort(),
        PAYSTACK_TIMEOUT_MS,
    );

    try {
        const response = await fetch(`${PAYSTACK_BASE}${path}`, {
            method,
            headers: {
                Authorization: `Bearer ${PAYSTACK_SECRET}`,
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            ...(method === 'POST'
                ? { body: JSON.stringify(body ?? {}) }
                : {}),
            signal: controller.signal,
        });

        const raw = await response.text();

        let json: PaystackResponse;

        try {
            json = JSON.parse(raw) as PaystackResponse;
        } catch {
            throw new Error(
                `Paystack returned an unreadable response (HTTP ${response.status}).`,
            );
        }

        if (!response.ok || json.status !== true) {
            throw new Error(
                json.message ||
                `Paystack request failed (HTTP ${response.status}).`,
            );
        }

        return {
            ok: response.ok,
            status: response.status,
            json,
        };
    } finally {
        clearTimeout(timeout);
    }
}

async function paystackPost(
    path: string,
    body: unknown,
) {
    return paystackRequest(path, 'POST', body);
}

async function paystackGet(path: string) {
    return paystackRequest(path, 'GET');
}

/* -------------------------------------------------------------------------- */
/* General helpers                                                            */
/* -------------------------------------------------------------------------- */

function normalizeProvider(
    raw: string,
): 'mtn' | 'vod' | 'atl' | null {
    const value = String(raw ?? '')
        .trim()
        .toLowerCase()
        .replace(/[_\s]/g, '-');

    if (['mtn', 'mtn-gh'].includes(value)) {
        return 'mtn';
    }

    if (
        [
            'vod',
            'vod-gh',
            'telecel',
            'telecel-gh',
            'vodafone',
            'vodafone-gh',
        ].includes(value)
    ) {
        return 'vod';
    }

    if (
        [
            'atl',
            'atl-gh',
            'airteltigo',
            'airteltigo-gh',
            'airtel-tigo',
        ].includes(value)
    ) {
        return 'atl';
    }

    return null;
}

function makeReference(uid: string): string {
    const shortUid = uid
        .substring(0, 10)
        .replace(/[^a-zA-Z0-9]/g, '');

    return [
        'TEG-SUB-PASS',
        shortUid,
        Date.now(),
        randomBytes(8).toString('hex'),
    ].join('-');
}

function validReference(reference: string): boolean {
    return /^[A-Za-z0-9_-]{10,100}$/.test(reference);
}

function normalizeCurrency(value: unknown): string {
    return String(value || 'GHS').trim().toUpperCase();
}

function amountInPesewas(value: string | number): number | null {
    const amount = Number(value);

    if (!Number.isFinite(amount) || amount <= 0) {
        return null;
    }

    const pesewas = Math.round(amount * 100);

    if (!Number.isSafeInteger(pesewas) || pesewas <= 0) {
        return null;
    }

    // Reject values with more than two meaningful decimal places.
    if (Math.abs(amount * 100 - pesewas) > 0.000001) {
        return null;
    }

    return pesewas;
}

function validatePaystackTransaction(
    data: Record<string, any>,
    payment: PaymentForVerification,
): boolean {
    const expectedAmount = amountInPesewas(payment.amount);
    const receivedAmount = Number(data.amount);

    return (
        data.status === 'success' &&
        String(data.reference ?? '') === payment.reference &&
        expectedAmount !== null &&
        Number.isSafeInteger(receivedAmount) &&
        receivedAmount === expectedAmount &&
        String(data.currency ?? '').trim().toUpperCase() ===
        normalizeCurrency(payment.currency)
    );
}

function safePaystackMessage(
    data: Record<string, any> | undefined,
    fallback: string,
): string {
    const value =
        data?.display_text ??
        data?.gateway_response ??
        data?.message;

    return typeof value === 'string' && value.trim()
        ? value.trim().slice(0, 500)
        : fallback;
}

/**
 * Maps a free-text Paystack failure message to a stable machine-readable
 * code so the client can pick the right UI (e.g. insufficient funds dialog
 * vs. a generic toast).
 */
function detectPaymentFailureCode(message: string): string | null {
    const lower = (message || '').toLowerCase();

    if (
        lower.includes('insufficient') ||
        lower.includes('no fund') ||
        lower.includes('not enough') ||
        lower.includes('low balance') ||
        lower.includes('balance is low') ||
        lower.includes('not sufficient') ||
        lower.includes('cannot perform this transaction') ||
        lower.includes('declined due to insufficient')
    ) {
        return 'INSUFFICIENT_FUNDS';
    }
    if (
        lower.includes('wrong pin') ||
        lower.includes('invalid pin') ||
        lower.includes('incorrect pin')
    ) {
        return 'WRONG_PIN';
    }
    if (lower.includes('declined')) return 'DECLINED';
    if (lower.includes('timeout') || lower.includes('timed out')) {
        return 'TIMEOUT';
    }
    if (lower.includes('cancel')) return 'CANCELLED';
    return null;
}

async function passengerForUid(uid: string) {
    const result = await pool.query(
        `SELECT id, firebase_uid, full_name, phone, email
         FROM public.passengers
         WHERE firebase_uid = $1
         LIMIT 1`,
        [uid],
    );

    return result.rows[0] ?? null;
}

/**
 * A reference is only usable by the passenger who owns the payment.
 * Return 404 for both missing and foreign references to avoid leaking
 * whether another passenger's reference exists.
 */
async function getPassengerPayment(
    reference: string,
    uid: string,
) {
    const result = await pool.query(
        `SELECT
            psp.id,
            psp.passenger_id,
            psp.plan_id,
            psp.amount,
            psp.currency,
            psp.status,
            psp.applied,
            psp.subscription_id,
            p.firebase_uid
         FROM public.passenger_subscription_payments psp
         INNER JOIN public.passengers p
            ON p.id = psp.passenger_id
         WHERE psp.reference = $1
           AND p.firebase_uid = $2
         LIMIT 1`,
        [reference, uid],
    );

    return result.rows[0] ?? null;
}

/* -------------------------------------------------------------------------- */
/* Subscription activation                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Call this only after an independent Paystack transaction verification
 * has confirmed reference, amount, currency and successful status.
 *
 * It is idempotent: an already-applied payment cannot create a second
 * subscription.
 */
async function activateFromReference(
    reference: string,
): Promise<{
    success: boolean;
    status: string;
    message: string;
}> {
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const paymentResult = await client.query(
            `SELECT
                id,
                passenger_id,
                plan_id,
                amount,
                currency,
                status,
                applied
             FROM public.passenger_subscription_payments
             WHERE reference = $1
             LIMIT 1
             FOR UPDATE`,
            [reference],
        );

        if (paymentResult.rows.length === 0) {
            await client.query('ROLLBACK');

            return {
                success: false,
                status: 'failed',
                message: 'Payment reference not found.',
            };
        }

        const payment = paymentResult.rows[0];

        if (payment.applied === true) {
            await client.query('COMMIT');

            return {
                success: true,
                status: 'success',
                message: 'Subscription already activated.',
            };
        }

        if (payment.status !== 'pending') {
            await client.query('ROLLBACK');

            return {
                success: false,
                status: String(payment.status),
                message: 'Payment is not eligible for activation.',
            };
        }

        // Serialize all subscription changes for this passenger.
        const passengerResult = await client.query(
            `SELECT id
             FROM public.passengers
             WHERE id = $1
             LIMIT 1
             FOR UPDATE`,
            [payment.passenger_id],
        );

        if (passengerResult.rows.length === 0) {
            throw new Error('Passenger record no longer exists.');
        }

        const planResult = await client.query(
            `SELECT id, name, type, price, currency, duration_days
             FROM public.subscription_plans
             WHERE id = $1
             LIMIT 1`,
            [payment.plan_id],
        );

        if (planResult.rows.length === 0) {
            throw new Error('Subscription plan not found.');
        }

        const plan = planResult.rows[0] as Plan;
        const durationDays = Number(plan.duration_days);

        if (
            String(plan.type).toLowerCase() === 'trial' ||
            !Number.isInteger(durationDays) ||
            durationDays <= 0
        ) {
            throw new Error('Invalid paid subscription plan.');
        }

        // The payment amount/currency are the immutable snapshot captured
        // when the charge was initialized. Do not compare against today's
        // plan price: an administrator may have changed the plan since then.
        if (amountInPesewas(payment.amount) === null) {
            throw new Error('Invalid stored payment amount.');
        }

        const existingResult = await client.query(
            `SELECT id, expires_at
             FROM public.passenger_subscriptions
             WHERE passenger_id = $1
               AND status IN ('trial', 'active')
               AND (
                    expires_at IS NULL
                    OR expires_at > NOW()
               )
             ORDER BY expires_at DESC NULLS FIRST, created_at DESC
             LIMIT 1
             FOR UPDATE`,
            [payment.passenger_id],
        );

        const existingExpiry = existingResult.rows[0]?.expires_at;

        // Use the database clock to decide whether the old period is active.
        const clockResult = await client.query(
            `SELECT NOW() AS now`,
        );

        const databaseNow = new Date(clockResult.rows[0].now);
        const expiryDate = existingExpiry
            ? new Date(existingExpiry)
            : null;

        const startAt =
            expiryDate && expiryDate.getTime() > databaseNow.getTime()
                ? expiryDate
                : databaseNow;

        const expiresAt = new Date(
            startAt.getTime() +
            durationDays * 24 * 60 * 60 * 1000,
        );

        // The passenger row lock prevents concurrent trial/paid activations
        // that use this same locking convention.
        await client.query(
            `UPDATE public.passenger_subscriptions
             SET status = 'expired',
                 updated_at = NOW()
             WHERE passenger_id = $1
               AND status IN ('trial', 'active')`,
            [payment.passenger_id],
        );

        const subscriptionResult = await client.query(
            `INSERT INTO public.passenger_subscriptions
                (
                    passenger_id,
                    plan_id,
                    status,
                    starts_at,
                    expires_at,
                    is_trial,
                    trial_used,
                    price_paid,
                    currency
                )
             VALUES ($1, $2, 'active', $3, $4, FALSE, FALSE, $5, $6)
             RETURNING id`,
            [
                payment.passenger_id,
                payment.plan_id,
                startAt.toISOString(),
                expiresAt.toISOString(),
                Number(payment.amount),
                normalizeCurrency(payment.currency),
            ],
        );

        const subscriptionId = subscriptionResult.rows[0].id;

        await client.query(
            `UPDATE public.passenger_subscription_payments
             SET status = 'success',
                 applied = TRUE,
                 paid_at = NOW(),
                 subscription_id = $1,
                 updated_at = NOW()
             WHERE id = $2`,
            [subscriptionId, payment.id],
        );

        await client.query(
            `UPDATE public.paystack_transactions
             SET status = 'success',
                 applied = TRUE,
                 completed_at = NOW(),
                 updated_at = NOW()
             WHERE reference = $1
               AND purpose = 'passenger_subscription'`,
            [reference],
        );

        await client.query('COMMIT');

        return {
            success: true,
            status: 'success',
            message: 'Subscription activated successfully.',
        };
    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch {
            // Preserve the original error.
        }

        console.error(
            '[passenger-sub] activation failed:',
            (error as Error).message,
        );

        return {
            success: false,
            status: 'failed',
            message: 'Subscription activation failed.',
        };
    } finally {
        client.release();
    }
}

/* -------------------------------------------------------------------------- */
/* GET /plans                                                                 */
/* -------------------------------------------------------------------------- */

router.get('/plans', verifyFirebaseToken, async (_req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                id,
                name,
                type,
                price,
                currency,
                duration_days,
                description,
                is_active,
                sort_order
             FROM public.subscription_plans
             WHERE is_active = TRUE
             ORDER BY sort_order, id`,
        );

        return res.status(200).json({
            success: true,
            plans: result.rows,
        });
    } catch (error) {
        console.error(
            '[passenger-sub] /plans:',
            (error as Error).message,
        );

        return res.status(500).json({
            success: false,
            code: 'PLANS_FETCH_FAILED',
            message: 'Unable to retrieve subscription plans.',
        });
    }
});

/* -------------------------------------------------------------------------- */
/* GET /current                                                               */
/* -------------------------------------------------------------------------- */

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

        const usedResult = await pool.query(
            `SELECT EXISTS (
                SELECT 1
                FROM public.passenger_subscriptions
                WHERE passenger_id = $1
                  AND trial_used = TRUE
            ) AS used`,
            [passenger.id],
        );

        const trialUsedEver = usedResult.rows[0].used === true;

        const subscriptionResult = await pool.query(
            `SELECT
                s.id,
                s.plan_id,
                s.status,
                s.starts_at,
                s.expires_at,
                s.is_trial,
                s.trial_used,
                s.price_paid,
                s.currency,
                p.name AS plan_name,
                p.type AS plan_type
             FROM public.passenger_subscriptions s
             LEFT JOIN public.subscription_plans p
                ON p.id = s.plan_id
             WHERE s.passenger_id = $1
             ORDER BY s.created_at DESC, s.id DESC
             LIMIT 1`,
            [passenger.id],
        );

        if (subscriptionResult.rows.length === 0) {
            return res.status(200).json({
                success: true,
                subscription: null,
                trial_used: trialUsedEver,
            });
        }

        const row = subscriptionResult.rows[0];
        let status = String(row.status);

        if (
            (status === 'active' || status === 'trial') &&
            row.expires_at &&
            new Date(row.expires_at).getTime() <= Date.now()
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
    } catch (error) {
        console.error(
            '[passenger-sub] /current:',
            (error as Error).message,
        );

        return res.status(500).json({
            success: false,
            code: 'SUB_CURRENT_FAILED',
            message: 'Unable to retrieve current subscription.',
        });
    }
});

/* -------------------------------------------------------------------------- */
/* POST /trial                                                                */
/* -------------------------------------------------------------------------- */

router.post('/trial', verifyFirebaseToken, async (req: AuthReq, res) => {
    const client = await pool.connect();

    try {
        const uid = getUid(req);

        if (!uid) {
            return res.status(401).json({
                success: false,
                code: 'AUTH_USER_MISSING',
                message: 'Authenticated user not found.',
            });
        }

        await client.query('BEGIN');

        // Lock the passenger row. Trial activation and paid activation both
        // lock this row, serializing subscription changes for this passenger.
        const passengerResult = await client.query(
            `SELECT id
             FROM public.passengers
             WHERE firebase_uid = $1
             LIMIT 1
             FOR UPDATE`,
            [uid],
        );

        if (passengerResult.rows.length === 0) {
            await client.query('ROLLBACK');

            return res.status(404).json({
                success: false,
                code: 'PASSENGER_NOT_FOUND',
                message: 'Passenger not found.',
            });
        }

        const passengerId = passengerResult.rows[0].id;

        const usedResult = await client.query(
            `SELECT 1
             FROM public.passenger_subscriptions
             WHERE passenger_id = $1
               AND trial_used = TRUE
             LIMIT 1`,
            [passengerId],
        );

        if (usedResult.rows.length > 0) {
            await client.query('ROLLBACK');

            return res.status(409).json({
                success: false,
                code: 'TRIAL_ALREADY_USED',
                message: 'Free trial already used.',
            });
        }

        const activeResult = await client.query(
            `SELECT 1
             FROM public.passenger_subscriptions
             WHERE passenger_id = $1
               AND status IN ('trial', 'active')
               AND (
                    expires_at IS NULL
                    OR expires_at > NOW()
               )
             LIMIT 1`,
            [passengerId],
        );

        if (activeResult.rows.length > 0) {
            await client.query('ROLLBACK');

            return res.status(409).json({
                success: false,
                code: 'ALREADY_ACTIVE',
                message: 'A subscription is already active.',
            });
        }

        const planResult = await client.query(
            `SELECT id, duration_days
             FROM public.subscription_plans
             WHERE type = 'trial'
               AND is_active = TRUE
             ORDER BY id
             LIMIT 1`,
        );

        if (planResult.rows.length === 0) {
            await client.query('ROLLBACK');

            return res.status(503).json({
                success: false,
                code: 'NO_TRIAL_PLAN',
                message: 'No trial plan configured.',
            });
        }

        const plan = planResult.rows[0];
        const days = Number(plan.duration_days);

        if (!Number.isInteger(days) || days <= 0) {
            throw new Error('Invalid trial plan duration.');
        }

        const insertResult = await client.query(
            `INSERT INTO public.passenger_subscriptions
                (
                    passenger_id,
                    plan_id,
                    status,
                    starts_at,
                    expires_at,
                    is_trial,
                    trial_used,
                    price_paid,
                    currency
                )
             VALUES (
                $1,
                $2,
                'trial',
                NOW(),
                NOW() + ($3 * INTERVAL '1 day'),
                TRUE,
                TRUE,
                0,
                'GHS'
             )
             RETURNING
                id,
                status,
                starts_at,
                expires_at,
                is_trial,
                trial_used`,
            [passengerId, plan.id, days],
        );

        await client.query('COMMIT');

        return res.status(201).json({
            success: true,
            subscription: insertResult.rows[0],
        });
    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch {
            // Ignore rollback errors.
        }

        console.error(
            '[passenger-sub] /trial:',
            (error as Error).message,
        );

        return res.status(500).json({
            success: false,
            code: 'TRIAL_FAILED',
            message: 'Unable to activate free trial.',
        });
    } finally {
        client.release();
    }
});

/* -------------------------------------------------------------------------- */
/* POST /initialize                                                           */
/* -------------------------------------------------------------------------- */

router.post('/initialize', verifyFirebaseToken, async (req: AuthReq, res) => {
    let reference: string | null = null;
    let paymentCreated = false;

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
                message: 'Payment service is not configured.',
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
        const provider = normalizeProvider(
            String(req.body?.provider ?? ''),
        );

        const phone = String(
            req.body?.phone ?? passenger.phone ?? '',
        ).trim();

        const phoneDigits = phone.replace(/\D/g, '');

        if (!Number.isSafeInteger(planId) || planId <= 0) {
            return res.status(400).json({
                success: false,
                code: 'INVALID_PLAN',
                message: 'A valid plan_id is required.',
            });
        }

        if (!provider) {
            return res.status(400).json({
                success: false,
                code: 'INVALID_PROVIDER',
                message: 'Unsupported mobile money provider.',
            });
        }

        if (phoneDigits.length < 10 || phoneDigits.length > 15) {
            return res.status(400).json({
                success: false,
                code: 'INVALID_PHONE',
                message: 'Please provide a valid mobile money number.',
            });
        }

        const planResult = await pool.query(
            `SELECT
                id,
                name,
                type,
                price,
                currency,
                duration_days
             FROM public.subscription_plans
             WHERE id = $1
               AND is_active = TRUE
             LIMIT 1`,
            [planId],
        );

        if (planResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                code: 'PLAN_NOT_FOUND',
                message: 'Subscription plan not found.',
            });
        }

        const plan = planResult.rows[0] as Plan;

        if (String(plan.type).toLowerCase() === 'trial') {
            return res.status(400).json({
                success: false,
                code: 'INVALID_PAID_PLAN',
                message: 'Free trial plans cannot be purchased.',
            });
        }

        const currency = normalizeCurrency(plan.currency);

        if (currency !== 'GHS') {
            return res.status(400).json({
                success: false,
                code: 'UNSUPPORTED_CURRENCY',
                message: 'Mobile Money subscriptions currently support GHS only.',
            });
        }

        const amount = Number(plan.price);
        const amountPesewas = amountInPesewas(amount);

        if (amountPesewas === null) {
            return res.status(400).json({
                success: false,
                code: 'INVALID_PLAN_PRICE',
                message: 'Subscription plan has an invalid price.',
            });
        }

        const email =
            String(passenger.email ?? '').trim() ||
            `passenger_${passenger.id}@tegaara.app`;

        reference = makeReference(uid);

        // Create both records atomically before contacting Paystack.
        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            await client.query(
                `INSERT INTO public.passenger_subscription_payments
                    (
                        passenger_id,
                        plan_id,
                        reference,
                        amount,
                        currency,
                        status,
                        provider,
                        channel,
                        phone
                    )
                 VALUES ($1, $2, $3, $4, $5, 'pending',
                         'paystack', 'mobile_money', $6)`,
                [
                    passenger.id,
                    planId,
                    reference,
                    amount,
                    currency,
                    phone,
                ],
            );

            await client.query(
                `INSERT INTO public.paystack_transactions
                    (
                        reference,
                        user_firebase_uid,
                        purpose,
                        amount,
                        status,
                        channel,
                        provider,
                        phone,
                        passenger_id
                    )
                 VALUES (
                    $1, $2, 'passenger_subscription', $3,
                    'pending', 'mobile_money', $4, $5, $6
                 )`,
                [
                    reference,
                    uid,
                    amount,
                    provider,
                    phone,
                    passenger.id,
                ],
            );

            await client.query('COMMIT');
            paymentCreated = true;
        } catch (error) {
            try {
                await client.query('ROLLBACK');
            } catch {
                // Ignore rollback errors.
            }
            throw error;
        } finally {
            client.release();
        }

        const charge = await paystackPost('/charge', {
            email,
            amount: amountPesewas,
            currency,
            reference,
            mobile_money: {
                phone,
                provider,
            },
        });

        const chargeData = charge.json.data ?? {};
        const chargeStatus = String(
            chargeData.status ?? '',
        ).toLowerCase();

        const chargeMessage = safePaystackMessage(
            chargeData,
            'Payment request submitted.',
        );

        await pool.query(
            `UPDATE public.passenger_subscription_payments
             SET paystack_init = $1::jsonb,
                 updated_at = NOW()
             WHERE reference = $2`,
            [JSON.stringify(charge.json), reference],
        );

        await pool.query(
            `UPDATE public.paystack_transactions
             SET paystack_init = $1::jsonb,
                 updated_at = NOW()
             WHERE reference = $2`,
            [JSON.stringify(charge.json), reference],
        );

        if (chargeStatus === 'failed') {
            await pool.query(
                `UPDATE public.passenger_subscription_payments
                 SET status = 'failed',
                     failure_reason = $1,
                     updated_at = NOW()
                 WHERE reference = $2
                   AND status = 'pending'`,
                [chargeMessage, reference],
            );

            await pool.query(
                `UPDATE public.paystack_transactions
                 SET status = 'failed',
                     updated_at = NOW()
                 WHERE reference = $1`,
                [reference],
            );

            return res.status(400).json({
                success: false,
                code:
                    detectPaymentFailureCode(chargeMessage) ??
                    'CHARGE_FAILED',
                reference,
                message: chargeMessage,
            });
        }

        if (chargeStatus === 'success') {
            // Do not trust the charge response alone. Verify independently.
            const verification = await paystackGet(
                `/transaction/verify/${encodeURIComponent(reference)}`,
            );

            const verifiedData = verification.json.data ?? {};

            await pool.query(
                `UPDATE public.passenger_subscription_payments
                 SET paystack_verify = $1::jsonb,
                     updated_at = NOW()
                 WHERE reference = $2`,
                [JSON.stringify(verification.json), reference],
            );

            await pool.query(
                `UPDATE public.paystack_transactions
                 SET paystack_verify = $1::jsonb,
                     updated_at = NOW()
                 WHERE reference = $2`,
                [JSON.stringify(verification.json), reference],
            );

            if (
                validatePaystackTransaction(verifiedData, {
                    reference,
                    amount,
                    currency,
                })
            ) {
                const activated = await activateFromReference(reference);

                return res.status(200).json({
                    success: activated.success,
                    reference,
                    needs_otp: false,
                    status: activated.status,
                    message: activated.message,
                });
            }

            return res.status(200).json({
                success: true,
                reference,
                needs_otp: false,
                status: 'pending',
                message: 'Payment is awaiting final verification.',
            });
        }

        if (chargeStatus === 'send_otp') {
            return res.status(200).json({
                success: true,
                reference,
                needs_otp: true,
                status: 'pending',
                message: chargeMessage || 'Enter the OTP sent to your phone.',
            });
        }

        if (
            chargeStatus === 'pay_offline' ||
            chargeStatus === 'pending' ||
            chargeStatus === ''
        ) {
            return res.status(200).json({
                success: true,
                reference,
                needs_otp: false,
                status: 'pending',
                message: chargeMessage ||
                    'Authorize the payment on your phone.',
            });
        }

        // Unknown statuses are left pending for /verify to reconcile.
        return res.status(200).json({
            success: true,
            reference,
            needs_otp: false,
            status: 'pending',
            message: chargeMessage,
        });
    } catch (error) {
        console.error(
            '[passenger-sub] /initialize:',
            (error as Error).message,
        );

        // If Paystack timed out after receiving the charge, the charge may
        // still complete. Return the reference so the client can poll /verify.
        if (paymentCreated && reference) {
            return res.status(202).json({
                success: true,
                reference,
                needs_otp: false,
                status: 'pending',
                message: 'Payment status is being checked. Please do not start another payment yet.',
            });
        }

        return res.status(502).json({
            success: false,
            code: 'INITIALIZE_FAILED',
            message: 'Unable to initialize payment. Please try again.',
        });
    }
});

/* -------------------------------------------------------------------------- */
/* POST /submit-otp                                                           */
/* -------------------------------------------------------------------------- */

router.post('/submit-otp', verifyFirebaseToken, async (req: AuthReq, res) => {
    const uid = getUid(req);

    if (!uid) {
        return res.status(401).json({
            success: false,
            code: 'AUTH_USER_MISSING',
            message: 'Authenticated user not found.',
        });
    }

    const reference = String(req.body?.reference ?? '').trim();
    const otp = String(req.body?.otp ?? '').trim();

    if (
        !validReference(reference) ||
        !/^\d{4,8}$/.test(otp)
    ) {
        return res.status(400).json({
            success: false,
            code: 'INVALID_FIELDS',
            message: 'A valid payment reference and OTP are required.',
        });
    }

    if (!PAYSTACK_SECRET) {
        return res.status(503).json({
            success: false,
            code: 'PAYSTACK_NOT_CONFIGURED',
            message: 'Payment service is not configured.',
        });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // Lock this payment while submitting the OTP to prevent concurrent
        // OTP submissions for the same reference.
        const paymentResult = await client.query(
            `SELECT
                psp.id,
                psp.passenger_id,
                psp.amount,
                psp.currency,
                psp.status,
                psp.applied,
                p.firebase_uid
             FROM public.passenger_subscription_payments psp
             INNER JOIN public.passengers p
                ON p.id = psp.passenger_id
             WHERE psp.reference = $1
               AND p.firebase_uid = $2
             LIMIT 1
             FOR UPDATE OF psp`,
            [reference, uid],
        );

        if (paymentResult.rows.length === 0) {
            await client.query('ROLLBACK');

            return res.status(404).json({
                success: false,
                code: 'TX_NOT_FOUND',
                message: 'Payment not found.',
            });
        }

        const payment = paymentResult.rows[0];

        if (payment.applied || payment.status === 'success') {
            await client.query('COMMIT');

            return res.status(200).json({
                success: true,
                status: 'success',
                message: 'Subscription already activated.',
            });
        }

        if (payment.status !== 'pending') {
            await client.query('ROLLBACK');

            return res.status(409).json({
                success: false,
                code: 'PAYMENT_NOT_PENDING',
                message: 'This payment cannot accept an OTP.',
            });
        }

        const submit = await paystackPost(
            '/charge/submit_otp',
            { otp, reference },
        );

        const submitData = submit.json.data ?? {};
        const submitStatus = String(
            submitData.status ?? '',
        ).toLowerCase();
        const submitMessage = safePaystackMessage(
            submitData,
            'OTP verification failed.',
        );

        // Never persist the OTP. Only persist Paystack's response.
        await client.query(
            `UPDATE public.passenger_subscription_payments
             SET paystack_verify = $1::jsonb,
                 updated_at = NOW()
             WHERE id = $2`,
            [JSON.stringify(submit.json), payment.id],
        );

        await client.query(
            `UPDATE public.paystack_transactions
             SET paystack_verify = $1::jsonb,
                 updated_at = NOW()
             WHERE reference = $2`,
            [JSON.stringify(submit.json), reference],
        );

        await client.query('COMMIT');

        if (
            submitStatus === 'send_otp' ||
            submitStatus === 'pending' ||
            submitStatus === ''
        ) {
            return res.status(200).json({
                success: false,
                status: 'pending',
                code: 'OTP_REQUIRED',
                message: safePaystackMessage(
                    submitData,
                    'OTP verification is still pending. Check the code and try again.',
                ),
            });
        }

        if (submitStatus === 'failed') {
            await pool.query(
                `UPDATE public.passenger_subscription_payments
                 SET status = 'failed',
                     failure_reason = $1,
                     updated_at = NOW()
                 WHERE reference = $2
                   AND status = 'pending'`,
                [submitMessage, reference],
            );

            await pool.query(
                `UPDATE public.paystack_transactions
                 SET status = 'failed',
                     updated_at = NOW()
                 WHERE reference = $1`,
                [reference],
            );

            return res.status(400).json({
                success: false,
                status: 'failed',
                code:
                    detectPaymentFailureCode(submitMessage) ??
                    'OTP_FAILED',
                message: submitMessage,
            });
        }

        // Regardless of the OTP response, independently verify the actual
        // transaction with Paystack before activating the subscription.
        const verification = await paystackGet(
            `/transaction/verify/${encodeURIComponent(reference)}`,
        );

        const verifiedData = verification.json.data ?? {};

        await pool.query(
            `UPDATE public.passenger_subscription_payments
             SET paystack_verify = $1::jsonb,
                 updated_at = NOW()
             WHERE reference = $2`,
            [JSON.stringify(verification.json), reference],
        );

        await pool.query(
            `UPDATE public.paystack_transactions
             SET paystack_verify = $1::jsonb,
                 updated_at = NOW()
             WHERE reference = $2`,
            [JSON.stringify(verification.json), reference],
        );

        const valid = validatePaystackTransaction(
            verifiedData,
            {
                reference,
                amount: payment.amount,
                currency: payment.currency,
            },
        );

        if (!valid) {
            return res.status(200).json({
                success: false,
                status: 'pending',
                message: 'Payment is awaiting final verification.',
            });
        }

        const activated = await activateFromReference(reference);

        return res.status(200).json({
            success: activated.success,
            status: activated.status,
            message: activated.message,
        });
    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch {
            // The transaction may already have committed.
        }

        console.error(
            '[passenger-sub] /submit-otp:',
            (error as Error).message,
        );

        return res.status(502).json({
            success: false,
            code: 'OTP_SUBMIT_FAILED',
            message: 'Unable to process OTP with the payment provider.',
        });
    } finally {
        client.release();
    }
});

/* -------------------------------------------------------------------------- */
/* POST /verify/:reference                                                    */
/* -------------------------------------------------------------------------- */

router.post(
    '/verify/:reference',
    verifyFirebaseToken,
    async (req: AuthReq, res) => {
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
                    message: 'Payment service is not configured.',
                });
            }

            const reference = String(
                req.params.reference ?? '',
            ).trim();

            if (!validReference(reference)) {
                return res.status(400).json({
                    success: false,
                    code: 'INVALID_REFERENCE',
                    message: 'Invalid payment reference.',
                });
            }

            // Ownership check happens before calling Paystack.
            const payment = await getPassengerPayment(reference, uid);

            if (!payment) {
                return res.status(404).json({
                    success: false,
                    code: 'TX_NOT_FOUND',
                    message: 'Payment not found.',
                });
            }

            if (payment.applied) {
                return res.status(200).json({
                    success: true,
                    status: 'success',
                    message: 'Subscription already activated.',
                });
            }

            if (payment.status !== 'pending') {
                return res.status(200).json({
                    success: false,
                    status: payment.status,
                    message: 'Payment is no longer pending.',
                });
            }

            const verification = await paystackGet(
                `/transaction/verify/${encodeURIComponent(reference)}`,
            );

            const data = verification.json.data ?? {};
            const status = String(
                data.status ?? 'pending',
            ).toLowerCase();

            // Capture the real provider message so the client can react
            // to specifics (e.g. "Insufficient funds").
            const message = safePaystackMessage(
                data,
                'Payment is still processing.',
            );

            await pool.query(
                `UPDATE public.passenger_subscription_payments
                 SET paystack_verify = $1::jsonb,
                     updated_at = NOW()
                 WHERE reference = $2`,
                [JSON.stringify(verification.json), reference],
            );

            await pool.query(
                `UPDATE public.paystack_transactions
                 SET paystack_verify = $1::jsonb,
                     updated_at = NOW()
                 WHERE reference = $2`,
                [JSON.stringify(verification.json), reference],
            );

            if (status === 'success') {
                const valid = validatePaystackTransaction(
                    data,
                    {
                        reference,
                        amount: payment.amount,
                        currency: payment.currency,
                    },
                );

                if (!valid) {
                    console.error(
                        '[passenger-sub] Paystack verification mismatch:',
                        reference,
                    );

                    return res.status(409).json({
                        success: false,
                        code: 'PAYMENT_VALIDATION_FAILED',
                        status: 'pending',
                        message: 'Payment details could not be verified.',
                    });
                }

                const activated = await activateFromReference(reference);

                return res.status(200).json({
                    success: activated.success,
                    status: activated.status,
                    message: activated.message,
                });
            }

            if (
                status === 'failed' ||
                status === 'reversed' ||
                status === 'cancelled'
            ) {
                // The passenger payment table's CHECK constraint does not
                // permit "cancelled"; map cancellation to "failed".
                const databaseStatus =
                    status === 'cancelled' ? 'failed' : status;

                await pool.query(
                    `UPDATE public.passenger_subscription_payments
                     SET status = $1,
                         failure_reason = $2,
                         updated_at = NOW()
                     WHERE reference = $3
                       AND status = 'pending'`,
                    [databaseStatus, message, reference],
                );

                await pool.query(
                    `UPDATE public.paystack_transactions
                     SET status = $1,
                         updated_at = NOW()
                     WHERE reference = $2`,
                    [databaseStatus, reference],
                );

                // Return the REAL reason (e.g. "Insufficient funds") plus a
                // machine-readable code so the client can show the right UI.
                return res.status(200).json({
                    success: false,
                    status,
                    code:
                        detectPaymentFailureCode(message) ??
                        'PAYMENT_FAILED',
                    message:
                        message && message !== 'Payment is still processing.'
                            ? message
                            : 'Payment was not completed.',
                });
            }

            return res.status(200).json({
                success: false,
                status: 'pending',
                message,
            });
        } catch (error) {
            console.error(
                '[passenger-sub] /verify:',
                (error as Error).message,
            );

            return res.status(502).json({
                success: false,
                code: 'VERIFY_FAILED',
                message: 'Unable to verify payment at this time.',
            });
        }
    },
);

export default router;
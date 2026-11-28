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

interface PaystackResult {
    ok: boolean;
    httpStatus: number;
    json: PaystackResponse;
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
/* AUTHENTICATION                                                             */
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
            '[passenger-sub] Firebase authentication failed:',
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
/* PAYSTACK HELPERS                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Important:
 * Do not throw just because Paystack's JSON status is false.
 *
 * We need the response payload to inspect its message, code and data.
 * Otherwise, Mobile Money failures can be converted into generic errors
 * before the route has a chance to handle them.
 */
async function paystackRequest(
    path: string,
    method: 'GET' | 'POST',
    body?: unknown,
): Promise<PaystackResult> {
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

        return {
            ok: response.ok && json.status === true,
            httpStatus: response.status,
            json,
        };
    } finally {
        clearTimeout(timeout);
    }
}

async function paystackPost(
    path: string,
    body: unknown,
): Promise<PaystackResult> {
    return paystackRequest(path, 'POST', body);
}

async function paystackGet(
    path: string,
): Promise<PaystackResult> {
    return paystackRequest(path, 'GET');
}

function getPaystackData(
    response: PaystackResponse,
): Record<string, any> {
    return response.data ?? {};
}

function getPaystackMessage(
    response: PaystackResponse,
    fallback: string,
): string {
    const data = getPaystackData(response);

    const candidates = [
        data.display_text,
        data.gateway_response,
        data.message,
        response.message,
    ];

    for (const candidate of candidates) {
        if (
            typeof candidate === 'string' &&
            candidate.trim().length > 0
        ) {
            return candidate.trim().slice(0, 500);
        }
    }

    return fallback;
}

/* -------------------------------------------------------------------------- */
/* GENERAL HELPERS                                                            */
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

function amountInPesewas(
    value: string | number,
): number | null {
    const amount = Number(value);

    if (!Number.isFinite(amount) || amount <= 0) {
        return null;
    }

    const pesewas = Math.round(amount * 100);

    if (!Number.isSafeInteger(pesewas) || pesewas <= 0) {
        return null;
    }

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

function detectPaymentFailureCode(
    message: string,
): string | null {
    const lower = String(message ?? '').toLowerCase();

    if (
        lower.includes('low_balance_or_payee_limit_reached_or_not_allowed') ||
        lower.includes('insufficient_funds') ||
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

    if (lower.includes('declined')) {
        return 'DECLINED';
    }

    if (
        lower.includes('timeout') ||
        lower.includes('timed out')
    ) {
        return 'TIMEOUT';
    }

    if (lower.includes('cancel')) {
        return 'CANCELLED';
    }

    return null;
}

function resolvePaystackFailureCode(
    data: Record<string, any> | undefined,
    message: string,
): string | null {
    const rawCode = String(data?.code ?? '')
        .trim()
        .toLowerCase();

    if (
        rawCode === 'low_balance_or_payee_limit_reached_or_not_allowed' ||
        rawCode === 'insufficient_funds'
    ) {
        return 'INSUFFICIENT_FUNDS';
    }

    return detectPaymentFailureCode(
        `${rawCode} ${message}`,
    );
}

function friendlyInsufficientFundsMessage(
    data: Record<string, any> | undefined,
    fallback: string,
): string {
    const rawCode = String(data?.code ?? '').toLowerCase();
    const rawMessage = String(fallback ?? '').toLowerCase();

    if (
        rawCode.includes('low_balance_or_payee_limit_reached_or_not_allowed') ||
        rawMessage.includes('low_balance_or_payee_limit_reached_or_not_allowed') ||
        rawMessage.includes('insufficient_funds')
    ) {
        return (
            'Your Mobile Money wallet does not have enough funds, or your ' +
            'payee limit has been reached. Please top up or check your ' +
            'transaction limits and try again.'
        );
    }

    return fallback;
}

function paymentFailureResponse(
    response: PaystackResponse,
    fallback: string,
): {
    code: string;
    message: string;
} {
    const data = getPaystackData(response);
    const message = getPaystackMessage(response, fallback);
    const code = resolvePaystackFailureCode(data, message);

    return {
        code: code ?? 'CHARGE_FAILED',
        message: code === 'INSUFFICIENT_FUNDS'
            ? friendlyInsufficientFundsMessage(data, message)
            : message,
    };
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
/* PAYMENT FAILURE DATABASE UPDATE                                            */
/* -------------------------------------------------------------------------- */

async function markPaymentFailed(
    reference: string,
    message: string,
): Promise<void> {
    await pool.query(
        `UPDATE public.passenger_subscription_payments
         SET status = 'failed',
             failure_reason = $1,
             updated_at = NOW()
         WHERE reference = $2
           AND status = 'pending'`,
        [message, reference],
    );

    await pool.query(
        `UPDATE public.paystack_transactions
         SET status = 'failed',
             updated_at = NOW()
         WHERE reference = $1
           AND purpose = 'passenger_subscription'`,
        [reference],
    );
}

/* -------------------------------------------------------------------------- */
/* SUBSCRIPTION ACTIVATION                                                    */
/* -------------------------------------------------------------------------- */

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

        // These names match your current Flutter service.
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

        // Create the payment records before contacting Paystack.
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
                 VALUES (
                    $1, $2, $3, $4, $5,
                    'pending', 'paystack', 'mobile_money', $6
                 )`,
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

        console.log('[passenger-sub] Initializing payment:', {
            reference,
            planId,
            provider,
            currency,
            amountPesewas,
        });

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

        const chargeData = getPaystackData(charge.json);
        const chargeStatus = String(
            chargeData.status ?? '',
        ).toLowerCase();

        const chargeMessage = getPaystackMessage(
            charge.json,
            'Payment request submitted.',
        );

        // Save the complete Paystack response for debugging and reconciliation.
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

        /*
         * Paystack API-level rejection:
         * The request itself was rejected. Do not treat it as a successful
         * pending charge.
         */
        if (!charge.ok) {
            const failure = paymentFailureResponse(
                charge.json,
                'Paystack could not initialize this payment.',
            );

            await markPaymentFailed(reference, failure.message);

            return res.status(400).json({
                success: false,
                code: failure.code,
                reference,
                status: 'failed',
                needs_otp: false,
                message: failure.message,
            });
        }

        /*
         * Paystack accepted the request but the actual charge failed.
         */
        if (chargeStatus === 'failed') {
            const failure = paymentFailureResponse(
                charge.json,
                chargeMessage,
            );

            await markPaymentFailed(reference, failure.message);

            return res.status(400).json({
                success: false,
                code: failure.code,
                reference,
                status: 'failed',
                needs_otp: false,
                message: failure.message,
            });
        }

        /*
         * Charge reports success.
         * Independently verify the transaction before activating.
         */
        if (chargeStatus === 'success') {
            const verification = await paystackGet(
                `/transaction/verify/${encodeURIComponent(reference)}`,
            );

            const verifiedData = getPaystackData(verification.json);

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
                verification.ok &&
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

        /*
         * Paystack requires OTP.
         */
        if (chargeStatus === 'send_otp') {
            return res.status(200).json({
                success: true,
                reference,
                needs_otp: true,
                status: 'pending',
                message: chargeMessage ||
                    'Enter the OTP sent to your phone.',
            });
        }

        /*
         * Customer must authorize the payment on their phone.
         */
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

        // Unknown provider statuses must be reconciled by verification.
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

        /*
         * A timeout may occur after Paystack has received the charge.
         * Do not mark that payment failed or create a new reference.
         */
        if (paymentCreated && reference) {
            return res.status(202).json({
                success: true,
                reference,
                needs_otp: false,
                status: 'pending',
                message:
                    'Payment status is being checked. Please do not start another payment yet.',
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

    try {
        const payment = await getPassengerPayment(reference, uid);

        if (!payment) {
            return res.status(404).json({
                success: false,
                code: 'TX_NOT_FOUND',
                message: 'Payment not found.',
            });
        }

        if (payment.applied || payment.status === 'success') {
            return res.status(200).json({
                success: true,
                status: 'success',
                message: 'Subscription already activated.',
            });
        }

        if (payment.status !== 'pending') {
            return res.status(409).json({
                success: false,
                code: 'PAYMENT_NOT_PENDING',
                status: String(payment.status),
                message: 'This payment cannot accept an OTP.',
            });
        }

        const submit = await paystackPost(
            '/charge/submit_otp',
            { otp, reference },
        );

        const submitData = getPaystackData(submit.json);
        const submitStatus = String(
            submitData.status ?? '',
        ).toLowerCase();

        const submitMessage = getPaystackMessage(
            submit.json,
            'OTP verification failed.',
        );

        // Persist the provider response. Never persist the OTP itself.
        await pool.query(
            `UPDATE public.passenger_subscription_payments
             SET paystack_verify = $1::jsonb,
                 updated_at = NOW()
             WHERE reference = $2`,
            [JSON.stringify(submit.json), reference],
        );

        await pool.query(
            `UPDATE public.paystack_transactions
             SET paystack_verify = $1::jsonb,
                 updated_at = NOW()
             WHERE reference = $1`,
            [JSON.stringify(submit.json), reference],
        );

        if (!submit.ok) {
            const failure = paymentFailureResponse(
                submit.json,
                'OTP verification failed.',
            );

            /*
             * A failed OTP attempt does not always mean the underlying
             * payment is permanently failed. Keep it pending for retry
             * unless Paystack explicitly reports a failed charge.
             */
            if (submitStatus === 'failed') {
                await markPaymentFailed(reference, failure.message);

                return res.status(400).json({
                    success: false,
                    status: 'failed',
                    code: failure.code,
                    message: failure.message,
                });
            }

            return res.status(400).json({
                success: false,
                status: 'pending',
                code: failure.code,
                message: failure.message,
            });
        }

        if (
            submitStatus === 'send_otp' ||
            submitStatus === 'pending' ||
            submitStatus === ''
        ) {
            return res.status(200).json({
                success: false,
                status: 'pending',
                code: 'OTP_REQUIRED',
                message: submitMessage ||
                    'OTP verification is still pending. Check the code and try again.',
            });
        }

        if (submitStatus === 'failed') {
            const failure = paymentFailureResponse(
                submit.json,
                submitMessage,
            );

            await markPaymentFailed(reference, failure.message);

            return res.status(400).json({
                success: false,
                status: 'failed',
                code: failure.code,
                message: failure.message,
            });
        }

        /*
         * OTP submission is not proof of payment.
         * Verify the actual transaction with Paystack.
         */
        const verification = await paystackGet(
            `/transaction/verify/${encodeURIComponent(reference)}`,
        );

        const verifiedData = getPaystackData(verification.json);

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
             WHERE reference = $1`,
            [JSON.stringify(verification.json), reference],
        );

        const valid =
            verification.ok &&
            validatePaystackTransaction(verifiedData, {
                reference,
                amount: payment.amount,
                currency: payment.currency,
            });

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
        console.error(
            '[passenger-sub] /submit-otp:',
            (error as Error).message,
        );

        return res.status(502).json({
            success: false,
            code: 'OTP_SUBMIT_FAILED',
            message: 'Unable to process OTP with the payment provider.',
        });
    }
});

/* -------------------------------------------------------------------------- */
/* GET /verify/:reference                                                     */
/* -------------------------------------------------------------------------- */

/**
 * IMPORTANT:
 * This is GET, matching your Flutter ApiConfig:
 * passengerSubscriptionVerify(reference)
 */
router.get(
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

            // Check ownership before contacting Paystack.
            const payment = await getPassengerPayment(reference, uid);

            if (!payment) {
                return res.status(404).json({
                    success: false,
                    code: 'TX_NOT_FOUND',
                    message: 'Payment not found.',
                });
            }

            if (payment.applied || payment.status === 'success') {
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

            const data = getPaystackData(verification.json);

            const status = String(
                data.status ?? '',
            ).toLowerCase();

            const message = getPaystackMessage(
                verification.json,
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

            /*
             * Paystack verification API itself rejected the request.
             * This is not proof that the customer payment failed.
             */
            if (!verification.ok) {
                return res.status(200).json({
                    success: true,
                    status: 'pending',
                    message: 'Payment verification is temporarily unavailable. Please wait.',
                });
            }

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
                status === 'send_otp' ||
                status === 'otp'
            ) {
                return res.status(200).json({
                    success: true,
                    status: 'send_otp',
                    needs_otp: true,
                    message: message ||
                        'Enter the OTP sent to your phone.',
                });
            }

            if (
                status === 'failed' ||
                status === 'reversed'
            ) {
                const failure = paymentFailureResponse(
                    verification.json,
                    message,
                );

                await markPaymentFailed(
                    reference,
                    failure.message,
                );

                return res.status(200).json({
                    success: false,
                    status: 'failed',
                    code: failure.code === 'CHARGE_FAILED'
                        ? 'VERIFY_FAILED'
                        : failure.code,
                    message: failure.message,
                });
            }

            return res.status(200).json({
                success: true,
                status: 'pending',
                message: message || 'Payment is still processing.',
            });
        } catch (error) {
            console.error(
                '[passenger-sub] /verify:',
                (error as Error).message,
            );

            return res.status(502).json({
                success: false,
                code: 'VERIFY_FAILED',
                message: 'Unable to verify payment status.',
            });
        }
    },
);

export default router;
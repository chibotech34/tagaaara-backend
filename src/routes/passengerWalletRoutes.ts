import { Router, Response } from 'express';
import pool from '../config/database';
import { firebaseMessaging } from '../config/firebase';
import {
    verifyFirebaseToken,
    AuthenticatedRequest,
} from '../middleware/firebaseAdmin';
import {
    initializeMobileMoneyCharge,
    verifyTransaction,
    generateReference,
    fromPesewas,
    submitOtp,
    type PaystackProvider,
} from '../services/paystackService';

const router = Router();
const FLAT_COMMISSION = 2.0;

type PaymentStatus =
    | 'success'
    | 'pending'
    | 'pay_offline'
    | 'send_otp'
    | 'failed'
    | 'reversed';

/* ==========================================================================
 * HELPERS
 * ========================================================================== */

function getAuthenticatedUid(req: AuthenticatedRequest): string | null {
    const uid = req.decodedToken?.uid;
    return typeof uid === 'string' && uid.trim() ? uid.trim() : null;
}

function normaliseStatus(value: unknown): PaymentStatus {
    const status = String(value ?? 'pending').toLowerCase();
    const allowed: PaymentStatus[] = [
        'success',
        'pending',
        'pay_offline',
        'send_otp',
        'failed',
        'reversed',
    ];
    return allowed.includes(status as PaymentStatus)
        ? (status as PaymentStatus)
        : 'pending';
}

function statusMessage(status: PaymentStatus): string {
    switch (status) {
        case 'success':
            return 'Payment confirmed.';
        case 'pay_offline':
            return 'Check your phone and follow the Mobile Money approval instructions.';
        case 'send_otp':
            return 'Enter the verification code requested by the payment provider.';
        case 'failed':
        case 'reversed':
            return 'The payment was not successful. Check your Mobile Money account before trying again.';
        default:
            return 'Your payment is processing. Please wait for confirmation before trying again.';
    }
}

function validProvider(value: unknown): value is PaystackProvider {
    return ['mtn', 'vod', 'atl'].includes(
        String(value ?? '').trim().toLowerCase(),
    );
}

function amountToGHS(value: unknown): number {
    const amount = Number(value);
    return Number.isFinite(amount) ? Math.round(amount * 100) / 100 : 0;
}

/* ==========================================================================
 * PASSENGER LOOKUP / CREATE
 *
 * Schema (public.passengers):
 *   firebase_uid        varchar(255) NOT NULL UNIQUE
 *   full_name           varchar(255) NOT NULL
 *   phone               varchar(50)  NOT NULL
 *   email               varchar(255)
 *   mobile_money_number varchar(50)
 * ========================================================================== */

type PassengerRow = {
    id: number;
    full_name: string | null;
    email: string | null;
    phone: string | null;
    mobile_money_number: string | null;
};

async function findPassenger(uid: string): Promise<PassengerRow | null> {
    const result = await pool.query<PassengerRow>(
        `SELECT id, full_name, email, phone, mobile_money_number
         FROM public.passengers
         WHERE firebase_uid = $1::varchar
         LIMIT 1`,
        [uid],
    );
    return result.rows[0] ?? null;
}

async function findOrCreatePassenger(
    uid: string,
    fallback?: {
        full_name?: string;
        email?: string;
        phone?: string;
    },
): Promise<PassengerRow> {
    const existing = await findPassenger(uid);
    if (existing) return existing;

    // Both full_name and phone are NOT NULL, so we seed sensible defaults.
    const fullName = (fallback?.full_name ?? '').trim() || 'Passenger';
    const phone =
        (fallback?.phone ?? '').trim() || `pending-${uid.slice(0, 12)}`;
    const email = (fallback?.email ?? '').trim() || null;
    const momo = (fallback?.phone ?? '').trim() || null;

    try {
        const inserted = await pool.query<PassengerRow>(
            `INSERT INTO public.passengers (
                firebase_uid, full_name, phone, email, mobile_money_number
             )
             VALUES ($1::varchar, $2::varchar, $3::varchar, $4::varchar, $5::varchar)
             RETURNING id, full_name, email, phone, mobile_money_number`,
            [uid, fullName, phone, email, momo],
        );
        return inserted.rows[0];
    } catch (error: any) {
        // Race: another request created the row between our SELECT and INSERT.
        if (error?.code === '23505') {
            const retry = await findPassenger(uid);
            if (retry) return retry;
        }
        throw error;
    }
}

/* ==========================================================================
 * WALLET LOOKUP / CREATE
 *
 * Schema (public.wallets):
 *   id            bigint
 *   passenger_id  integer  ← partial unique idx_wallets_passenger_id
 *   driver_id     bigint   ← CHECK: exactly one of passenger_id/driver_id
 *   balance, pending_balance, total_spent  numeric(10,2) NOT NULL
 *   last_transaction_at, created_at, updated_at  timestamptz
 *
 * IMPORTANT: idx_wallets_passenger_id is a PARTIAL unique index
 * (WHERE passenger_id IS NOT NULL), so `ON CONFLICT (passenger_id)` is
 * rejected with 42P10. We use SELECT → INSERT → catch 23505 instead.
 * ========================================================================== */

type WalletRow = {
    id: number;
    passenger_id: number;
    balance: string | number;
    pending_balance: string | number;
    total_spent: string | number;
    last_transaction_at: Date | null;
    created_at: Date;
    updated_at: Date;
};

async function getOrCreatePassengerWallet(
    passengerId: number,
): Promise<WalletRow> {
    const selectSql = `
        SELECT id, passenger_id, balance, pending_balance, total_spent,
               last_transaction_at, created_at, updated_at
        FROM public.wallets
        WHERE passenger_id = $1::integer
        LIMIT 1`;

    const found = await pool.query<WalletRow>(selectSql, [passengerId]);
    if (found.rows.length) return found.rows[0];

    try {
        const inserted = await pool.query<WalletRow>(
            `INSERT INTO public.wallets (
                passenger_id, balance, pending_balance, total_spent,
                created_at, updated_at
             )
             VALUES ($1::integer, 0, 0, 0, NOW(), NOW())
             RETURNING id, passenger_id, balance, pending_balance, total_spent,
                       last_transaction_at, created_at, updated_at`,
            [passengerId],
        );
        return inserted.rows[0];
    } catch (error: any) {
        // Another request won the race → just re-read.
        if (error?.code === '23505') {
            const retry = await pool.query<WalletRow>(selectSql, [passengerId]);
            if (retry.rows.length) return retry.rows[0];
        }
        throw error;
    }
}

async function getWalletBalance(walletId: number | string): Promise<number | null> {
    const result = await pool.query<{ balance: string | number }>(
        `SELECT balance FROM public.wallets WHERE id = $1::bigint LIMIT 1`,
        [walletId],
    );
    return result.rows.length ? Number(result.rows[0].balance) || 0 : null;
}

/* ==========================================================================
 * DRIVER PAYMENT NOTIFICATION
 * ========================================================================== */

async function notifyDriverPaymentReceived(
    driverUid: string | null,
    rideId: number,
    earnings: number,
    fare: number,
    commission: number,
): Promise<void> {
    if (!driverUid) return;

    try {
        const tokenResult = await pool.query<{ token: string }>(
            `SELECT token
             FROM public.fcm_tokens
             WHERE user_id = $1::varchar
             ORDER BY updated_at DESC NULLS LAST
             LIMIT 1`,
            [driverUid],
        );

        const token = tokenResult.rows[0]?.token;
        if (!token) return;

        await firebaseMessaging.send({
            token,
            notification: {
                title: 'Payment Received',
                body: `You earned GH₵${earnings.toFixed(2)} for ride #${rideId}.`,
            },
            data: {
                role: 'driver',
                notificationType: 'payment_received',
                targetScreen: 'driver_wallet',
                status: 'paid',
                rideId: String(rideId),
                amount: earnings.toFixed(2),
                fare: fare.toFixed(2),
                commission: commission.toFixed(2),
            },
        });
    } catch (error: any) {
        if (
            error?.code === 'messaging/invalid-registration-token' ||
            error?.code === 'messaging/registration-token-not-registered'
        ) {
            try {
                await pool.query(
                    `DELETE FROM public.fcm_tokens
                     WHERE user_id = $1::varchar AND token IS NOT NULL`,
                    [driverUid],
                );
            } catch (deleteError) {
                console.error('Failed to clean up FCM token:', deleteError);
            }
        }
        console.error('Driver payment notification failed:', error);
    }
}

/* ==========================================================================
 * applySuccessfulPayment — applies a verified Paystack payment exactly once.
 *
 * Only call with data returned by Paystack verification / OTP submission.
 * ========================================================================== */

export async function applySuccessfulPayment(
    reference: string,
    paystackData: Record<string, any>,
): Promise<{
    applied: boolean;
    alreadyApplied: boolean;
    purpose: string | null;
    newBalance: number | null;
}> {
    const client = await pool.connect();
    let notification: {
        driverUid: string | null;
        rideId: number;
        earnings: number;
        fare: number;
        commission: number;
    } | null = null;

    try {
        await client.query('BEGIN');

        const txResult = await client.query(
            `SELECT *
             FROM public.paystack_transactions
             WHERE reference = $1::varchar
             LIMIT 1
             FOR UPDATE`,
            [reference],
        );

        if (!txResult.rows.length) {
            await client.query('ROLLBACK');
            return {
                applied: false,
                alreadyApplied: false,
                purpose: null,
                newBalance: null,
            };
        }

        const tx = txResult.rows[0];

        if (tx.applied === true) {
            let balance: number | null = null;
            if (tx.purpose === 'wallet_topup' && tx.wallet_id) {
                const result = await client.query(
                    `SELECT balance FROM public.wallets WHERE id = $1::bigint`,
                    [tx.wallet_id],
                );
                if (result.rows.length) {
                    balance = Number(result.rows[0].balance) || 0;
                }
            }
            await client.query('COMMIT');
            return {
                applied: true,
                alreadyApplied: true,
                purpose: tx.purpose,
                newBalance: balance,
            };
        }

        const paidPesewas = Number(paystackData?.amount);
        if (!Number.isFinite(paidPesewas) || paidPesewas <= 0) {
            await client.query('ROLLBACK');
            return {
                applied: false,
                alreadyApplied: false,
                purpose: tx.purpose,
                newBalance: null,
            };
        }

        const paidGHS = fromPesewas(paidPesewas);
        const expectedGHS = amountToGHS(tx.amount);

        if (Math.abs(paidGHS - expectedGHS) > 0.01) {
            console.error('Paystack amount mismatch:', {
                reference,
                paidGHS,
                expectedGHS,
            });
            await client.query(
                `UPDATE public.paystack_transactions
                 SET paystack_verify = $1::jsonb,
                     updated_at = NOW()
                 WHERE reference = $2::varchar AND applied = FALSE`,
                [JSON.stringify(paystackData), reference],
            );
            await client.query('COMMIT');
            return {
                applied: false,
                alreadyApplied: false,
                purpose: tx.purpose,
                newBalance: null,
            };
        }

        let newBalance: number | null = null;

        if (tx.purpose === 'wallet_topup') {
            const walletResult = await client.query(
                `SELECT id, passenger_id, balance
                 FROM public.wallets
                 WHERE id = $1::bigint
                 LIMIT 1
                 FOR UPDATE`,
                [tx.wallet_id],
            );

            if (!walletResult.rows.length) {
                throw new Error('Wallet not found for verified top-up.');
            }

            const wallet = walletResult.rows[0];
            const before = Number(wallet.balance) || 0;
            const after = Math.round((before + expectedGHS) * 100) / 100;

            await client.query(
                `UPDATE public.wallets
                 SET balance = $1::numeric,
                     last_transaction_at = NOW(),
                     updated_at = NOW()
                 WHERE id = $2::bigint`,
                [after, wallet.id],
            );

            await client.query(
                `INSERT INTO public.transactions (
                    wallet_id, passenger_id, type, amount,
                    balance_before, balance_after, status,
                    payment_method, provider, description,
                    created_at, updated_at
                 )
                 VALUES (
                    $1::bigint, $2::integer, 'topup', $3::numeric,
                    $4::numeric, $5::numeric, 'completed',
                    'paystack_momo', $6::varchar, $7::text,
                    NOW(), NOW()
                 )`,
                [
                    wallet.id,
                    wallet.passenger_id,
                    expectedGHS,
                    before,
                    after,
                    tx.provider ?? 'mtn',
                    `Paystack top-up reference ${reference}`,
                ],
            );

            newBalance = after;
        } else if (tx.purpose === 'ride_payment') {
            const rideResult = await client.query(
                `SELECT
                    r.id, r.passenger_id, r.driver_id, r.fare,
                    r.payment_status,
                    p.full_name AS passenger_name
                 FROM public.rides r
                 JOIN public.passengers p ON p.id = r.passenger_id
                 WHERE r.id = $1::integer
                   AND r.passenger_id = $2::integer
                 LIMIT 1
                 FOR UPDATE OF r`,
                [tx.ride_id, tx.passenger_id],
            );

            if (!rideResult.rows.length) {
                throw new Error('Ride not found for verified payment.');
            }

            const ride = rideResult.rows[0];
            const fare = amountToGHS(ride.fare);

            if (ride.payment_status === 'paid') {
                await client.query(
                    `UPDATE public.paystack_transactions
                     SET status = 'refund_review',
                         paystack_verify = $1::jsonb,
                         updated_at = NOW()
                     WHERE reference = $2::varchar AND applied = FALSE`,
                    [JSON.stringify(paystackData), reference],
                );
                await client.query('COMMIT');
                return {
                    applied: false,
                    alreadyApplied: false,
                    purpose: tx.purpose,
                    newBalance: null,
                };
            }

            if (fare <= 0 || Math.abs(fare - expectedGHS) > 0.01) {
                await client.query(
                    `UPDATE public.paystack_transactions
                     SET paystack_verify = $1::jsonb,
                         updated_at = NOW()
                     WHERE reference = $2::varchar AND applied = FALSE`,
                    [JSON.stringify(paystackData), reference],
                );
                await client.query('COMMIT');
                return {
                    applied: false,
                    alreadyApplied: false,
                    purpose: tx.purpose,
                    newBalance: null,
                };
            }

            const commission = Math.min(FLAT_COMMISSION, fare);
            const earnings = Math.max(0, fare - commission);

            if (ride.driver_id) {
                const driverResult = await client.query(
                    `SELECT id FROM public.drivers
                     WHERE uid = $1::varchar LIMIT 1`,
                    [ride.driver_id],
                );
                const driverId = driverResult.rows[0]?.id;

                if (driverId) {
                    const walletResult = await client.query(
                        `SELECT id, balance FROM public.driver_wallets
                         WHERE driver_id = $1::bigint
                         LIMIT 1
                         FOR UPDATE`,
                        [driverId],
                    );

                    if (walletResult.rows.length) {
                        const dw = walletResult.rows[0];
                        const before = Number(dw.balance) || 0;
                        const after = Math.round((before + earnings) * 100) / 100;

                        await client.query(
                            `UPDATE public.driver_wallets
                             SET balance = $1::numeric,
                                 last_transaction_at = NOW(),
                                 updated_at = NOW()
                             WHERE id = $2::bigint`,
                            [after, dw.id],
                        );

                        await client.query(
                            `INSERT INTO public.driver_transactions (
                                driver_id, wallet_id, ride_id, amount,
                                type, status, balance_before, balance_after,
                                transaction_reference, description, metadata,
                                created_at, updated_at
                             )
                             VALUES (
                                $1::bigint, $2::bigint, $3::integer,
                                $4::numeric, 'ride_earning', 'completed',
                                $5::numeric, $6::numeric, $7::varchar,
                                $8::text, $9::jsonb, NOW(), NOW()
                             )`,
                            [
                                driverId,
                                dw.id,
                                ride.id,
                                earnings,
                                before,
                                after,
                                `PAYSTACK-${reference}`,
                                `Earnings from ride #${ride.id}`,
                                JSON.stringify({
                                    ride_id: ride.id,
                                    passenger_id: ride.passenger_id,
                                    source: 'paystack',
                                    reference,
                                }),
                            ],
                        );
                    }
                }
            }

            // The trg_enforce_flat_commission trigger will overwrite
            // driver_earnings/tegaara_commission when fare is set, but this
            // UPDATE only touches payment_status / paid_at so it stays stable.
            await client.query(
                `UPDATE public.rides
                 SET payment_status = 'paid',
                     driver_earnings = $1::numeric,
                     tegaara_commission = $2::numeric,
                     paid_at = NOW(),
                     updated_at = NOW()
                 WHERE id = $3::integer`,
                [earnings, commission, ride.id],
            );

            const passengerWallet = await client.query(
                `SELECT id, balance FROM public.wallets
                 WHERE passenger_id = $1::integer LIMIT 1`,
                [ride.passenger_id],
            );

            if (passengerWallet.rows.length) {
                const wallet = passengerWallet.rows[0];
                const balance = Number(wallet.balance) || 0;

                await client.query(
                    `INSERT INTO public.transactions (
                        wallet_id, passenger_id, ride_id, type, amount,
                        balance_before, balance_after, status,
                        payment_method, description, created_at, updated_at
                     )
                     VALUES (
                        $1::bigint, $2::integer, $3::integer,
                        'ride_payment', $4::numeric, $5::numeric,
                        $5::numeric, 'completed', 'paystack_momo',
                        $6::text, NOW(), NOW()
                     )`,
                    [
                        wallet.id,
                        ride.passenger_id,
                        ride.id,
                        fare,
                        balance,
                        `Paystack MoMo payment for ride #${ride.id}`,
                    ],
                );
            }

            notification = {
                driverUid: ride.driver_id,
                rideId: Number(ride.id),
                earnings,
                fare,
                commission,
            };
        } else {
            throw new Error(`Unsupported payment purpose: ${tx.purpose}`);
        }

        await client.query(
            `UPDATE public.paystack_transactions
             SET applied = TRUE,
                 status = 'success',
                 paystack_verify = $1::jsonb,
                 completed_at = NOW(),
                 updated_at = NOW()
             WHERE reference = $2::varchar AND applied = FALSE`,
            [JSON.stringify(paystackData), reference],
        );

        await client.query('COMMIT');

        if (notification) {
            void notifyDriverPaymentReceived(
                notification.driverUid,
                notification.rideId,
                notification.earnings,
                notification.fare,
                notification.commission,
            );
        }

        return {
            applied: true,
            alreadyApplied: false,
            purpose: tx.purpose,
            newBalance,
        };
    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch {
            // ignore
        }
        console.error(`Payment application failed for ${reference}:`, error);
        return {
            applied: false,
            alreadyApplied: false,
            purpose: null,
            newBalance: null,
        };
    } finally {
        client.release();
    }
}

/* ==========================================================================
 * GET /passengers/wallet
 * ========================================================================== */

router.get(
    '/passengers/wallet',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) return res.status(401).json({ success: false, message: 'Unauthenticated.' });

        try {
            const passenger = await findPassenger(uid);
            if (!passenger) return res.status(404).json({ success: false, message: 'Passenger profile not found.' });

            const result = await pool.query(
                `SELECT id, passenger_id, balance,
                        pending_balance AS "pendingBalance",
                        total_spent AS "totalSpent",
                        last_transaction_at AS "lastTransactionAt",
                        created_at AS "createdAt",
                        updated_at AS "updatedAt"
                 FROM public.wallets
                 WHERE passenger_id = $1::integer
                 LIMIT 1`,
                [passenger.id],
            );

            if (!result.rows.length) {
                return res.status(404).json({ success: false, message: 'Wallet not found.' });
            }

            const w = result.rows[0];
            return res.json({
                success: true,
                wallet: {
                    ...w,
                    balance: Number(w.balance) || 0,
                    pendingBalance: Number(w.pendingBalance) || 0,
                    totalSpent: Number(w.totalSpent) || 0,
                    currency: 'GHS',
                    isActive: true,
                },
            });
        } catch (error) {
            console.error('GET wallet failed:', error);
            return res.status(500).json({ success: false, message: 'Failed to load wallet.' });
        }
    },
);

/* ==========================================================================
 * POST /passengers/wallet
 * ========================================================================== */

router.post(
    '/passengers/wallet',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) return res.status(401).json({ success: false, message: 'Unauthenticated.' });

        const bodyFullName = String(req.body?.full_name ?? '').trim();
        const bodyEmail = String(req.body?.email ?? '').trim();
        const bodyPhone = String(req.body?.phone ?? '').trim();

        try {
            const passenger = await findOrCreatePassenger(uid, {
                full_name: bodyFullName || undefined,
                email: bodyEmail || undefined,
                phone: bodyPhone || undefined,
            });

            const w = await getOrCreatePassengerWallet(passenger.id);

            return res.status(200).json({
                success: true,
                wallet: {
                    id: w.id,
                    passengerId: w.passenger_id,
                    balance: Number(w.balance) || 0,
                    pendingBalance: Number(w.pending_balance) || 0,
                    totalSpent: Number(w.total_spent) || 0,
                    currency: 'GHS',
                    isActive: true,
                    lastTransactionAt: w.last_transaction_at,
                    createdAt: w.created_at,
                    updatedAt: w.updated_at,
                },
            });
        } catch (error: any) {
            console.error('POST /passengers/wallet failed:', {
                uid,
                code: error?.code,
                message: error?.message,
                detail: error?.detail,
                hint: error?.hint,
                where: error?.where,
                schema: error?.schema,
                table: error?.table,
                column: error?.column,
                constraint: error?.constraint,
            });

            const code = error?.code ?? 'UNKNOWN';

            if (code === '42P01') {
                return res.status(500).json({
                    success: false,
                    code,
                    message: 'Server schema error: a required table is missing.',
                });
            }
            if (code === '42703') {
                return res.status(500).json({
                    success: false,
                    code,
                    message: `Server schema error: missing column "${error?.column ?? 'unknown'}".`,
                });
            }
            if (code === '23502') {
                return res.status(500).json({
                    success: false,
                    code,
                    message: `Server schema error: required field "${error?.column ?? 'unknown'}" was not provided.`,
                });
            }
            if (code === '23514') {
                return res.status(500).json({
                    success: false,
                    code,
                    message: `Server schema error: constraint "${error?.constraint ?? 'unknown'}" was violated.`,
                });
            }

            return res.status(500).json({
                success: false,
                code,
                message: `Wallet creation failed (${code}): ${error?.message ?? 'unknown error'}`,
            });
        }
    },
);

/* Legacy direct top-up disabled. */
router.post(
    '/passengers/wallet/topup',
    verifyFirebaseToken,
    (_req: AuthenticatedRequest, res: Response) =>
        res.status(410).json({
            success: false,
            code: 'LEGACY_TOPUP_DISABLED',
            message: 'Direct wallet top-ups are disabled. Use Paystack Mobile Money.',
        }),
);

/* ==========================================================================
 * GET /passengers/wallet/pending-payment-ride
 * ========================================================================== */

router.get(
    '/passengers/wallet/pending-payment-ride',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) return res.status(401).json({ success: false, message: 'Unauthenticated.' });

        try {
            const passenger = await findPassenger(uid);
            if (!passenger) return res.status(404).json({ success: false, message: 'Passenger profile not found.' });

            const result = await pool.query(
                `SELECT r.id AS ride_id, r.fare AS amount, r.completed_at,
                        d.uid AS driver_id, d.full_name AS driver_name,
                        d.profile_photo_url AS driver_photo_url,
                        d.vehicle_type, d.vehicle_model, d.vehicle_color,
                        d.registration_number AS vehicle_registration,
                        d.vehicle_year
                 FROM public.rides r
                 LEFT JOIN public.drivers d ON d.uid = r.driver_id
                 WHERE r.passenger_id = $1::integer
                   AND r.status = 'completed'
                   AND (r.payment_status IS NULL OR r.payment_status <> 'paid')
                   AND r.driver_id IS NOT NULL
                 ORDER BY r.completed_at DESC NULLS LAST, r.id DESC
                 LIMIT 1`,
                [passenger.id],
            );

            return res.json({
                success: true,
                ride: result.rows[0] ?? null,
            });
        } catch (error) {
            console.error('Pending ride lookup failed:', error);
            return res.status(500).json({ success: false, message: 'Failed to load pending payment ride.' });
        }
    },
);

/* ==========================================================================
 * GET /passengers/transactions
 * ========================================================================== */

router.get(
    '/passengers/transactions',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) return res.status(401).json({ success: false, message: 'Unauthenticated.' });

        const page = Math.max(parseInt(String(req.query.page ?? '1'), 10) || 1, 1);
        const limit = Math.min(Math.max(parseInt(String(req.query.limit ?? '20'), 10) || 20, 1), 100);
        const offset = (page - 1) * limit;

        try {
            const passenger = await findPassenger(uid);
            if (!passenger) return res.status(404).json({ success: false, message: 'Passenger profile not found.' });

            const result = await pool.query(
                `SELECT id, wallet_id, ride_id, type, amount, balance_before,
                        balance_after, status, payment_method, provider, created_at
                 FROM public.transactions
                 WHERE passenger_id = $1::integer
                 ORDER BY created_at DESC, id DESC
                 LIMIT $2 OFFSET $3`,
                [passenger.id, limit, offset],
            );

            return res.json({ success: true, transactions: result.rows });
        } catch (error) {
            console.error('Transaction history failed:', error);
            return res.status(500).json({ success: false, message: 'Failed to load transactions.' });
        }
    },
);

/* ==========================================================================
 * POST /passengers/wallet/pay — pay using existing wallet balance
 * ========================================================================== */

router.post(
    '/passengers/wallet/pay',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) return res.status(401).json({ success: false, message: 'Unauthenticated.' });

        const rideId = Number(req.body?.ride_id);
        if (!Number.isInteger(rideId) || rideId <= 0) {
            return res.status(400).json({ success: false, message: 'A valid ride_id is required.' });
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const passengerResult = await client.query(
                `SELECT id, full_name FROM public.passengers
                 WHERE firebase_uid = $1::varchar LIMIT 1 FOR UPDATE`,
                [uid],
            );
            if (!passengerResult.rows.length) {
                await client.query('ROLLBACK');
                return res.status(404).json({ success: false, message: 'Passenger profile not found.' });
            }

            const passenger = passengerResult.rows[0];

            const rideResult = await client.query(
                `SELECT id, passenger_id, driver_id, fare, payment_status
                 FROM public.rides
                 WHERE id = $1::integer AND passenger_id = $2::integer
                 LIMIT 1 FOR UPDATE`,
                [rideId, passenger.id],
            );
            if (!rideResult.rows.length) {
                await client.query('ROLLBACK');
                return res.status(404).json({ success: false, message: 'Ride not found or does not belong to you.' });
            }

            const ride = rideResult.rows[0];
            if (ride.payment_status === 'paid') {
                await client.query('ROLLBACK');
                return res.json({ success: true, alreadyPaid: true, message: 'Ride already paid.' });
            }
            if (!ride.driver_id) {
                await client.query('ROLLBACK');
                return res.status(400).json({ success: false, message: 'Ride has no assigned driver.' });
            }

            const fare = amountToGHS(ride.fare);
            if (fare <= 0) {
                await client.query('ROLLBACK');
                return res.status(400).json({ success: false, message: 'Ride has no valid fare.' });
            }

            const walletResult = await client.query(
                `SELECT id, balance FROM public.wallets
                 WHERE passenger_id = $1::integer LIMIT 1 FOR UPDATE`,
                [passenger.id],
            );
            if (!walletResult.rows.length) {
                await client.query('ROLLBACK');
                return res.status(404).json({ success: false, message: 'Wallet not found. Please create a wallet first.' });
            }

            const wallet = walletResult.rows[0];
            const before = Number(wallet.balance) || 0;
            if (before < fare) {
                await client.query('ROLLBACK');
                return res.status(402).json({
                    success: false,
                    code: 'INSUFFICIENT_WALLET_BALANCE',
                    message: `Insufficient balance. You have GH₵${before.toFixed(2)} but need GH₵${fare.toFixed(2)}.`,
                    balance: before,
                    required: fare,
                });
            }

            const after = Math.round((before - fare) * 100) / 100;
            const commission = Math.min(FLAT_COMMISSION, fare);
            const earnings = Math.max(0, fare - commission);

            await client.query(
                `UPDATE public.wallets
                 SET balance = $1::numeric,
                     total_spent = COALESCE(total_spent, 0) + $2::numeric,
                     last_transaction_at = NOW(),
                     updated_at = NOW()
                 WHERE id = $3::bigint`,
                [after, fare, wallet.id],
            );

            const driverResult = await client.query(
                `SELECT id FROM public.drivers WHERE uid = $1::varchar LIMIT 1`,
                [ride.driver_id],
            );
            let driverBalance: number | null = null;

            if (driverResult.rows.length) {
                const driverId = driverResult.rows[0].id;
                const dwResult = await client.query(
                    `SELECT id, balance FROM public.driver_wallets
                     WHERE driver_id = $1::bigint LIMIT 1 FOR UPDATE`,
                    [driverId],
                );

                if (dwResult.rows.length) {
                    const dw = dwResult.rows[0];
                    const dbefore = Number(dw.balance) || 0;
                    driverBalance = Math.round((dbefore + earnings) * 100) / 100;

                    await client.query(
                        `UPDATE public.driver_wallets
                         SET balance = $1::numeric,
                             last_transaction_at = NOW(),
                             updated_at = NOW()
                         WHERE id = $2::bigint`,
                        [driverBalance, dw.id],
                    );

                    await client.query(
                        `INSERT INTO public.driver_transactions (
                            driver_id, wallet_id, ride_id, amount, type, status,
                            balance_before, balance_after, transaction_reference,
                            description, metadata, created_at, updated_at
                         )
                         VALUES (
                            $1::bigint, $2::bigint, $3::integer, $4::numeric,
                            'ride_earning', 'completed', $5::numeric, $6::numeric,
                            $7::varchar, $8::text, $9::jsonb, NOW(), NOW()
                         )`,
                        [
                            driverId,
                            dw.id,
                            rideId,
                            earnings,
                            dbefore,
                            driverBalance,
                            `WALLET-${rideId}-${Date.now()}`,
                            `Earnings from ride #${rideId}`,
                            JSON.stringify({
                                ride_id: rideId,
                                passenger_id: passenger.id,
                                source: 'wallet',
                            }),
                        ],
                    );
                }
            }

            await client.query(
                `INSERT INTO public.transactions (
                    wallet_id, passenger_id, ride_id, type, amount,
                    balance_before, balance_after, status, payment_method,
                    description, created_at, updated_at
                 )
                 VALUES (
                    $1::bigint, $2::integer, $3::integer, 'ride_payment',
                    $4::numeric, $5::numeric, $6::numeric, 'completed',
                    'wallet', $7::text, NOW(), NOW()
                 )`,
                [
                    wallet.id,
                    passenger.id,
                    rideId,
                    fare,
                    before,
                    after,
                    `Payment for ride #${rideId}`,
                ],
            );

            await client.query(
                `UPDATE public.rides
                 SET payment_status = 'paid',
                     driver_earnings = $1::numeric,
                     tegaara_commission = $2::numeric,
                     paid_at = NOW(),
                     updated_at = NOW()
                 WHERE id = $3::integer`,
                [earnings, commission, rideId],
            );

            await client.query('COMMIT');

            void notifyDriverPaymentReceived(
                ride.driver_id,
                rideId,
                earnings,
                fare,
                commission,
            );

            return res.json({
                success: true,
                rideId,
                paymentStatus: 'paid',
                amount: fare,
                driverEarnings: earnings,
                tegaaraCommission: commission,
                newPassengerBalance: after,
                newDriverBalance: driverBalance,
                message: 'Payment processed successfully.',
            });
        } catch (error) {
            try {
                await client.query('ROLLBACK');
            } catch {
                // ignore
            }
            console.error('Wallet ride payment failed:', error);
            return res.status(500).json({ success: false, message: 'Failed to process payment.' });
        } finally {
            client.release();
        }
    },
);

/* ==========================================================================
 * SHARED PAYSTACK INITIALIZATION
 *
 * Default MoMo number resolution order:
 *   1. request body `phone`
 *   2. passengers.mobile_money_number
 *   3. passengers.phone
 * ========================================================================== */

async function initializePayment(
    req: AuthenticatedRequest,
    res: Response,
    purpose: 'wallet_topup' | 'ride_payment',
) {
    const uid = getAuthenticatedUid(req);
    if (!uid) return res.status(401).json({ success: false, message: 'Unauthenticated.' });

    const providedPhone = String(req.body?.phone ?? '').trim();
    const providerText = String(req.body?.provider ?? '').trim().toLowerCase();
    const amountInput = Number(req.body?.amount);
    const rideId = Number(req.body?.ride_id);

    if (!validProvider(providerText)) {
        return res.status(400).json({ success: false, message: 'Unsupported mobile money provider.' });
    }

    try {
        const passenger = await findPassenger(uid);
        if (!passenger) {
            return res.status(404).json({ success: false, message: 'Passenger profile not found.' });
        }

        const phone =
            providedPhone ||
            String(passenger.mobile_money_number ?? '').trim() ||
            String(passenger.phone ?? '').trim();

        if (phone.length < 6) {
            return res.status(400).json({
                success: false,
                code: 'PHONE_REQUIRED',
                message:
                    'No mobile money number on file. Add one to your profile ' +
                    'or enter it manually.',
            });
        }

        let walletId: number | null = null;
        let amount = amountToGHS(amountInput);

        if (purpose === 'wallet_topup') {
            if (amount <= 0 || amount > 10000) {
                return res.status(400).json({ success: false, message: 'Enter a valid top-up amount.' });
            }

            const walletResult = await pool.query(
                `SELECT id FROM public.wallets WHERE passenger_id = $1::integer LIMIT 1`,
                [passenger.id],
            );
            walletId = walletResult.rows[0]?.id ?? null;
            if (!walletId) {
                return res.status(404).json({
                    success: false,
                    message: 'Wallet not found. Please create a wallet first.',
                });
            }
        } else {
            if (!Number.isInteger(rideId) || rideId <= 0) {
                return res.status(400).json({ success: false, message: 'A valid ride_id is required.' });
            }

            const rideResult = await pool.query(
                `SELECT id, fare, payment_status
                 FROM public.rides
                 WHERE id = $1::integer AND passenger_id = $2::integer
                 LIMIT 1`,
                [rideId, passenger.id],
            );
            if (!rideResult.rows.length) {
                return res.status(404).json({
                    success: false,
                    message: 'Ride not found or does not belong to you.',
                });
            }
            if (rideResult.rows[0].payment_status === 'paid') {
                return res.json({ success: true, alreadyPaid: true, message: 'Ride already paid.' });
            }

            amount = amountToGHS(rideResult.rows[0].fare);
            if (amount <= 0) {
                return res.status(400).json({ success: false, message: 'Ride has no valid fare.' });
            }
        }

        const provider = providerText as PaystackProvider;
        const email =
            (req.decodedToken as any)?.email ||
            passenger.email ||
            `passenger+${uid.slice(0, 8)}@tegaara.app`;
        const reference = generateReference(
            purpose === 'wallet_topup' ? 'topup' : 'ride',
            uid,
        );

        await pool.query(
            `INSERT INTO public.paystack_transactions (
                reference, user_firebase_uid, purpose, amount, status,
                channel, provider, phone, passenger_id, wallet_id, ride_id
             )
             VALUES (
                $1::varchar, $2::varchar, $3::varchar, $4::numeric, 'pending',
                'mobile_money', $5::varchar, $6::varchar,
                $7::integer, $8::bigint, $9::integer
             )`,
            [
                reference,
                uid,
                purpose,
                amount,
                provider,
                phone,
                passenger.id,
                walletId,
                purpose === 'ride_payment' ? rideId : null,
            ],
        );

        const charge = await initializeMobileMoneyCharge({
            email,
            amountGHS: amount,
            phone,
            provider,
            reference,
            metadata: {
                purpose,
                userFirebaseUid: uid,
                passengerId: passenger.id,
                ...(walletId ? { walletId } : {}),
                ...(purpose === 'ride_payment' ? { rideId } : {}),
            },
        });

        const status = normaliseStatus(charge.status);

        await pool.query(
            `UPDATE public.paystack_transactions
             SET status = $1::varchar,
                 paystack_init = $2::jsonb,
                 updated_at = NOW()
             WHERE reference = $3::varchar`,
            [status, JSON.stringify(charge.raw), reference],
        );

        return res.status(200).json({
            success: status !== 'failed' && status !== 'reversed',
            reference,
            status,
            displayText: statusMessage(status),
            message: statusMessage(status),
            amount,
            phone,
            provider,
            ...(purpose === 'ride_payment' ? { rideId } : {}),
        });
    } catch (error) {
        console.error(`Initialize ${purpose} failed:`, error);
        return res.status(500).json({
            success: false,
            message: 'Could not initiate the Mobile Money payment. Please try again.',
        });
    }
}

router.post(
    '/passengers/wallet/topup/initialize',
    verifyFirebaseToken,
    (req: AuthenticatedRequest, res: Response) =>
        initializePayment(req, res, 'wallet_topup'),
);

router.post(
    '/passengers/wallet/pay/initialize',
    verifyFirebaseToken,
    (req: AuthenticatedRequest, res: Response) =>
        initializePayment(req, res, 'ride_payment'),
);

/* ==========================================================================
 * SHARED OTP SUBMISSION HANDLER
 * ========================================================================== */

async function submitPaymentOtp(
    req: AuthenticatedRequest,
    res: Response,
    purpose: 'wallet_topup' | 'ride_payment',
) {
    const uid = getAuthenticatedUid(req);
    if (!uid) return res.status(401).json({ success: false, message: 'Unauthenticated.' });

    const reference = String(req.body?.reference ?? '').trim();
    const otp = String(req.body?.otp ?? '').trim();

    if (!reference) {
        return res.status(400).json({ success: false, message: 'Reference is required.' });
    }
    if (!/^\d{4,8}$/.test(otp)) {
        return res.status(400).json({ success: false, message: 'Enter a valid verification code.' });
    }

    try {
        const txResult = await pool.query(
            `SELECT * FROM public.paystack_transactions
             WHERE reference = $1::varchar
               AND user_firebase_uid = $2::varchar
               AND purpose = $3::varchar
             LIMIT 1`,
            [reference, uid, purpose],
        );

        if (!txResult.rows.length) {
            return res.status(404).json({ success: false, message: 'Payment not found.' });
        }

        const tx = txResult.rows[0];

        if (tx.applied === true) {
            return res.json({
                success: true,
                status: 'success',
                alreadyApplied: true,
                ...(purpose === 'ride_payment' ? { rideId: tx.ride_id } : {}),
                ...(purpose === 'wallet_topup'
                    ? { newBalance: await getWalletBalance(tx.wallet_id) }
                    : {}),
            });
        }

        let submitted;
        try {
            submitted = await submitOtp({ reference, otp });
        } catch {
            return res.status(400).json({
                success: false,
                status: 'send_otp',
                code: 'OTP_SUBMISSION_FAILED',
                message: 'The verification code could not be accepted. Check the code and try again.',
            });
        }

        const status = normaliseStatus(submitted.status);

        await pool.query(
            `UPDATE public.paystack_transactions
             SET status = $1::varchar,
                 paystack_verify = $2::jsonb,
                 updated_at = NOW()
             WHERE reference = $3::varchar
               AND user_firebase_uid = $4::varchar
               AND applied = FALSE`,
            [status, JSON.stringify(submitted.raw), reference, uid],
        );

        if (status === 'success') {
            const result = await applySuccessfulPayment(
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
                        'The payment may have been received, but account updating ' +
                        'is not yet confirmed. Do not pay again; check the ' +
                        'transaction status shortly.',
                });
            }

            return res.json({
                success: true,
                status: 'success',
                alreadyApplied: result.alreadyApplied,
                ...(purpose === 'ride_payment' ? { rideId: tx.ride_id } : {}),
                ...(purpose === 'wallet_topup'
                    ? { newBalance: await getWalletBalance(tx.wallet_id) }
                    : {}),
            });
        }

        if (status === 'failed' || status === 'reversed') {
            return res.status(200).json({
                success: false,
                status,
                message: statusMessage(status),
            });
        }

        return res.status(200).json({
            success: true,
            status,
            message: statusMessage(status),
        });
    } catch (error) {
        console.error('OTP submission failed:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to submit verification code.',
        });
    }
}

router.post(
    '/passengers/wallet/topup/submit-otp',
    verifyFirebaseToken,
    (req: AuthenticatedRequest, res: Response) =>
        submitPaymentOtp(req, res, 'wallet_topup'),
);

router.post(
    '/passengers/wallet/pay/submit-otp',
    verifyFirebaseToken,
    (req: AuthenticatedRequest, res: Response) =>
        submitPaymentOtp(req, res, 'ride_payment'),
);

/* ==========================================================================
 * SHARED VERIFICATION HANDLER
 * ========================================================================== */

async function verifyPayment(
    req: AuthenticatedRequest,
    res: Response,
    purpose: 'wallet_topup' | 'ride_payment',
) {
    const uid = getAuthenticatedUid(req);
    if (!uid) return res.status(401).json({ success: false, message: 'Unauthenticated.' });

    const reference = String(req.params.reference ?? '').trim();
    if (!reference) {
        return res.status(400).json({ success: false, message: 'Reference is required.' });
    }

    try {
        const txResult = await pool.query(
            `SELECT * FROM public.paystack_transactions
             WHERE reference = $1::varchar
               AND user_firebase_uid = $2::varchar
               AND purpose = $3::varchar
             LIMIT 1`,
            [reference, uid, purpose],
        );

        if (!txResult.rows.length) {
            return res.status(404).json({ success: false, message: 'Payment not found.' });
        }

        const tx = txResult.rows[0];

        if (tx.applied === true) {
            return res.json({
                success: true,
                status: 'success',
                alreadyApplied: true,
                ...(purpose === 'ride_payment' ? { rideId: tx.ride_id } : {}),
                ...(purpose === 'wallet_topup'
                    ? { newBalance: await getWalletBalance(tx.wallet_id) }
                    : {}),
            });
        }

        let verified;
        try {
            verified = await verifyTransaction(reference);
        } catch {
            return res.status(200).json({
                success: true,
                status: 'pending',
                message: statusMessage('pending'),
                reference,
            });
        }

        const status = normaliseStatus(verified.status);
        const paystackData = verified.raw?.data ?? verified.raw ?? {};

        if (status === 'success') {
            const result = await applySuccessfulPayment(reference, paystackData);

            if (!result.applied) {
                return res.status(503).json({
                    success: false,
                    status: 'pending',
                    code: 'PAYMENT_CREDIT_PENDING',
                    reference,
                    message:
                        'Payment confirmation was received, but the account ' +
                        'update is not yet confirmed. Do not pay again; check ' +
                        'the status shortly.',
                });
            }

            return res.json({
                success: true,
                status: 'success',
                alreadyApplied: result.alreadyApplied,
                ...(purpose === 'ride_payment' ? { rideId: tx.ride_id } : {}),
                ...(purpose === 'wallet_topup'
                    ? { newBalance: result.newBalance }
                    : {}),
            });
        }

        if (status === 'failed' || status === 'reversed') {
            await pool.query(
                `UPDATE public.paystack_transactions
                 SET status = $1::varchar,
                     paystack_verify = $2::jsonb,
                     updated_at = NOW()
                 WHERE reference = $3::varchar AND applied = FALSE`,
                [status, JSON.stringify(verified.raw), reference],
            );

            return res.status(200).json({
                success: false,
                status,
                message: statusMessage(status),
            });
        }

        await pool.query(
            `UPDATE public.paystack_transactions
             SET status = $1::varchar,
                 paystack_verify = $2::jsonb,
                 updated_at = NOW()
             WHERE reference = $3::varchar AND applied = FALSE`,
            [status, JSON.stringify(verified.raw), reference],
        );

        return res.status(200).json({
            success: true,
            status,
            reference,
            message: statusMessage(status),
        });
    } catch (error) {
        console.error('Payment verification failed:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to verify payment. Please try again.',
        });
    }
}

router.get(
    '/passengers/wallet/topup/verify/:reference',
    verifyFirebaseToken,
    (req: AuthenticatedRequest, res: Response) =>
        verifyPayment(req, res, 'wallet_topup'),
);

router.get(
    '/passengers/wallet/pay/verify/:reference',
    verifyFirebaseToken,
    (req: AuthenticatedRequest, res: Response) =>
        verifyPayment(req, res, 'ride_payment'),
);

/* OTP save/fetch routes intentionally removed.
 * Never store or return OTPs from your database. */

export default router;
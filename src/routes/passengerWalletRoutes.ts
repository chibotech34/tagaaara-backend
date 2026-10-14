// routes/passengerWalletRoutes.ts

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

/* ==========================================================================
 * CONSTANTS
 * ========================================================================== */

const FLAT_COMMISSION = 2.0;

/* ==========================================================================
 * AUTH HELPER
 * ========================================================================== */

function getAuthenticatedUid(req: AuthenticatedRequest): string | null {
    const uid = req.decodedToken?.uid;
    if (!uid || typeof uid !== 'string' || !uid.trim()) return null;
    return uid.trim();
}

/* ==========================================================================
 * FCM: Notify driver that payment was received
 * ========================================================================== */

async function notifyDriverPaymentReceived(
    driverFirebaseUid: string | null | undefined,
    rideId: number,
    fare: number,
    driverEarnings: number,
    commission: number,
    newDriverBalance: number | null,
    passengerName: string,
    pickupAddress: string,
    destinationAddress: string,
): Promise<void> {
    if (!driverFirebaseUid) return;

    let driverToken: string | null = null;

    try {
        const tokenResult = await pool.query(
            `
            SELECT token
            FROM public.fcm_tokens
            WHERE user_id = $1::text
            ORDER BY updated_at DESC NULLS LAST
            LIMIT 1
            `,
            [driverFirebaseUid],
        );
        driverToken = tokenResult.rows[0]?.token ?? null;
    } catch (lookupError) {
        console.error(
            '❌ Driver payment FCM — token lookup failed:',
            lookupError,
        );
        return;
    }

    if (!driverToken) {
        console.log(
            `ℹ️ Driver payment FCM — no token for UID ${driverFirebaseUid}`,
        );
        return;
    }

    const title = 'Payment Received';
    const body =
        `You earned GH₵${driverEarnings.toFixed(2)} ` +
        `for ride #${rideId}.`;

    const data: Record<string, string> = {
        role: 'driver',
        notificationType: 'payment_received',
        targetScreen: 'driver_wallet',
        status: 'paid',
        rideId: String(rideId),
        amount: driverEarnings.toFixed(2),
        fare: fare.toFixed(2),
        commission: commission.toFixed(2),
        newBalance:
            newDriverBalance != null ? newDriverBalance.toFixed(2) : '',
        passengerName,
        pickupAddress,
        destinationAddress,
        title,
        body,
    };

    try {
        await firebaseMessaging.send({
            token: driverToken,
            notification: { title, body },
            data,
            android: {
                priority: 'high',
                ttl: 60 * 1000,
                notification: {
                    channelId: 'tegaara_ride_channel',
                    priority: 'high' as const,
                    defaultSound: true,
                    defaultVibrateTimings: true,
                    defaultLightSettings: true,
                    clickAction: 'FLUTTER_NOTIFICATION_CLICK',
                },
            },
            apns: {
                headers: {
                    'apns-priority': '10',
                    'apns-push-type': 'alert',
                },
                payload: {
                    aps: {
                        alert: { title, body },
                        sound: 'default',
                        badge: 1,
                        contentAvailable: true,
                        mutableContent: true,
                    },
                },
            },
        });
        console.log(
            `📨 payment_received sent to driver ${driverFirebaseUid} ` +
            `for ride ${rideId} ` +
            `(earned=GH₵${driverEarnings.toFixed(2)}, ` +
            `balance=${newDriverBalance != null
                ? newDriverBalance.toFixed(2)
                : 'n/a'
            })`,
        );
    } catch (error: any) {
        if (
            error?.code === 'messaging/invalid-registration-token' ||
            error?.code === 'messaging/registration-token-not-registered'
        ) {
            try {
                await pool.query(
                    `DELETE FROM public.fcm_tokens WHERE token = $1`,
                    [driverToken],
                );
                console.log(
                    `🧹 Removed stale FCM token for driver ${driverFirebaseUid}`,
                );
            } catch (deleteError) {
                console.error(
                    '❌ Failed deleting invalid FCM token:',
                    deleteError,
                );
            }
        }
        console.error('❌ Driver payment FCM failed:', error);
    }
}

/* ==========================================================================
 * PAYSTACK: APPLY A SUCCESSFUL PAYMENT (idempotent)
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

    try {
        await client.query('BEGIN');

        const txRowResult = await client.query(
            `
            SELECT *
            FROM public.paystack_transactions
            WHERE reference = $1
            LIMIT 1
            FOR UPDATE
            `,
            [reference],
        );

        if (txRowResult.rows.length === 0) {
            await client.query('ROLLBACK');
            console.warn(
                `⚠️ applySuccessfulPayment: ref ${reference} not found.`,
            );
            return {
                applied: false,
                alreadyApplied: false,
                purpose: null,
                newBalance: null,
            };
        }

        const txRow = txRowResult.rows[0];

        if (txRow.applied === true) {
            let newBalance: number | null = null;

            if (txRow.purpose === 'wallet_topup' && txRow.wallet_id) {
                const walletResult = await client.query(
                    `
                    SELECT balance
                    FROM public.wallets
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [txRow.wallet_id],
                );
                if (walletResult.rows.length > 0) {
                    newBalance =
                        Number(walletResult.rows[0].balance) || 0;
                }
            }

            await client.query('ROLLBACK');
            console.log(
                `ℹ️ applySuccessfulPayment: ref ${reference} already applied ` +
                `(purpose=${txRow.purpose})`,
            );
            return {
                applied: true,
                alreadyApplied: true,
                purpose: txRow.purpose,
                newBalance,
            };
        }

        const paidPesewas = Number(paystackData?.amount) || 0;
        const paidGHS = fromPesewas(paidPesewas);
        const expectedGHS = Number(txRow.amount) || 0;

        if (Math.abs(paidGHS - expectedGHS) > 0.01) {
            console.error(
                `⚠️ Paystack ref=${reference}: amount mismatch. ` +
                `paid=${paidGHS} expected=${expectedGHS}`,
            );
            await client.query(
                `
                UPDATE public.paystack_transactions
                SET status          = 'failed',
                    paystack_verify = $1::jsonb,
                    updated_at      = NOW()
                WHERE reference = $2
                `,
                [JSON.stringify(paystackData), reference],
            );
            await client.query('COMMIT');
            return {
                applied: false,
                alreadyApplied: false,
                purpose: txRow.purpose,
                newBalance: null,
            };
        }

        const payloadJson = JSON.stringify(paystackData);
        let newBalance: number | null = null;

        /* ==================================================================
         * WALLET TOP-UP
         * ================================================================== */
        if (txRow.purpose === 'wallet_topup') {
            const walletResult = await client.query(
                `
                SELECT id, passenger_id, balance
                FROM public.wallets
                WHERE id = $1
                LIMIT 1
                FOR UPDATE
                `,
                [txRow.wallet_id],
            );

            if (walletResult.rows.length === 0) {
                throw new Error(
                    `Wallet ${txRow.wallet_id} not found for ref ${reference}`,
                );
            }

            const walletId = walletResult.rows[0].id;
            const passengerId = walletResult.rows[0].passenger_id;
            const balanceBefore =
                Number(walletResult.rows[0].balance) || 0;
            const balanceAfter = balanceBefore + expectedGHS;

            await client.query(
                `
                UPDATE public.wallets
                SET balance             = $1::numeric,
                    last_transaction_at = NOW(),
                    updated_at          = NOW()
                WHERE id = $2
                `,
                [balanceAfter, walletId],
            );

            await client.query(
                `
                INSERT INTO public.transactions (
                    wallet_id,
                    passenger_id,
                    type,
                    amount,
                    balance_before,
                    balance_after,
                    status,
                    payment_method,
                    provider,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1::bigint,
                    $2::integer,
                    'topup',
                    $3::numeric,
                    $4::numeric,
                    $5::numeric,
                    'completed',
                    'paystack_momo',
                    $6::varchar,
                    $7::text,
                    NOW(),
                    NOW()
                )
                `,
                [
                    walletId,
                    passengerId,
                    expectedGHS,
                    balanceBefore,
                    balanceAfter,
                    txRow.provider ?? 'mtn',
                    `Paystack top-up • ref ${reference}`,
                ],
            );

            newBalance = balanceAfter;
        }

        /* ==================================================================
         * DIRECT RIDE PAYMENT
         * ================================================================== */
        else if (txRow.purpose === 'ride_payment') {
            const rideResult = await client.query(
                `
                SELECT
                    r.id,
                    r.passenger_id,
                    r.driver_id,
                    r.fare,
                    r.payment_status,
                    r.pickup_address,
                    r.destination_address
                FROM public.rides r
                WHERE r.id = $1::integer
                LIMIT 1
                FOR UPDATE
                `,
                [txRow.ride_id],
            );

            if (rideResult.rows.length === 0) {
                throw new Error(
                    `Ride ${txRow.ride_id} not found for ref ${reference}`,
                );
            }

            const ride = rideResult.rows[0];

            if (ride.payment_status === 'paid') {
                await client.query(
                    `
                    UPDATE public.paystack_transactions
                    SET applied         = TRUE,
                        status          = 'success',
                        paystack_verify = $1::jsonb,
                        completed_at    = NOW(),
                        updated_at      = NOW()
                    WHERE reference = $2
                    `,
                    [payloadJson, reference],
                );

                await client.query('COMMIT');
                console.log(
                    `ℹ️ applySuccessfulPayment: ride ${ride.id} already paid, ` +
                    `ref ${reference} marked applied.`,
                );
                return {
                    applied: true,
                    alreadyApplied: true,
                    purpose: txRow.purpose,
                    newBalance: null,
                };
            }

            const fare = Number(ride.fare) || expectedGHS;
            const commission = Math.min(FLAT_COMMISSION, fare);
            const driverEarnings = Math.max(0, fare - commission);

            /* Credit driver wallet if we can resolve it. */
            if (ride.driver_id) {
                const driverLookup = await client.query(
                    `
                    SELECT id
                    FROM public.drivers
                    WHERE uid = $1::text
                    LIMIT 1
                    `,
                    [ride.driver_id],
                );

                const driverNumericId = driverLookup.rows[0]?.id;

                if (driverNumericId) {
                    const driverWallet = await client.query(
                        `
                        SELECT id, balance
                        FROM public.driver_wallets
                        WHERE driver_id = $1
                        LIMIT 1
                        FOR UPDATE
                        `,
                        [driverNumericId],
                    );

                    if (driverWallet.rows.length > 0) {
                        const dwId = driverWallet.rows[0].id;
                        const dwBefore =
                            Number(driverWallet.rows[0].balance) || 0;
                        const dwAfter = dwBefore + driverEarnings;

                        await client.query(
                            `
                            UPDATE public.driver_wallets
                            SET balance             = $1::numeric,
                                last_transaction_at = NOW(),
                                updated_at          = NOW()
                            WHERE id = $2
                            `,
                            [dwAfter, dwId],
                        );

                        await client.query(
                            `
                            INSERT INTO public.driver_transactions (
                                driver_id,
                                wallet_id,
                                ride_id,
                                amount,
                                type,
                                status,
                                balance_before,
                                balance_after,
                                transaction_reference,
                                description,
                                metadata,
                                created_at,
                                updated_at
                            )
                            VALUES (
                                $1::bigint,
                                $2::bigint,
                                $3::integer,
                                $4::numeric,
                                'ride_earning',
                                'completed',
                                $5::numeric,
                                $6::numeric,
                                'PAYSTACK-' || $3 || '-' ||
                                    extract(epoch from now())::bigint,
                                $7::text,
                                $8::jsonb,
                                NOW(),
                                NOW()
                            )
                            `,
                            [
                                driverNumericId,
                                dwId,
                                ride.id,
                                driverEarnings,
                                dwBefore,
                                dwAfter,
                                `Earnings from ride #${ride.id}`,
                                JSON.stringify({
                                    ride_id: ride.id,
                                    passenger_id: ride.passenger_id,
                                    source: 'paystack',
                                }),
                            ],
                        );
                    }
                }
            }

            await client.query(
                `
                UPDATE public.rides
                SET payment_status     = 'paid',
                    driver_earnings    = $1::numeric,
                    tegaara_commission = $2::numeric,
                    paid_at            = NOW()
                WHERE id = $3::integer
                `,
                [driverEarnings, commission, ride.id],
            );

            const walletLookup = await client.query(
                `
                SELECT id, balance
                FROM public.wallets
                WHERE passenger_id = $1
                LIMIT 1
                `,
                [ride.passenger_id],
            );

            if (walletLookup.rows.length > 0) {
                const wId = walletLookup.rows[0].id;
                const wBal =
                    Number(walletLookup.rows[0].balance) || 0;

                await client.query(
                    `
                    INSERT INTO public.transactions (
                        wallet_id,
                        passenger_id,
                        ride_id,
                        type,
                        amount,
                        balance_before,
                        balance_after,
                        status,
                        payment_method,
                        description,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        $1::bigint,
                        $2::integer,
                        $3::integer,
                        'ride_payment',
                        $4::numeric,
                        $5::numeric,
                        $5::numeric,
                        'completed',
                        'paystack_momo',
                        $6::text,
                        NOW(),
                        NOW()
                    )
                    `,
                    [
                        wId,
                        ride.passenger_id,
                        ride.id,
                        fare,
                        wBal,
                        `MoMo payment for ride #${ride.id}`,
                    ],
                );
            }
        }

        await client.query(
            `
            UPDATE public.paystack_transactions
            SET applied         = TRUE,
                status          = 'success',
                paystack_verify = $1::jsonb,
                completed_at    = NOW(),
                updated_at      = NOW()
            WHERE reference = $2
            `,
            [payloadJson, reference],
        );

        await client.query('COMMIT');
        console.log(
            `✅ applySuccessfulPayment OK: ref=${reference} ` +
            `purpose=${txRow.purpose} balance=${newBalance ?? 'n/a'}`,
        );

        return {
            applied: true,
            alreadyApplied: false,
            purpose: txRow.purpose,
            newBalance,
        };
    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch (_) {
            /* ignore */
        }
        console.error(
            `❌ applySuccessfulPayment failed (ref=${reference}):`,
            error,
        );
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
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        try {
            const passengerResult = await pool.query(
                `
                SELECT id
                FROM public.passengers
                WHERE firebase_uid = $1::text
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger profile not found.',
                });
            }

            const passengerId = passengerResult.rows[0].id;

            const walletResult = await pool.query(
                `
                SELECT
                    id,
                    passenger_id,
                    balance,
                    pending_balance      AS "pendingBalance",
                    total_spent          AS "totalSpent",
                    last_transaction_at  AS "lastTransactionAt",
                    created_at           AS "createdAt",
                    updated_at           AS "updatedAt"
                FROM public.wallets
                WHERE passenger_id = $1
                LIMIT 1
                `,
                [passengerId],
            );

            if (walletResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Wallet not found.',
                });
            }

            const w = walletResult.rows[0];

            return res.status(200).json({
                success: true,
                wallet: {
                    id: w.id,
                    passengerId: w.passenger_id,
                    balance: Number(w.balance) || 0,
                    pendingBalance: Number(w.pendingBalance) || 0,
                    totalSpent: Number(w.totalSpent) || 0,
                    currency: 'GHS',
                    isActive: true,
                    lastTransactionAt: w.lastTransactionAt,
                    createdAt: w.createdAt,
                    updatedAt: w.updatedAt,
                },
            });
        } catch (error) {
            console.error('❌ GET /passengers/wallet failed:', error);
            return res.status(500).json({
                success: false,
                message: 'Failed to load wallet.',
            });
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
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        try {
            const passengerResult = await pool.query(
                `
                SELECT id
                FROM public.passengers
                WHERE firebase_uid = $1::text
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger profile not found.',
                });
            }

            const passengerId = passengerResult.rows[0].id;

            const existing = await pool.query(
                `
                SELECT
                    id,
                    passenger_id,
                    balance,
                    pending_balance      AS "pendingBalance",
                    total_spent          AS "totalSpent",
                    last_transaction_at  AS "lastTransactionAt",
                    created_at           AS "createdAt",
                    updated_at           AS "updatedAt"
                FROM public.wallets
                WHERE passenger_id = $1
                LIMIT 1
                `,
                [passengerId],
            );

            if (existing.rows.length > 0) {
                const w = existing.rows[0];
                return res.status(200).json({
                    success: true,
                    wallet: {
                        id: w.id,
                        passengerId: w.passenger_id,
                        balance: Number(w.balance) || 0,
                        pendingBalance: Number(w.pendingBalance) || 0,
                        totalSpent: Number(w.totalSpent) || 0,
                        currency: 'GHS',
                        isActive: true,
                        lastTransactionAt: w.lastTransactionAt,
                        createdAt: w.createdAt,
                        updatedAt: w.updatedAt,
                    },
                    message: 'Wallet already exists.',
                });
            }

            const insert = await pool.query(
                `
                INSERT INTO public.wallets (
                    passenger_id,
                    balance,
                    pending_balance,
                    total_spent,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1::integer,
                    0.00,
                    0.00,
                    0.00,
                    NOW(),
                    NOW()
                )
                RETURNING
                    id,
                    passenger_id,
                    balance,
                    pending_balance      AS "pendingBalance",
                    total_spent          AS "totalSpent",
                    last_transaction_at  AS "lastTransactionAt",
                    created_at           AS "createdAt",
                    updated_at           AS "updatedAt"
                `,
                [passengerId],
            );

            const w = insert.rows[0];

            return res.status(201).json({
                success: true,
                wallet: {
                    id: w.id,
                    passengerId: w.passenger_id,
                    balance: Number(w.balance) || 0,
                    pendingBalance: Number(w.pendingBalance) || 0,
                    totalSpent: Number(w.totalSpent) || 0,
                    currency: 'GHS',
                    isActive: true,
                    lastTransactionAt: w.lastTransactionAt,
                    createdAt: w.createdAt,
                    updatedAt: w.updatedAt,
                },
                message: 'Wallet created successfully.',
            });
        } catch (error: any) {
            console.error(
                '❌ POST /passengers/wallet failed:',
                error?.code,
                error?.message,
                error?.detail,
            );
            return res.status(500).json({
                success: false,
                message: 'Failed to create wallet.',
            });
        }
    },
);

/* ==========================================================================
 * GET /passengers/wallet/pending-payment-ride
 * ========================================================================== */

router.get(
    '/passengers/wallet/pending-payment-ride',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        try {
            const passengerResult = await pool.query(
                `
                SELECT id
                FROM public.passengers
                WHERE firebase_uid = $1::text
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger profile not found.',
                });
            }

            const passengerId = passengerResult.rows[0].id;

            const rideResult = await pool.query(
                `
                SELECT
                    r.id                   AS ride_id,
                    r.fare                 AS amount,
                    r.completed_at,
                    d.uid                  AS driver_id,
                    d.full_name            AS driver_name,
                    d.profile_photo_url    AS driver_photo_url,
                    d.vehicle_type,
                    d.vehicle_model,
                    d.vehicle_color,
                    d.registration_number  AS vehicle_registration,
                    d.vehicle_year
                FROM public.rides r
                LEFT JOIN public.drivers d
                    ON d.uid = r.driver_id
                WHERE r.passenger_id = $1::integer
                  AND r.status = 'completed'
                  AND (r.payment_status IS NULL
                       OR r.payment_status <> 'paid')
                  AND r.driver_id IS NOT NULL
                ORDER BY r.completed_at DESC NULLS LAST, r.id DESC
                LIMIT 1
                `,
                [passengerId],
            );

            if (rideResult.rows.length === 0) {
                return res.status(200).json({
                    success: true,
                    ride: null,
                });
            }

            return res.status(200).json({
                success: true,
                ride: rideResult.rows[0],
            });
        } catch (error) {
            console.error(
                '❌ GET /passengers/wallet/pending-payment-ride failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message: 'Failed to load pending payment ride.',
            });
        }
    },
);

/* ==========================================================================
 * POST /passengers/wallet/topup  (legacy — direct wallet credit)
 * ========================================================================== */

router.post(
    '/passengers/wallet/topup',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        const amount = Number(req.body?.amount);
        const paymentMethod =
            typeof req.body?.payment_method === 'string'
                ? req.body.payment_method.trim()
                : 'Mobile Money';
        const provider =
            typeof req.body?.provider === 'string'
                ? req.body.provider.trim()
                : 'MTN';

        if (!Number.isFinite(amount) || amount <= 0) {
            return res.status(400).json({
                success: false,
                message: 'A valid amount is required.',
            });
        }

        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const passengerResult = await client.query(
                `
                SELECT id
                FROM public.passengers
                WHERE firebase_uid = $1::text
                LIMIT 1
                FOR UPDATE
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({
                    success: false,
                    message: 'Passenger profile not found.',
                });
            }

            const passengerId = passengerResult.rows[0].id;

            const walletResult = await client.query(
                `
                SELECT id, balance
                FROM public.wallets
                WHERE passenger_id = $1
                LIMIT 1
                FOR UPDATE
                `,
                [passengerId],
            );

            if (walletResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({
                    success: false,
                    message:
                        'Wallet not found. Please create a wallet first.',
                });
            }

            const walletId = walletResult.rows[0].id;
            const balanceBefore =
                Number(walletResult.rows[0].balance) || 0;
            const balanceAfter = balanceBefore + amount;

            await client.query(
                `
                UPDATE public.wallets
                SET
                    balance             = $1::numeric,
                    last_transaction_at = NOW(),
                    updated_at          = NOW()
                WHERE id = $2
                `,
                [balanceAfter, walletId],
            );

            await client.query(
                `
                INSERT INTO public.transactions (
                    wallet_id,
                    passenger_id,
                    type,
                    amount,
                    balance_before,
                    balance_after,
                    status,
                    payment_method,
                    provider,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1::bigint,
                    $2::integer,
                    'topup',
                    $3::numeric,
                    $4::numeric,
                    $5::numeric,
                    'completed',
                    $6::varchar,
                    $7::varchar,
                    NOW(),
                    NOW()
                )
                `,
                [
                    walletId,
                    passengerId,
                    amount,
                    balanceBefore,
                    balanceAfter,
                    paymentMethod,
                    provider,
                ],
            );

            await client.query('COMMIT');

            return res.status(200).json({
                success: true,
                message: 'Top-up successful.',
                newBalance: balanceAfter,
            });
        } catch (error) {
            try {
                await client.query('ROLLBACK');
            } catch (_) { }
            console.error(
                '❌ POST /passengers/wallet/topup failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message: 'Failed to process top-up.',
            });
        } finally {
            client.release();
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
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        const page = Math.max(
            parseInt(String(req.query.page ?? '1'), 10) || 1,
            1,
        );
        const limit = Math.min(
            Math.max(
                parseInt(String(req.query.limit ?? '20'), 10) || 20,
                1,
            ),
            100,
        );
        const offset = (page - 1) * limit;

        try {
            const passengerResult = await pool.query(
                `
                SELECT id
                FROM public.passengers
                WHERE firebase_uid = $1::text
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger profile not found.',
                });
            }

            const passengerId = passengerResult.rows[0].id;

            const result = await pool.query(
                `
                SELECT
                    t.id,
                    t.wallet_id,
                    t.ride_id,
                    t.type,
                    t.amount,
                    t.balance_before,
                    t.balance_after,
                    t.status,
                    t.payment_method,
                    t.provider,
                    t.created_at
                FROM public.transactions t
                WHERE t.passenger_id = $1::integer
                ORDER BY t.created_at DESC, t.id DESC
                LIMIT $2 OFFSET $3
                `,
                [passengerId, limit, offset],
            );

            return res.status(200).json({
                success: true,
                transactions: result.rows,
            });
        } catch (error) {
            console.error(
                '❌ GET /passengers/transactions failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message: 'Failed to load transactions.',
            });
        }
    },
);

/* ==========================================================================
 * POST /passengers/wallet/pay  (legacy — wallet-balance payment)
 * ========================================================================== */

router.post(
    '/passengers/wallet/pay',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        const rideId = Number(req.body?.ride_id);
        const amountInput = Number(req.body?.amount);

        if (!Number.isInteger(rideId) || rideId <= 0) {
            return res.status(400).json({
                success: false,
                message: 'A valid ride_id is required.',
            });
        }
        if (!Number.isFinite(amountInput) || amountInput <= 0) {
            return res.status(400).json({
                success: false,
                message: 'A valid amount is required.',
            });
        }

        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            const passengerResult = await client.query(
                `
                SELECT id, full_name
                FROM public.passengers
                WHERE firebase_uid = $1::text
                LIMIT 1
                FOR UPDATE
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({
                    success: false,
                    message: 'Passenger profile not found.',
                });
            }

            const passengerId = passengerResult.rows[0].id;
            const passengerName =
                passengerResult.rows[0].full_name || 'Passenger';

            const rideResult = await client.query(
                `
                SELECT
                    r.id                    AS ride_id,
                    r.passenger_id,
                    r.driver_id,
                    r.fare,
                    r.payment_status,
                    r.pickup_address,
                    r.destination_address
                FROM public.rides r
                WHERE r.id = $1::integer
                  AND r.passenger_id = $2::integer
                LIMIT 1
                FOR UPDATE OF r
                `,
                [rideId, passengerId],
            );

            if (rideResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({
                    success: false,
                    message: 'Ride not found or does not belong to you.',
                });
            }

            const rideInfo = rideResult.rows[0];

            if (rideInfo.payment_status === 'paid') {
                await client.query('ROLLBACK');
                return res.status(200).json({
                    success: true,
                    alreadyPaid: true,
                    message: 'Ride already paid.',
                });
            }

            if (!rideInfo.driver_id) {
                await client.query('ROLLBACK');
                return res.status(400).json({
                    success: false,
                    message: 'Ride has no assigned driver.',
                });
            }

            const fare = Number(rideInfo.fare) || 0;
            const amount = fare > 0 ? fare : amountInput;
            const commission = Math.min(FLAT_COMMISSION, amount);
            const driverEarnings = Math.max(0, amount - commission);

            const passengerWalletResult = await client.query(
                `
                SELECT id, balance
                FROM public.wallets
                WHERE passenger_id = $1
                LIMIT 1
                FOR UPDATE
                `,
                [passengerId],
            );

            if (passengerWalletResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({
                    success: false,
                    message:
                        'Wallet not found. Please create a wallet first.',
                });
            }

            const passengerWalletId =
                passengerWalletResult.rows[0].id;
            const passengerBalanceBefore =
                Number(passengerWalletResult.rows[0].balance) || 0;

            if (passengerBalanceBefore < amount) {
                await client.query('ROLLBACK');
                return res.status(402).json({
                    success: false,
                    code: 'INSUFFICIENT_WALLET_BALANCE',
                    message:
                        `Insufficient balance. You have ` +
                        `GH₵${passengerBalanceBefore.toFixed(2)} but need ` +
                        `GH₵${amount.toFixed(2)}.`,
                    balance: passengerBalanceBefore,
                    required: amount,
                });
            }

            const passengerBalanceAfter =
                passengerBalanceBefore - amount;

            await client.query(
                `
                UPDATE public.wallets
                SET
                    balance             = $1::numeric,
                    total_spent         = COALESCE(total_spent, 0) + $2::numeric,
                    last_transaction_at = NOW(),
                    updated_at          = NOW()
                WHERE id = $3
                `,
                [passengerBalanceAfter, amount, passengerWalletId],
            );

            const driverResult = await client.query(
                `
                SELECT id
                FROM public.drivers
                WHERE uid = $1::text
                LIMIT 1
                `,
                [rideInfo.driver_id],
            );

            let newDriverBalance: number | null = null;

            if (driverResult.rows.length > 0) {
                const driverNumericId = driverResult.rows[0].id;

                const driverWalletResult = await client.query(
                    `
                    SELECT id, balance
                    FROM public.driver_wallets
                    WHERE driver_id = $1
                    LIMIT 1
                    FOR UPDATE
                    `,
                    [driverNumericId],
                );

                if (driverWalletResult.rows.length > 0) {
                    const driverWalletId =
                        driverWalletResult.rows[0].id;
                    const driverBalanceBefore =
                        Number(driverWalletResult.rows[0].balance) || 0;

                    newDriverBalance =
                        driverBalanceBefore + driverEarnings;

                    await client.query(
                        `
                        UPDATE public.driver_wallets
                        SET
                            balance             = $1::numeric,
                            last_transaction_at = NOW(),
                            updated_at          = NOW()
                        WHERE id = $2
                        `,
                        [newDriverBalance, driverWalletId],
                    );

                    await client.query(
                        `
                        INSERT INTO public.driver_transactions (
                            driver_id,
                            wallet_id,
                            ride_id,
                            amount,
                            type,
                            status,
                            balance_before,
                            balance_after,
                            transaction_reference,
                            description,
                            metadata,
                            created_at,
                            updated_at
                        )
                        VALUES (
                            $1::bigint,
                            $2::bigint,
                            $3::integer,
                            $4::numeric,
                            'ride_earning',
                            'completed',
                            $5::numeric,
                            $6::numeric,
                            'WALLET-' || $3 || '-' ||
                                extract(epoch from now())::bigint,
                            $7::text,
                            $8::jsonb,
                            NOW(),
                            NOW()
                        )
                        `,
                        [
                            driverNumericId,
                            driverWalletId,
                            rideId,
                            driverEarnings,
                            driverBalanceBefore,
                            newDriverBalance,
                            `Earnings from ride #${rideId}`,
                            JSON.stringify({
                                ride_id: rideId,
                                passenger_id: passengerId,
                                source: 'wallet',
                            }),
                        ],
                    );
                }
            }

            await client.query(
                `
                INSERT INTO public.transactions (
                    wallet_id,
                    passenger_id,
                    ride_id,
                    type,
                    amount,
                    balance_before,
                    balance_after,
                    status,
                    payment_method,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1::bigint,
                    $2::integer,
                    $3::integer,
                    'ride_payment',
                    $4::numeric,
                    $5::numeric,
                    $6::numeric,
                    'completed',
                    'wallet',
                    $7::text,
                    NOW(),
                    NOW()
                )
                `,
                [
                    passengerWalletId,
                    passengerId,
                    rideId,
                    amount,
                    passengerBalanceBefore,
                    passengerBalanceAfter,
                    `Payment for ride #${rideId}`,
                ],
            );

            await client.query(
                `
                UPDATE public.rides
                SET
                    payment_status     = 'paid',
                    driver_earnings    = $1::numeric,
                    tegaara_commission = $2::numeric,
                    paid_at            = NOW()
                WHERE id = $3::integer
                `,
                [driverEarnings, commission, rideId],
            );

            await client.query('COMMIT');

            console.log(
                `✅ Ride ${rideId} paid by passenger ${uid}. ` +
                `fare=${amount.toFixed(2)} ` +
                `driverEarnings=${driverEarnings.toFixed(2)} ` +
                `commission=${commission.toFixed(2)}`,
            );

            void notifyDriverPaymentReceived(
                rideInfo.driver_id,
                rideInfo.ride_id,
                fare > 0 ? fare : amount,
                driverEarnings,
                commission,
                newDriverBalance,
                passengerName,
                rideInfo.pickup_address ?? '',
                rideInfo.destination_address ?? '',
            );

            return res.status(200).json({
                success: true,
                rideId,
                paymentStatus: 'paid',
                amount,
                driverEarnings,
                tegaaraCommission: commission,
                newPassengerBalance: passengerBalanceAfter,
                newDriverBalance,
                message: 'Payment processed successfully.',
            });
        } catch (error: any) {
            try {
                await client.query('ROLLBACK');
            } catch (_) { }
            console.error(
                '❌ POST /passengers/wallet/pay failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message: 'Failed to process payment.',
                code: error?.code ?? 'PAYMENT_FAILED',
                detail: error?.detail ?? null,
            });
        } finally {
            client.release();
        }
    },
);

/* ==========================================================================
 * PAYSTACK: INITIALIZE WALLET TOP-UP
 * ========================================================================== */

router.post(
    '/passengers/wallet/topup/initialize',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        const amount = Number(req.body?.amount);
        const phone = String(req.body?.phone ?? '').trim();
        const provider = String(req.body?.provider ?? '')
            .trim()
            .toLowerCase() as PaystackProvider;

        if (!Number.isFinite(amount) || amount <= 0) {
            return res.status(400).json({
                success: false,
                message: 'A valid amount is required.',
            });
        }
        if (!['mtn', 'vod', 'atl'].includes(provider)) {
            return res.status(400).json({
                success: false,
                message: 'Unsupported mobile money provider.',
            });
        }
        if (phone.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'A valid phone number is required.',
            });
        }

        try {
            const passengerResult = await pool.query(
                `
                SELECT p.id AS passenger_id,
                       p.full_name,
                       p.email,
                       w.id AS wallet_id
                FROM public.passengers p
                LEFT JOIN public.wallets w
                    ON w.passenger_id = p.id
                WHERE p.firebase_uid = $1::text
                LIMIT 1
                `,
                [uid],
            );

            if (passengerResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Passenger profile not found.',
                });
            }

            const p = passengerResult.rows[0];

            if (!p.wallet_id) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Wallet not found. Please create a wallet first.',
                });
            }

            const email =
                (req.decodedToken as any)?.email ||
                p.email ||
                `passenger+${uid.slice(0, 8)}@tegaara.app`;

            const reference = generateReference('topup', uid);

            await pool.query(
                `
                INSERT INTO public.paystack_transactions (
                    reference,
                    user_firebase_uid,
                    purpose,
                    amount,
                    status,
                    channel,
                    provider,
                    phone,
                    passenger_id,
                    wallet_id
                )
                VALUES (
                    $1, $2, 'wallet_topup',
                    $3::numeric, 'pending', 'mobile_money',
                    $4::varchar, $5::varchar,
                    $6::integer, $7::bigint
                )
                `,
                [
                    reference,
                    uid,
                    amount,
                    provider,
                    phone,
                    p.passenger_id,
                    p.wallet_id,
                ],
            );

            const chargeResult = await initializeMobileMoneyCharge({
                email,
                amountGHS: amount,
                phone,
                provider,
                reference,
                metadata: {
                    purpose: 'wallet_topup',
                    userFirebaseUid: uid,
                    passengerId: p.passenger_id,
                    walletId: p.wallet_id,
                },
            });

            await pool.query(
                `
                UPDATE public.paystack_transactions
                SET status         = $1,
                    paystack_init  = $2::jsonb,
                    updated_at     = NOW()
                WHERE reference = $3
                `,
                [
                    chargeResult.status,
                    JSON.stringify(chargeResult.raw),
                    reference,
                ],
            );

            return res.status(200).json({
                success: true,
                reference: chargeResult.reference,
                status: chargeResult.status,
                displayText: chargeResult.displayText,
                amount,
                phone,
                provider,
                message:
                    'Check your phone and approve the mobile money prompt.',
            });
        } catch (error: any) {
            console.error(
                '❌ POST /passengers/wallet/topup/initialize failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message:
                    error?.message ??
                    'Failed to initiate mobile money charge.',
            });
        }
    },
);

/* ==========================================================================
 * PAYSTACK: SUBMIT OTP FOR WALLET TOP-UP
 * ========================================================================== */

router.post(
    '/passengers/wallet/topup/submit-otp',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        const reference = String(req.body?.reference ?? '').trim();
        const otp = String(req.body?.otp ?? '').trim();

        if (!reference) {
            return res.status(400).json({
                success: false,
                message: 'Reference is required.',
            });
        }
        if (!otp) {
            return res.status(400).json({
                success: false,
                message: 'OTP is required.',
            });
        }

        try {
            const txResult = await pool.query(
                `
                SELECT *
                FROM public.paystack_transactions
                WHERE reference = $1
                  AND user_firebase_uid = $2
                  AND purpose = 'wallet_topup'
                LIMIT 1
                `,
                [reference, uid],
            );

            if (txResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Top-up not found.',
                });
            }

            const tx = txResult.rows[0];

            if (tx.applied === true) {
                const walletResult = await pool.query(
                    `
                    SELECT balance
                    FROM public.wallets
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [tx.wallet_id],
                );
                return res.status(200).json({
                    success: true,
                    status: 'success',
                    alreadyApplied: true,
                    newBalance: walletResult.rows[0]
                        ? Number(walletResult.rows[0].balance) || 0
                        : null,
                });
            }

            let submitResult;
            try {
                submitResult = await submitOtp({ reference, otp });
            } catch (otpErr: any) {
                return res.status(200).json({
                    success: true,
                    status: 'send_otp',
                    message:
                        otpErr?.message ??
                        'Incorrect code. Please try again.',
                });
            }

            await pool.query(
                `
                UPDATE public.paystack_transactions
                SET status          = $1,
                    paystack_verify = $2::jsonb,
                    updated_at      = NOW()
                WHERE reference = $3
                `,
                [
                    submitResult.status,
                    JSON.stringify(submitResult.raw),
                    reference,
                ],
            );

            if (submitResult.status === 'success') {
                const applied = await applySuccessfulPayment(
                    reference,
                    submitResult.raw?.data ?? submitResult.raw ?? {},
                );
                const walletResult = await pool.query(
                    `
                    SELECT balance
                    FROM public.wallets
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [tx.wallet_id],
                );
                return res.status(200).json({
                    success: true,
                    status: 'success',
                    alreadyApplied: applied.alreadyApplied,
                    newBalance: walletResult.rows[0]
                        ? Number(walletResult.rows[0].balance) || 0
                        : null,
                });
            }

            if (submitResult.status === 'send_otp') {
                return res.status(200).json({
                    success: true,
                    status: 'send_otp',
                    message:
                        submitResult.displayText ||
                        'Incorrect or expired code. Please try again.',
                });
            }

            if (
                submitResult.status === 'failed' ||
                submitResult.status === 'reversed'
            ) {
                return res.status(200).json({
                    success: false,
                    status: 'failed',
                    message:
                        submitResult.displayText ||
                        'OTP verification failed.',
                });
            }

            return res.status(200).json({
                success: true,
                status: submitResult.status || 'pay_offline',
                message:
                    submitResult.displayText ||
                    'Now enter your MoMo PIN on your phone to confirm.',
            });
        } catch (error: any) {
            console.error(
                '❌ POST /passengers/wallet/topup/submit-otp failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message: error?.message ?? 'Failed to submit OTP.',
            });
        }
    },
);

/* ==========================================================================
 * PAYSTACK: VERIFY WALLET TOP-UP
 * ========================================================================== */

router.get(
    '/passengers/wallet/topup/verify/:reference',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        const reference = String(req.params.reference ?? '').trim();
        if (!reference) {
            return res.status(400).json({
                success: false,
                message: 'Reference is required.',
            });
        }

        try {
            const txResult = await pool.query(
                `
                SELECT *
                FROM public.paystack_transactions
                WHERE reference = $1
                  AND user_firebase_uid = $2
                  AND purpose = 'wallet_topup'
                LIMIT 1
                `,
                [reference, uid],
            );

            if (txResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Top-up not found.',
                });
            }

            const tx = txResult.rows[0];

            if (tx.applied === true) {
                const walletResult = await pool.query(
                    `
                    SELECT balance
                    FROM public.wallets
                    WHERE id = $1
                    LIMIT 1
                    `,
                    [tx.wallet_id],
                );
                return res.status(200).json({
                    success: true,
                    status: 'success',
                    alreadyApplied: true,
                    newBalance: walletResult.rows[0]
                        ? Number(walletResult.rows[0].balance) || 0
                        : null,
                });
            }

            let verifyData;
            try {
                verifyData = await verifyTransaction(reference);
            } catch (err: any) {
                return res.status(200).json({
                    success: true,
                    status: 'pending',
                    message:
                        err?.message ??
                        'Waiting for confirmation from Paystack.',
                });
            }

            if (verifyData.status === 'success') {
                const result = await applySuccessfulPayment(
                    reference,
                    verifyData.raw?.data ?? verifyData.raw ?? {},
                );
                return res.status(200).json({
                    success: true,
                    status: 'success',
                    alreadyApplied: result.alreadyApplied,
                    newBalance: result.newBalance,
                });
            }

            if (
                verifyData.status === 'failed' ||
                verifyData.status === 'reversed'
            ) {
                await pool.query(
                    `
                    UPDATE public.paystack_transactions
                    SET status          = 'failed',
                        paystack_verify = $1::jsonb,
                        updated_at      = NOW()
                    WHERE reference = $2
                    `,
                    [JSON.stringify(verifyData.raw), reference],
                );
                return res.status(200).json({
                    success: false,
                    status: 'failed',
                    message:
                        'The mobile money charge was not successful.',
                });
            }

            return res.status(200).json({
                success: true,
                status: 'pending',
                message: 'Awaiting approval on your phone.',
            });
        } catch (error: any) {
            console.error(
                '❌ GET /passengers/wallet/topup/verify failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message:
                    'Failed to verify top-up. Please try again.',
            });
        }
    },
);

/* ==========================================================================
 * PAYSTACK: INITIALIZE DIRECT RIDE PAYMENT
 * ========================================================================== */

router.post(
    '/passengers/wallet/pay/initialize',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        const rideId = Number(req.body?.ride_id);
        const phone = String(req.body?.phone ?? '').trim();
        const provider = String(req.body?.provider ?? '')
            .trim()
            .toLowerCase() as PaystackProvider;

        if (!Number.isInteger(rideId) || rideId <= 0) {
            return res.status(400).json({
                success: false,
                message: 'A valid ride_id is required.',
            });
        }
        if (!['mtn', 'vod', 'atl'].includes(provider)) {
            return res.status(400).json({
                success: false,
                message: 'Unsupported mobile money provider.',
            });
        }
        if (phone.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'A valid phone number is required.',
            });
        }

        try {
            const result = await pool.query(
                `
                SELECT
                    r.id,
                    r.fare,
                    r.payment_status,
                    r.driver_id,
                    p.id AS passenger_id,
                    p.email
                FROM public.rides r
                INNER JOIN public.passengers p
                    ON p.id = r.passenger_id
                WHERE r.id = $1::integer
                  AND p.firebase_uid = $2::text
                LIMIT 1
                `,
                [rideId, uid],
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message:
                        'Ride not found or does not belong to you.',
                });
            }

            const ride = result.rows[0];

            if (ride.payment_status === 'paid') {
                return res.status(200).json({
                    success: true,
                    alreadyPaid: true,
                    message: 'Ride already paid.',
                });
            }

            const fare = Number(ride.fare) || 0;
            if (fare <= 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Ride has no fare on record.',
                });
            }

            const email =
                (req.decodedToken as any)?.email ||
                ride.email ||
                `passenger+${uid.slice(0, 8)}@tegaara.app`;

            const reference = generateReference('ride', uid);

            await pool.query(
                `
                INSERT INTO public.paystack_transactions (
                    reference,
                    user_firebase_uid,
                    purpose,
                    amount,
                    status,
                    channel,
                    provider,
                    phone,
                    passenger_id,
                    ride_id
                )
                VALUES (
                    $1, $2, 'ride_payment',
                    $3::numeric, 'pending', 'mobile_money',
                    $4::varchar, $5::varchar,
                    $6::integer, $7::integer
                )
                `,
                [
                    reference,
                    uid,
                    fare,
                    provider,
                    phone,
                    ride.passenger_id,
                    rideId,
                ],
            );

            const chargeResult = await initializeMobileMoneyCharge({
                email,
                amountGHS: fare,
                phone,
                provider,
                reference,
                metadata: {
                    purpose: 'ride_payment',
                    rideId,
                    userFirebaseUid: uid,
                    passengerId: ride.passenger_id,
                },
            });

            await pool.query(
                `
                UPDATE public.paystack_transactions
                SET status        = $1,
                    paystack_init = $2::jsonb,
                    updated_at    = NOW()
                WHERE reference = $3
                `,
                [
                    chargeResult.status,
                    JSON.stringify(chargeResult.raw),
                    reference,
                ],
            );

            return res.status(200).json({
                success: true,
                reference: chargeResult.reference,
                status: chargeResult.status,
                displayText: chargeResult.displayText,
                amount: fare,
                rideId,
                message:
                    'Check your phone and approve the mobile money prompt.',
            });
        } catch (error: any) {
            console.error(
                '❌ POST /passengers/wallet/pay/initialize failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message:
                    error?.message ??
                    'Failed to initiate mobile money charge.',
            });
        }
    },
);

/* ==========================================================================
 * PAYSTACK: SUBMIT OTP FOR DIRECT RIDE PAYMENT
 * ========================================================================== */

router.post(
    '/passengers/wallet/pay/submit-otp',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        const reference = String(req.body?.reference ?? '').trim();
        const otp = String(req.body?.otp ?? '').trim();

        if (!reference) {
            return res.status(400).json({
                success: false,
                message: 'Reference is required.',
            });
        }
        if (!otp) {
            return res.status(400).json({
                success: false,
                message: 'OTP is required.',
            });
        }

        try {
            const txResult = await pool.query(
                `
                SELECT *
                FROM public.paystack_transactions
                WHERE reference = $1
                  AND user_firebase_uid = $2
                  AND purpose = 'ride_payment'
                LIMIT 1
                `,
                [reference, uid],
            );

            if (txResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Payment not found.',
                });
            }

            const tx = txResult.rows[0];

            if (tx.applied === true) {
                return res.status(200).json({
                    success: true,
                    status: 'success',
                    alreadyApplied: true,
                    rideId: tx.ride_id,
                });
            }

            let submitResult;
            try {
                submitResult = await submitOtp({ reference, otp });
            } catch (otpErr: any) {
                return res.status(200).json({
                    success: true,
                    status: 'send_otp',
                    message:
                        otpErr?.message ??
                        'Incorrect code. Please try again.',
                });
            }

            await pool.query(
                `
                UPDATE public.paystack_transactions
                SET status          = $1,
                    paystack_verify = $2::jsonb,
                    updated_at      = NOW()
                WHERE reference = $3
                `,
                [
                    submitResult.status,
                    JSON.stringify(submitResult.raw),
                    reference,
                ],
            );

            if (submitResult.status === 'success') {
                const applied = await applySuccessfulPayment(
                    reference,
                    submitResult.raw?.data ?? submitResult.raw ?? {},
                );
                return res.status(200).json({
                    success: true,
                    status: 'success',
                    alreadyApplied: applied.alreadyApplied,
                    rideId: tx.ride_id,
                });
            }

            if (submitResult.status === 'send_otp') {
                return res.status(200).json({
                    success: true,
                    status: 'send_otp',
                    message:
                        submitResult.displayText ||
                        'Incorrect or expired code. Please try again.',
                });
            }

            if (
                submitResult.status === 'failed' ||
                submitResult.status === 'reversed'
            ) {
                return res.status(200).json({
                    success: false,
                    status: 'failed',
                    message:
                        submitResult.displayText ||
                        'OTP verification failed.',
                });
            }

            return res.status(200).json({
                success: true,
                status: submitResult.status || 'pay_offline',
                message:
                    submitResult.displayText ||
                    'Now enter your MoMo PIN on your phone to confirm.',
            });
        } catch (error: any) {
            console.error(
                '❌ POST /passengers/wallet/pay/submit-otp failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message: error?.message ?? 'Failed to submit OTP.',
            });
        }
    },
);

/* ==========================================================================
 * PAYSTACK: VERIFY DIRECT RIDE PAYMENT
 * ========================================================================== */

router.get(
    '/passengers/wallet/pay/verify/:reference',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        const reference = String(req.params.reference ?? '').trim();
        if (!reference) {
            return res.status(400).json({
                success: false,
                message: 'Reference is required.',
            });
        }

        try {
            const txResult = await pool.query(
                `
                SELECT *
                FROM public.paystack_transactions
                WHERE reference = $1
                  AND user_firebase_uid = $2
                  AND purpose = 'ride_payment'
                LIMIT 1
                `,
                [reference, uid],
            );

            if (txResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Payment not found.',
                });
            }

            const tx = txResult.rows[0];

            if (tx.applied === true) {
                return res.status(200).json({
                    success: true,
                    status: 'success',
                    alreadyApplied: true,
                    rideId: tx.ride_id,
                });
            }

            let verifyData;
            try {
                verifyData = await verifyTransaction(reference);
            } catch (err: any) {
                return res.status(200).json({
                    success: true,
                    status: 'pending',
                    message:
                        err?.message ??
                        'Waiting for confirmation from Paystack.',
                });
            }

            if (verifyData.status === 'success') {
                const result = await applySuccessfulPayment(
                    reference,
                    verifyData.raw?.data ?? verifyData.raw ?? {},
                );
                return res.status(200).json({
                    success: true,
                    status: 'success',
                    alreadyApplied: result.alreadyApplied,
                    rideId: tx.ride_id,
                });
            }

            if (
                verifyData.status === 'failed' ||
                verifyData.status === 'reversed'
            ) {
                await pool.query(
                    `
                    UPDATE public.paystack_transactions
                    SET status          = 'failed',
                        paystack_verify = $1::jsonb,
                        updated_at      = NOW()
                    WHERE reference = $2
                    `,
                    [JSON.stringify(verifyData.raw), reference],
                );
                return res.status(200).json({
                    success: false,
                    status: 'failed',
                    message:
                        'The mobile money charge was not successful.',
                });
            }

            return res.status(200).json({
                success: true,
                status: 'pending',
                message: 'Awaiting approval on your phone.',
            });
        } catch (error: any) {
            console.error(
                '❌ GET /passengers/wallet/pay/verify failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message:
                    'Failed to verify ride payment. Please try again.',
            });
        }
    },
);

/* ==========================================================================
 * OTP PERSISTENCE — SAVE + FETCH
 *
 * These two routes let the Flutter app persist the OTP the user typed (or
 * that was autofilled from SMS) so it can be re-shown in the dialog on
 * reopen, and cleared automatically once the charge is applied.
 * ========================================================================== */

/* --------------------------------------------------------------------------
 * POST /passengers/wallet/otp/save
 *
 * Body: { reference: string, otp: string }
 *
 * Called by the Flutter app the moment a full 6-digit code lands in the
 * OTP field — whether the user typed it or the OS autofilled it.
 *
 * We only store it if:
 *   - The reference belongs to the caller (Firebase UID match).
 *   - The transaction has not yet been applied.
 * -------------------------------------------------------------------------- */
router.post(
    '/passengers/wallet/otp/save',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        const reference = String(req.body?.reference ?? '').trim();
        const otp = String(req.body?.otp ?? '').trim();

        if (!reference) {
            return res.status(400).json({
                success: false,
                message: 'reference is required.',
            });
        }
        if (!/^\d{4,8}$/.test(otp)) {
            return res.status(400).json({
                success: false,
                message: 'otp must be 4–8 digits.',
            });
        }

        try {
            const result = await pool.query(
                `
                UPDATE public.paystack_transactions
                   SET otp_code      = $1,
                       otp_saved_at  = NOW(),
                       updated_at    = NOW()
                 WHERE reference          = $2
                   AND user_firebase_uid  = $3
                   AND applied            = FALSE
                RETURNING id, reference, otp_code, otp_saved_at
                `,
                [otp, reference, uid],
            );

            if (result.rowCount === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Reference not found or already applied.',
                });
            }

            return res.status(200).json({
                success: true,
                reference: result.rows[0].reference,
                otp: result.rows[0].otp_code,
                savedAt: result.rows[0].otp_saved_at,
            });
        } catch (error: any) {
            console.error(
                '❌ POST /passengers/wallet/otp/save failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message: 'Failed to save OTP.',
            });
        }
    },
);

/* --------------------------------------------------------------------------
 * GET /passengers/wallet/otp/:reference
 *
 * Returns the last OTP stored for the caller's own pending reference.
 * The Flutter app uses this to pre-fill the OTP field when it re-opens
 * (e.g. after a wrong code, or after a rebuild).
 * -------------------------------------------------------------------------- */
router.get(
    '/passengers/wallet/otp/:reference',
    verifyFirebaseToken,
    async (req: AuthenticatedRequest, res: Response) => {
        const uid = getAuthenticatedUid(req);
        if (!uid) {
            return res.status(401).json({
                success: false,
                message: 'Unauthenticated.',
            });
        }

        const reference = String(req.params.reference ?? '').trim();
        if (!reference) {
            return res.status(400).json({
                success: false,
                message: 'reference is required.',
            });
        }

        try {
            const result = await pool.query(
                `
                SELECT otp_code, otp_saved_at
                  FROM public.paystack_transactions
                 WHERE reference         = $1
                   AND user_firebase_uid = $2
                 LIMIT 1
                `,
                [reference, uid],
            );

            if (result.rowCount === 0) {
                return res.status(200).json({
                    success: true,
                    otp: null,
                });
            }

            return res.status(200).json({
                success: true,
                otp: result.rows[0].otp_code ?? null,
                savedAt: result.rows[0].otp_saved_at ?? null,
            });
        } catch (error: any) {
            console.error(
                '❌ GET /passengers/wallet/otp/:reference failed:',
                error,
            );
            return res.status(500).json({
                success: false,
                message: 'Failed to fetch OTP.',
            });
        }
    },
);

export default router;
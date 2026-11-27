// routes/passengerWalletRoutes.ts

import { Router, Response } from 'express';

import pool from '../config/database';
import { firebaseMessaging } from '../config/firebase';
import {
    verifyFirebaseToken,
    AuthenticatedRequest,
} from '../middleware/firebaseAdmin';

const router = Router();

/* ==========================================================================
 * CONSTANTS
 * ========================================================================== */

const FLAT_COMMISSION = 2.0;

/* ==========================================================================
 * AUTH HELPER
 * ========================================================================== */

function getAuthenticatedUid(
    req: AuthenticatedRequest
): string | null {
    const uid = req.decodedToken?.uid;

    if (!uid || typeof uid !== 'string' || !uid.trim()) {
        return null;
    }

    return uid.trim();
}

/* ==========================================================================
 * FCM: Notify driver that payment was received
 * ==========================================================================
 * Fire-and-forget. Never throws. Payment must succeed even if FCM fails.
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
            [driverFirebaseUid]
        );

        driverToken = tokenResult.rows[0]?.token ?? null;
    } catch (lookupError) {
        console.error(
            '❌ Driver payment FCM — token lookup failed:',
            lookupError
        );
        return;
    }

    if (!driverToken) {
        console.log(
            `ℹ️ Driver payment FCM — no token for UID ${driverFirebaseUid}`
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
            newDriverBalance != null
                ? newDriverBalance.toFixed(2)
                : '',

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
            })`
        );
    } catch (error: any) {
        if (
            error?.code === 'messaging/invalid-registration-token' ||
            error?.code === 'messaging/registration-token-not-registered'
        ) {
            try {
                await pool.query(
                    `DELETE FROM public.fcm_tokens WHERE token = $1`,
                    [driverToken]
                );

                console.log(
                    `🧹 Removed stale FCM token for driver ${driverFirebaseUid}`
                );
            } catch (deleteError) {
                console.error(
                    '❌ Failed deleting invalid FCM token:',
                    deleteError
                );
            }
        }

        console.error('❌ Driver payment FCM failed:', error);
    }
}

/* ==========================================================================
 * GET /passengers/wallet
 * ==========================================================================
 * Returns the passenger's wallet. Creates one implicitly on first read if
 * your schema supports it, otherwise returns 404 so the client can POST.
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
                [uid]
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
                    currency,
                    is_active            AS "isActive",
                    last_transaction_at  AS "lastTransactionAt",
                    created_at           AS "createdAt",
                    updated_at           AS "updatedAt"
                FROM public.passenger_wallets
                WHERE passenger_id = $1
                LIMIT 1
                `,
                [passengerId]
            );

            if (walletResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Wallet not found.',
                });
            }

            const wallet = walletResult.rows[0];

            return res.status(200).json({
                success: true,
                wallet: {
                    id: wallet.id,
                    passengerId: wallet.passenger_id,
                    balance: Number(wallet.balance) || 0,
                    pendingBalance: Number(wallet.pendingBalance) || 0,
                    totalSpent: Number(wallet.totalSpent) || 0,
                    currency: wallet.currency || 'GHS',
                    isActive: wallet.isActive ?? true,
                    lastTransactionAt: wallet.lastTransactionAt,
                    createdAt: wallet.createdAt,
                    updatedAt: wallet.updatedAt,
                },
            });
        } catch (error) {
            console.error('❌ GET /passengers/wallet failed:', error);

            return res.status(500).json({
                success: false,
                message: 'Failed to load wallet.',
            });
        }
    }
);

/* ==========================================================================
 * POST /passengers/wallet
 * ==========================================================================
 * Creates a passenger wallet. Idempotent: returns the existing wallet if
 * one already exists.
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
                [uid]
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
                    currency,
                    is_active            AS "isActive",
                    last_transaction_at  AS "lastTransactionAt",
                    created_at           AS "createdAt",
                    updated_at           AS "updatedAt"
                FROM public.passenger_wallets
                WHERE passenger_id = $1
                LIMIT 1
                `,
                [passengerId]
            );

            if (existing.rows.length > 0) {
                return res.status(200).json({
                    success: true,
                    wallet: {
                        id: existing.rows[0].id,
                        passengerId: existing.rows[0].passenger_id,
                        balance: Number(existing.rows[0].balance) || 0,
                        pendingBalance:
                            Number(existing.rows[0].pendingBalance) || 0,
                        totalSpent:
                            Number(existing.rows[0].totalSpent) || 0,
                        currency: existing.rows[0].currency || 'GHS',
                        isActive: existing.rows[0].isActive ?? true,
                        lastTransactionAt:
                            existing.rows[0].lastTransactionAt,
                        createdAt: existing.rows[0].createdAt,
                        updatedAt: existing.rows[0].updatedAt,
                    },
                    message: 'Wallet already exists.',
                });
            }

            const insert = await pool.query(
                `
                INSERT INTO public.passenger_wallets (
                    passenger_id,
                    balance,
                    pending_balance,
                    total_spent,
                    currency,
                    is_active,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1::integer,
                    0,
                    0,
                    0,
                    'GHS',
                    true,
                    NOW(),
                    NOW()
                )
                RETURNING
                    id,
                    passenger_id,
                    balance,
                    pending_balance      AS "pendingBalance",
                    total_spent          AS "totalSpent",
                    currency,
                    is_active            AS "isActive",
                    last_transaction_at  AS "lastTransactionAt",
                    created_at           AS "createdAt",
                    updated_at           AS "updatedAt"
                `,
                [passengerId]
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
                    currency: w.currency || 'GHS',
                    isActive: w.isActive ?? true,
                    lastTransactionAt: w.lastTransactionAt,
                    createdAt: w.createdAt,
                    updatedAt: w.updatedAt,
                },
                message: 'Wallet created successfully.',
            });
        } catch (error) {
            console.error('❌ POST /passengers/wallet failed:', error);

            return res.status(500).json({
                success: false,
                message: 'Failed to create wallet.',
            });
        }
    }
);

/* ==========================================================================
 * GET /passengers/wallet/pending-payment-ride
 * ==========================================================================
 * Returns the passenger's latest completed-but-unpaid ride plus the
 * assigned driver's details, so the "Pay for Ride" dialog can pre-fill.
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
                [uid]
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
                [passengerId]
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
                error
            );

            return res.status(500).json({
                success: false,
                message: 'Failed to load pending payment ride.',
            });
        }
    }
);

/* ==========================================================================
 * POST /passengers/wallet/topup
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
                [uid]
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
                FROM public.passenger_wallets
                WHERE passenger_id = $1
                LIMIT 1
                FOR UPDATE
                `,
                [passengerId]
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
            const balanceBefore = Number(walletResult.rows[0].balance) || 0;
            const balanceAfter = balanceBefore + amount;

            await client.query(
                `
                UPDATE public.passenger_wallets
                SET
                    balance            = $1::numeric,
                    last_transaction_at = NOW(),
                    updated_at          = NOW()
                WHERE id = $2
                `,
                [balanceAfter, walletId]
            );

            await client.query(
                `
                INSERT INTO public.passenger_transactions (
                    wallet_id,
                    type,
                    amount,
                    balance_before,
                    balance_after,
                    status,
                    payment_method,
                    provider,
                    created_at
                )
                VALUES (
                    $1::integer,
                    'topup',
                    $2::numeric,
                    $3::numeric,
                    $4::numeric,
                    'completed',
                    $5::varchar,
                    $6::varchar,
                    NOW()
                )
                `,
                [
                    walletId,
                    amount,
                    balanceBefore,
                    balanceAfter,
                    paymentMethod,
                    provider,
                ]
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

            console.error('❌ POST /passengers/wallet/topup failed:', error);

            return res.status(500).json({
                success: false,
                message: 'Failed to process top-up.',
            });
        } finally {
            client.release();
        }
    }
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
            1
        );
        const limit = Math.min(
            Math.max(
                parseInt(String(req.query.limit ?? '20'), 10) || 20,
                1
            ),
            100
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
                [uid]
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
                FROM public.passenger_transactions t
                INNER JOIN public.passenger_wallets w
                    ON w.id = t.wallet_id
                WHERE w.passenger_id = $1::integer
                ORDER BY t.created_at DESC, t.id DESC
                LIMIT $2 OFFSET $3
                `,
                [passengerId, limit, offset]
            );

            return res.status(200).json({
                success: true,
                transactions: result.rows,
            });
        } catch (error) {
            console.error(
                '❌ GET /passengers/transactions failed:',
                error
            );

            return res.status(500).json({
                success: false,
                message: 'Failed to load transactions.',
            });
        }
    }
);

/* ==========================================================================
 * POST /passengers/wallet/pay
 * ==========================================================================
 * THE MAIN EVENT — passenger pays for a completed ride.
 *
 * Steps:
 *   1. Validate ride + passenger ownership.
 *   2. Debit passenger wallet.
 *   3. Credit driver wallet (via drivers.id resolved from Firebase UID).
 *   4. Insert passenger transaction + driver transaction.
 *   5. Update ride.payment_status = 'paid'.
 *   6. COMMIT.
 *   7. Fire-and-forget FCM to the driver: "Payment Received".
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

            /* ----------------------------------------------------------
             * 1. Resolve passenger
             * ---------------------------------------------------------- */

            const passengerResult = await client.query(
                `
                SELECT id, full_name
                FROM public.passengers
                WHERE firebase_uid = $1::text
                LIMIT 1
                FOR UPDATE
                `,
                [uid]
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

            /* ----------------------------------------------------------
             * 2. Lock the ride row
             * ---------------------------------------------------------- */

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
                [rideId, passengerId]
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

            // Prefer the fare on record; fall back to client amount.
            const amount = fare > 0 ? fare : amountInput;

            const commission = Math.min(FLAT_COMMISSION, amount);
            const driverEarnings = Math.max(0, amount - commission);

            /* ----------------------------------------------------------
             * 3. Lock passenger wallet + debit
             * ---------------------------------------------------------- */

            const passengerWalletResult = await client.query(
                `
                SELECT id, balance
                FROM public.passenger_wallets
                WHERE passenger_id = $1
                LIMIT 1
                FOR UPDATE
                `,
                [passengerId]
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
                UPDATE public.passenger_wallets
                SET
                    balance             = $1::numeric,
                    total_spent         = COALESCE(total_spent, 0) + $2::numeric,
                    last_transaction_at = NOW(),
                    updated_at          = NOW()
                WHERE id = $3
                `,
                [passengerBalanceAfter, amount, passengerWalletId]
            );

            /* ----------------------------------------------------------
             * 4. Credit driver wallet
             * ---------------------------------------------------------- */

            const driverResult = await client.query(
                `
                SELECT id
                FROM public.drivers
                WHERE uid = $1::text
                LIMIT 1
                `,
                [rideInfo.driver_id]
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
                    [driverNumericId]
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
                        [newDriverBalance, driverWalletId]
                    );

                    await client.query(
                        `
                        INSERT INTO public.driver_transactions (
                            wallet_id,
                            ride_id,
                            type,
                            amount,
                            balance_before,
                            balance_after,
                            status,
                            payment_method,
                            description,
                            created_at
                        )
                        VALUES (
                            $1::integer,
                            $2::integer,
                            'ride_earning',
                            $3::numeric,
                            $4::numeric,
                            $5::numeric,
                            'completed',
                            'in_app',
                            $6::text,
                            NOW()
                        )
                        `,
                        [
                            driverWalletId,
                            rideId,
                            driverEarnings,
                            driverBalanceBefore,
                            newDriverBalance,
                            `Earnings from ride #${rideId}`,
                        ]
                    );
                }
            }

            /* ----------------------------------------------------------
             * 5. Passenger transaction + ride update
             * ---------------------------------------------------------- */

            await client.query(
                `
                INSERT INTO public.passenger_transactions (
                    wallet_id,
                    ride_id,
                    type,
                    amount,
                    balance_before,
                    balance_after,
                    status,
                    payment_method,
                    description,
                    created_at
                )
                VALUES (
                    $1::integer,
                    $2::integer,
                    'ride_payment',
                    $3::numeric,
                    $4::numeric,
                    $5::numeric,
                    'completed',
                    'wallet',
                    $6::text,
                    NOW()
                )
                `,
                [
                    passengerWalletId,
                    rideId,
                    amount,
                    passengerBalanceBefore,
                    passengerBalanceAfter,
                    `Payment for ride #${rideId}`,
                ]
            );

            await client.query(
                `
                UPDATE public.rides
                SET
                    payment_status     = 'paid',
                    driver_earnings    = $1::numeric,
                    tegaara_commission = $2::numeric
                WHERE id = $3::integer
                `,
                [driverEarnings, commission, rideId]
            );

            /* ----------------------------------------------------------
             * 6. Commit
             * ---------------------------------------------------------- */

            await client.query('COMMIT');

            console.log(
                `✅ Ride ${rideId} paid by passenger ${uid}. ` +
                `fare=${amount.toFixed(2)} ` +
                `driverEarnings=${driverEarnings.toFixed(2)} ` +
                `commission=${commission.toFixed(2)}`
            );

            /* ----------------------------------------------------------
             * 7. Fire-and-forget FCM to driver
             * ----------------------------------------------------------
             * Committed above. Notification failure must NOT affect
             * the 200 response.
             */

            void notifyDriverPaymentReceived(
                rideInfo.driver_id,
                rideInfo.ride_id,
                fare > 0 ? fare : amount,
                driverEarnings,
                commission,
                newDriverBalance,
                passengerName,
                rideInfo.pickup_address ?? '',
                rideInfo.destination_address ?? ''
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
                error
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
    }
);

export default router;
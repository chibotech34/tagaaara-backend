import {
    Router,
    Request,
    Response,
} from 'express';

import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';

const router = Router();

/*
|--------------------------------------------------------------------------
| Types
|--------------------------------------------------------------------------
*/

interface AuthenticatedDriverRequest
    extends Request {
    driverId?: number;
    firebaseUid?: string;
}

/*
|--------------------------------------------------------------------------
| Constants
|--------------------------------------------------------------------------
*/

const MINIMUM_WITHDRAWAL = 10.00;

const WITHDRAWAL_FEE = 0.00;


/*
|--------------------------------------------------------------------------
| Authentication
|--------------------------------------------------------------------------
|
| We verify the Firebase ID token directly here.
|
| This keeps wallet authentication independent from
| the admin authentication middleware in server.ts.
|
|--------------------------------------------------------------------------
*/

async function authenticateDriver(
    req: AuthenticatedDriverRequest,
    res: Response,
): Promise<boolean> {
    try {
        const authHeader =
            req.headers.authorization;

        if (
            !authHeader ||
            !authHeader.startsWith('Bearer ')
        ) {
            res.status(401).json({
                success: false,
                error:
                    'Authentication token required',
            });

            return false;
        }

        const token =
            authHeader.substring(7).trim();

        if (!token) {
            res.status(401).json({
                success: false,
                error:
                    'Authentication token required',
            });

            return false;
        }

        const decoded =
            await firebaseAuth.verifyIdToken(
                token,
            );

        const firebaseUid =
            decoded.uid;

        const result =
            await pool.query(
                `
                SELECT
                    id,
                    firebase_uid,
                    status
                FROM public.drivers
                WHERE firebase_uid = $1
                LIMIT 1
                `,
                [firebaseUid],
            );

        if (
            result.rows.length === 0
        ) {
            res.status(404).json({
                success: false,
                error:
                    'Driver account not found',
            });

            return false;
        }

        const driver =
            result.rows[0];

        if (
            driver.status !==
            'approved'
        ) {
            res.status(403).json({
                success: false,
                error:
                    'Driver account is not approved',
                status:
                    driver.status,
            });

            return false;
        }

        req.driverId =
            Number(driver.id);

        req.firebaseUid =
            firebaseUid;

        return true;
    } catch (error: unknown) {
        console.error(
            '❌ Driver wallet authentication error:',
            error,
        );

        res.status(401).json({
            success: false,
            error:
                'Invalid or expired authentication token',
        });

        return false;
    }
}


/*
|--------------------------------------------------------------------------
| Get or Create Driver Wallet
|--------------------------------------------------------------------------
*/

async function getOrCreateWallet(
    driverId: number,
    client = pool,
) {
    let result =
        await client.query(
            `
            SELECT *
            FROM public.driver_wallets
            WHERE driver_id = $1
            LIMIT 1
            `,
            [driverId],
        );

    if (
        result.rows.length > 0
    ) {
        return result.rows[0];
    }

    result =
        await client.query(
            `
            INSERT INTO public.driver_wallets
            (
                driver_id,
                balance,
                pending_balance,
                total_earnings,
                total_withdrawn,
                total_commission_paid,
                amount_owed,
                minimum_balance
            )
            VALUES
            (
                $1,
                0.00,
                0.00,
                0.00,
                0.00,
                0.00,
                0.00,
                100.00
            )
            RETURNING *
            `,
            [driverId],
        );

    return result.rows[0];
}


/*
|--------------------------------------------------------------------------
| GET DRIVER WALLET
|--------------------------------------------------------------------------
|
| GET /api/drivers/wallet
|
|--------------------------------------------------------------------------
*/

router.get(
    '/wallet',
    async (
        req: AuthenticatedDriverRequest,
        res: Response,
    ) => {
        if (
            !(await authenticateDriver(
                req,
                res,
            ))
        ) {
            return;
        }

        try {
            const wallet =
                await getOrCreateWallet(
                    req.driverId!,
                );

            return res.status(200).json({
                success: true,
                wallet: {
                    id: wallet.id,
                    driverId:
                        wallet.driver_id,
                    balance:
                        Number(
                            wallet.balance,
                        ),
                    pendingBalance:
                        Number(
                            wallet.pending_balance,
                        ),
                    totalEarnings:
                        Number(
                            wallet.total_earnings,
                        ),
                    totalWithdrawn:
                        Number(
                            wallet.total_withdrawn,
                        ),
                    totalCommissionPaid:
                        Number(
                            wallet.total_commission_paid,
                        ),
                    amountOwed:
                        Number(
                            wallet.amount_owed,
                        ),
                    minimumBalance:
                        Number(
                            wallet.minimum_balance,
                        ),
                    lastTransactionAt:
                        wallet.last_transaction_at,
                    createdAt:
                        wallet.created_at,
                    updatedAt:
                        wallet.updated_at,
                },
            });
        } catch (error: unknown) {
            console.error(
                '❌ Get wallet error:',
                error,
            );

            return res.status(500).json({
                success: false,
                error:
                    'Failed to load driver wallet',
            });
        }
    },
);


/*
|--------------------------------------------------------------------------
| GET WALLET TRANSACTIONS
|--------------------------------------------------------------------------
|
| GET /api/drivers/transactions
|
|--------------------------------------------------------------------------
*/

router.get(
    '/transactions',
    async (
        req: AuthenticatedDriverRequest,
        res: Response,
    ) => {
        if (
            !(await authenticateDriver(
                req,
                res,
            ))
        ) {
            return;
        }

        try {
            const limit = Math.min(
                Math.max(
                    Number(
                        req.query.limit,
                    ) || 50,
                    1,
                ),
                100,
            );

            const offset = Math.max(
                Number(
                    req.query.offset,
                ) || 0,
                0,
            );

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        transaction_type,
                        amount,
                        balance_before,
                        balance_after,
                        description,
                        reference,
                        status,
                        metadata,
                        created_at
                    FROM public.driver_wallet_transactions
                    WHERE driver_id = $1
                    ORDER BY created_at DESC
                    LIMIT $2
                    OFFSET $3
                    `,
                    [
                        req.driverId,
                        limit,
                        offset,
                    ],
                );

            return res.status(200).json({
                success: true,
                transactions:
                    result.rows.map(
                        (
                            transaction,
                        ) => ({
                            id:
                                transaction.id,
                            transactionType:
                                transaction.transaction_type,
                            amount:
                                Number(
                                    transaction.amount,
                                ),
                            balanceBefore:
                                Number(
                                    transaction.balance_before,
                                ),
                            balanceAfter:
                                Number(
                                    transaction.balance_after,
                                ),
                            description:
                                transaction.description,
                            reference:
                                transaction.reference,
                            status:
                                transaction.status,
                            metadata:
                                transaction.metadata,
                            createdAt:
                                transaction.created_at,
                        }),
                    ),
                pagination: {
                    limit,
                    offset,
                    count:
                        result.rows
                            .length,
                },
            });
        } catch (error: unknown) {
            console.error(
                '❌ Get wallet transactions error:',
                error,
            );

            return res.status(500).json({
                success: false,
                error:
                    'Failed to load wallet transactions',
            });
        }
    },
);


/*
|--------------------------------------------------------------------------
| GET PAYMENT ACCOUNT
|--------------------------------------------------------------------------
|
| GET /api/drivers/wallet/payment-account
|
|--------------------------------------------------------------------------
*/

router.get(
    '/wallet/payment-account',
    async (
        req: AuthenticatedDriverRequest,
        res: Response,
    ) => {
        if (
            !(await authenticateDriver(
                req,
                res,
            ))
        ) {
            return;
        }

        try {
            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        driver_id,
                        mobile_network,
                        mobile_money_number,
                        account_name,
                        is_verified,
                        is_active,
                        created_at,
                        updated_at
                    FROM public.driver_payment_accounts
                    WHERE driver_id = $1
                    LIMIT 1
                    `,
                    [req.driverId],
                );

            if (
                result.rows.length === 0
            ) {
                return res.status(200).json({
                    success: true,
                    paymentAccount:
                        null,
                });
            }

            const account =
                result.rows[0];

            return res.status(200).json({
                success: true,
                paymentAccount: {
                    id: account.id,
                    driverId:
                        account.driver_id,
                    mobileNetwork:
                        account.mobile_network,
                    mobileMoneyNumber:
                        account.mobile_money_number,
                    accountName:
                        account.account_name,
                    isVerified:
                        account.is_verified,
                    isActive:
                        account.is_active,
                    createdAt:
                        account.created_at,
                    updatedAt:
                        account.updated_at,
                },
            });
        } catch (error: unknown) {
            console.error(
                '❌ Get payment account error:',
                error,
            );

            return res.status(500).json({
                success: false,
                error:
                    'Failed to load payment account',
            });
        }
    },
);


/*
|--------------------------------------------------------------------------
| CREATE / UPDATE PAYMENT ACCOUNT
|--------------------------------------------------------------------------
|
| POST /api/drivers/wallet/payment-account
|
|--------------------------------------------------------------------------
*/

router.post(
    '/wallet/payment-account',
    async (
        req: AuthenticatedDriverRequest,
        res: Response,
    ) => {
        if (
            !(await authenticateDriver(
                req,
                res,
            ))
        ) {
            return;
        }

        const {
            mobileNetwork,
            mobileMoneyNumber,
            accountName,
        } = req.body ?? {};

        const network =
            String(
                mobileNetwork || '',
            ).trim();

        const phone =
            String(
                mobileMoneyNumber || '',
            ).trim();

        const name =
            accountName
                ? String(
                    accountName,
                ).trim()
                : null;

        if (!network) {
            return res.status(400).json({
                success: false,
                error:
                    'Mobile network is required',
            });
        }

        if (!phone) {
            return res.status(400).json({
                success: false,
                error:
                    'Mobile Money number is required',
            });
        }

        if (
            !/^(0\d{9}|\+233\d{9})$/.test(
                phone,
            )
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Invalid Ghana Mobile Money number',
            });
        }

        const allowedNetworks = [
            'MTN',
            'Telecel',
            'AirtelTigo',
        ];

        if (
            !allowedNetworks.includes(
                network,
            )
        ) {
            return res.status(400).json({
                success: false,
                error:
                    'Unsupported mobile network',
            });
        }

        try {
            const result =
                await pool.query(
                    `
                    INSERT INTO public.driver_payment_accounts
                    (
                        driver_id,
                        mobile_network,
                        mobile_money_number,
                        account_name,
                        is_verified,
                        is_active
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        false,
                        true
                    )
                    ON CONFLICT (driver_id)
                    DO UPDATE SET
                        mobile_network =
                            EXCLUDED.mobile_network,
                        mobile_money_number =
                            EXCLUDED.mobile_money_number,
                        account_name =
                            EXCLUDED.account_name,
                        is_active =
                            true,
                        is_verified =
                            false,
                        updated_at =
                            CURRENT_TIMESTAMP
                    RETURNING *
                    `,
                    [
                        req.driverId,
                        network,
                        phone,
                        name,
                    ],
                );

            const account =
                result.rows[0];

            return res.status(200).json({
                success: true,
                message:
                    'Payment account saved successfully',
                paymentAccount: {
                    id: account.id,
                    mobileNetwork:
                        account.mobile_network,
                    mobileMoneyNumber:
                        account.mobile_money_number,
                    accountName:
                        account.account_name,
                    isVerified:
                        account.is_verified,
                    isActive:
                        account.is_active,
                },
            });
        } catch (error: unknown) {
            console.error(
                '❌ Save payment account error:',
                error,
            );

            return res.status(500).json({
                success: false,
                error:
                    'Failed to save payment account',
            });
        }
    },
);


/*
|--------------------------------------------------------------------------
| TOP UP
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| This endpoint DOES NOT directly increase the wallet.
|
| A real payment provider must confirm the payment first.
|
|--------------------------------------------------------------------------
*/

router.post(
    '/wallet/topup',
    async (
        req: AuthenticatedDriverRequest,
        res: Response,
    ) => {
        if (
            !(await authenticateDriver(
                req,
                res,
            ))
        ) {
            return;
        }

        return res.status(501).json({
            success: false,
            error:
                'Wallet top-up is not enabled. A verified payment provider transaction is required.',
        });
    },
);


/*
|--------------------------------------------------------------------------
| WITHDRAW
|--------------------------------------------------------------------------
|
| POST /api/drivers/wallet/withdraw
|
|--------------------------------------------------------------------------
*/

router.post(
    '/wallet/withdraw',
    async (
        req: AuthenticatedDriverRequest,
        res: Response,
    ) => {
        if (
            !(await authenticateDriver(
                req,
                res,
            ))
        ) {
            return;
        }

        const client =
            await pool.connect();

        try {
            const requestedAmount =
                Number(
                    req.body?.amount,
                );

            if (
                !Number.isFinite(
                    requestedAmount,
                ) ||
                requestedAmount <= 0
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        'A valid withdrawal amount is required',
                });
            }

            if (
                requestedAmount <
                MINIMUM_WITHDRAWAL
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        `Minimum withdrawal amount is GH₵${MINIMUM_WITHDRAWAL.toFixed(2)}`,
                });
            }

            const paymentResult =
                await client.query(
                    `
                    SELECT *
                    FROM public.driver_payment_accounts
                    WHERE driver_id = $1
                      AND is_active = true
                    LIMIT 1
                    `,
                    [req.driverId],
                );

            if (
                paymentResult.rows.length ===
                0
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        'Please add an active Mobile Money payment account before withdrawing',
                });
            }

            const paymentAccount =
                paymentResult.rows[0];

            if (
                !paymentAccount.is_verified
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        'Your Mobile Money payment account has not been verified',
                });
            }

            await client.query(
                'BEGIN',
            );

            /*
             * Lock wallet row.
             *
             * This is critical.
             *
             * Without FOR UPDATE, two withdrawal requests
             * arriving at nearly the same time could both
             * see the same balance.
             */

            const walletResult =
                await client.query(
                    `
                    SELECT *
                    FROM public.driver_wallets
                    WHERE driver_id = $1
                    FOR UPDATE
                    `,
                    [req.driverId],
                );

            if (
                walletResult.rows.length ===
                0
            ) {
                await client.query(
                    `
                    INSERT INTO public.driver_wallets
                    (
                        driver_id
                    )
                    VALUES ($1)
                    `,
                    [req.driverId],
                );
            }

            const lockedWalletResult =
                await client.query(
                    `
                    SELECT *
                    FROM public.driver_wallets
                    WHERE driver_id = $1
                    FOR UPDATE
                    `,
                    [req.driverId],
                );

            const wallet =
                lockedWalletResult
                    .rows[0];

            const balance =
                Number(
                    wallet.balance,
                );

            const minimumBalance =
                Number(
                    wallet.minimum_balance,
                );

            const availableAfterWithdrawal =
                balance -
                requestedAmount -
                WITHDRAWAL_FEE;

            if (
                availableAfterWithdrawal <
                minimumBalance
            ) {
                await client.query(
                    'ROLLBACK',
                );

                return res.status(400).json({
                    success: false,
                    error:
                        `Insufficient withdrawable balance. You must maintain at least GH₵${minimumBalance.toFixed(2)} in your wallet.`,
                    balance,
                    minimumBalance,
                });
            }

            const reference =
                `WD-${Date.now()}-${req.driverId}`;

            const netAmount =
                requestedAmount -
                WITHDRAWAL_FEE;

            /*
             * Deduct immediately and create a pending
             * withdrawal.
             *
             * If the payment provider later fails,
             * an admin/provider callback should reverse
             * this transaction.
             */

            const newBalance =
                balance -
                requestedAmount -
                WITHDRAWAL_FEE;

            await client.query(
                `
                UPDATE public.driver_wallets
                SET
                    balance = $1,
                    total_withdrawn =
                        total_withdrawn + $2,
                    last_transaction_at =
                        CURRENT_TIMESTAMP,
                    updated_at =
                        CURRENT_TIMESTAMP
                WHERE id = $3
                `,
                [
                    newBalance,
                    requestedAmount,
                    wallet.id,
                ],
            );

            const withdrawalResult =
                await client.query(
                    `
                    INSERT INTO public.driver_wallet_withdrawals
                    (
                        driver_id,
                        wallet_id,
                        payment_account_id,
                        amount,
                        fee,
                        net_amount,
                        mobile_network,
                        mobile_money_number,
                        account_name,
                        status,
                        reference
                    )
                    VALUES
                    (
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        $8,
                        $9,
                        'pending',
                        $10
                    )
                    RETURNING *
                    `,
                    [
                        req.driverId,
                        wallet.id,
                        paymentAccount.id,
                        requestedAmount,
                        WITHDRAWAL_FEE,
                        netAmount,
                        paymentAccount.mobile_network,
                        paymentAccount.mobile_money_number,
                        paymentAccount.account_name,
                        reference,
                    ],
                );

            await client.query(
                `
                INSERT INTO public.driver_wallet_transactions
                (
                    driver_id,
                    wallet_id,
                    transaction_type,
                    amount,
                    balance_before,
                    balance_after,
                    description,
                    reference,
                    status,
                    metadata
                )
                VALUES
                (
                    $1,
                    $2,
                    'withdrawal',
                    $3,
                    $4,
                    $5,
                    $6,
                    $7,
                    'pending',
                    $8
                )
                `,
                [
                    req.driverId,
                    wallet.id,
                    requestedAmount,
                    balance,
                    newBalance,
                    'Driver wallet withdrawal',
                    reference,
                    JSON.stringify({
                        withdrawalId:
                            withdrawalResult
                                .rows[0]
                                .id,
                        fee:
                            WITHDRAWAL_FEE,
                        netAmount,
                    }),
                ],
            );

            await client.query(
                'COMMIT',
            );

            return res.status(201).json({
                success: true,
                message:
                    'Withdrawal request created successfully',
                withdrawal: {
                    id:
                        withdrawalResult
                            .rows[0]
                            .id,
                    amount:
                        requestedAmount,
                    fee:
                        WITHDRAWAL_FEE,
                    netAmount,
                    status:
                        'pending',
                    reference,
                    newBalance,
                },
            });
        } catch (error: unknown) {
            await client.query(
                'ROLLBACK',
            );

            console.error(
                '❌ Withdrawal error:',
                error,
            );

            const dbError =
                error as {
                    message?: string;
                };

            return res.status(500).json({
                success: false,
                error:
                    dbError.message ||
                    'Failed to process withdrawal',
            });
        } finally {
            client.release();
        }
    },
);


/*
|--------------------------------------------------------------------------
| GET WITHDRAWALS
|--------------------------------------------------------------------------
|
| GET /api/drivers/wallet/withdrawals
|
|--------------------------------------------------------------------------
*/

router.get(
    '/wallet/withdrawals',
    async (
        req: AuthenticatedDriverRequest,
        res: Response,
    ) => {
        if (
            !(await authenticateDriver(
                req,
                res,
            ))
        ) {
            return;
        }

        try {
            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        amount,
                        fee,
                        net_amount,
                        mobile_network,
                        mobile_money_number,
                        account_name,
                        status,
                        reference,
                        failure_reason,
                        processed_at,
                        created_at,
                        updated_at
                    FROM public.driver_wallet_withdrawals
                    WHERE driver_id = $1
                    ORDER BY created_at DESC
                    LIMIT 100
                    `,
                    [req.driverId],
                );

            return res.status(200).json({
                success: true,
                withdrawals:
                    result.rows.map(
                        (
                            withdrawal,
                        ) => ({
                            id:
                                withdrawal.id,
                            amount:
                                Number(
                                    withdrawal.amount,
                                ),
                            fee:
                                Number(
                                    withdrawal.fee,
                                ),
                            netAmount:
                                Number(
                                    withdrawal.net_amount,
                                ),
                            mobileNetwork:
                                withdrawal.mobile_network,
                            mobileMoneyNumber:
                                withdrawal.mobile_money_number,
                            accountName:
                                withdrawal.account_name,
                            status:
                                withdrawal.status,
                            reference:
                                withdrawal.reference,
                            failureReason:
                                withdrawal.failure_reason,
                            processedAt:
                                withdrawal.processed_at,
                            createdAt:
                                withdrawal.created_at,
                            updatedAt:
                                withdrawal.updated_at,
                        }),
                    ),
            });
        } catch (error: unknown) {
            console.error(
                '❌ Get withdrawals error:',
                error,
            );

            return res.status(500).json({
                success: false,
                error:
                    'Failed to load withdrawals',
            });
        }
    },
);


export default router;
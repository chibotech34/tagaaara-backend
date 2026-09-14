// src/routes/driverWalletRoutes.ts

import {
    Router,
    Request,
    Response,
} from 'express';

import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';

const router = Router();

/* ==========================================================================
 * TYPES
 * ========================================================================== */

interface AuthenticatedDriverRequest
    extends Request {
    driverId?: number;
    firebaseUid?: string;
}

/* ==========================================================================
 * CONSTANTS
 * ========================================================================== */

const MINIMUM_WITHDRAWAL = 10.00;
const WITHDRAWAL_FEE = 0.00;

/* ==========================================================================
 * AUTHENTICATE DRIVER
 * ========================================================================== */

async function authenticateDriver(
    req: AuthenticatedDriverRequest,
    res: Response,
): Promise<boolean> {

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
            code:
                'AUTH_HEADER_MISSING',
        });

        return false;
    }

    const token =
        authHeader
            .substring('Bearer '.length)
            .trim();

    if (!token) {
        res.status(401).json({
            success: false,
            error:
                'Authentication token required',
            code:
                'AUTH_TOKEN_MISSING',
        });

        return false;
    }

    let firebaseUid: string;

    try {
        const decoded =
            await firebaseAuth.verifyIdToken(
                token,
            );

        firebaseUid =
            decoded.uid;

        if (!firebaseUid) {
            res.status(401).json({
                success: false,
                error:
                    'Firebase token does not contain a UID',
                code:
                    'AUTH_UID_MISSING',
            });

            return false;
        }
    } catch (error: unknown) {

        console.error(
            '❌ Firebase token verification failed:',
            error,
        );

        const firebaseError =
            error as {
                code?: string;
                message?: string;
            };

        if (
            firebaseError.code ===
            'auth/id-token-expired'
        ) {
            res.status(401).json({
                success: false,
                error:
                    'Firebase ID token expired. Please refresh authentication.',
                code:
                    'AUTH_TOKEN_EXPIRED',
            });

            return false;
        }

        if (
            firebaseError.code ===
            'auth/id-token-revoked'
        ) {
            res.status(401).json({
                success: false,
                error:
                    'Firebase ID token has been revoked. Please sign in again.',
                code:
                    'AUTH_TOKEN_REVOKED',
            });

            return false;
        }

        res.status(401).json({
            success: false,
            error:
                'Firebase authentication failed.',
            code:
                'AUTH_TOKEN_INVALID',
        });

        return false;
    }

    try {

        const result =
            await pool.query(
                `
                SELECT
                    id,
                    uid,
                    status
                FROM public.drivers
                WHERE uid = $1
                LIMIT 1
                `,
                [firebaseUid],
            );

        if (result.rows.length === 0) {

            console.warn(
                `⚠️ No driver found for Firebase UID: ${firebaseUid}`,
            );

            res.status(404).json({
                success: false,
                error:
                    'Driver account not found',
                code:
                    'DRIVER_NOT_FOUND',
            });

            return false;
        }

        const driver =
            result.rows[0];

        if (driver.status !== 'approved') {

            console.warn(
                `⚠️ Driver ${driver.id} is not approved. Status: ${driver.status}`,
            );

            res.status(403).json({
                success: false,
                error:
                    'Driver account is not approved',
                code:
                    'DRIVER_NOT_APPROVED',
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
            '❌ Driver database lookup failed:',
            error,
        );

        const dbError =
            error as {
                code?: string;
                message?: string;
                detail?: string;
                hint?: string;
            };

        res.status(500).json({
            success: false,
            error:
                'Failed to load driver account',
            code:
                'DRIVER_LOOKUP_FAILED',
            details:
                dbError.message,
        });

        return false;
    }
}

/* ==========================================================================
 * GET OR CREATE DRIVER WALLET
 * ========================================================================== */

async function getOrCreateWallet(
    driverId: number,
    client: any = pool,
) {

    const existing =
        await client.query(
            `
            SELECT
                id,
                driver_id,
                balance,
                pending_balance,
                total_earnings,
                total_withdrawn,
                total_commission_paid,
                amount_owed,
                minimum_balance,
                last_transaction_at,
                created_at,
                updated_at
            FROM public.driver_wallets
            WHERE driver_id = $1
            LIMIT 1
            `,
            [driverId],
        );

    if (existing.rows.length > 0) {
        return existing.rows[0];
    }

    const created =
        await client.query(
            `
            INSERT INTO public.driver_wallets (
                driver_id,
                balance,
                pending_balance,
                total_earnings,
                total_withdrawn,
                total_commission_paid,
                amount_owed,
                minimum_balance
            )
            VALUES (
                $1,
                0.00,
                0.00,
                0.00,
                0.00,
                0.00,
                0.00,
                100.00
            )
            RETURNING
                id,
                driver_id,
                balance,
                pending_balance,
                total_earnings,
                total_withdrawn,
                total_commission_paid,
                amount_owed,
                minimum_balance,
                last_transaction_at,
                created_at,
                updated_at
            `,
            [driverId],
        );

    return created.rows[0];
}

/* ==========================================================================
 * GET DRIVER WALLET
 *
 * GET /api/drivers/wallet
 * ========================================================================== */

router.get(
    '/wallet',
    async (
        req: Request,
        res: Response,
    ) => {

        const authReq =
            req as AuthenticatedDriverRequest;

        const authenticated =
            await authenticateDriver(
                authReq,
                res,
            );

        if (!authenticated) {
            return;
        }

        try {

            const wallet =
                await getOrCreateWallet(
                    authReq.driverId!,
                );

            res.status(200).json({
                success: true,

                wallet: {
                    id:
                        Number(wallet.id),

                    driverId:
                        Number(wallet.driver_id),

                    balance:
                        Number(wallet.balance),

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
                '❌ Failed to load driver wallet:',
                error,
            );

            const dbError =
                error as {
                    message?: string;
                };

            res.status(500).json({
                success: false,
                error:
                    'Failed to load driver wallet',
                code:
                    'WALLET_LOAD_FAILED',
                details:
                    dbError.message,
            });
        }
    },
);

/* ==========================================================================
 * GET WALLET TRANSACTIONS
 *
 * GET /api/drivers/wallet/transactions
 * ========================================================================== */

router.get(
    '/wallet/transactions',
    async (
        req: Request,
        res: Response,
    ) => {

        const authReq =
            req as AuthenticatedDriverRequest;

        const authenticated =
            await authenticateDriver(
                authReq,
                res,
            );

        if (!authenticated) {
            return;
        }

        try {

            const limit =
                Math.min(
                    Math.max(
                        Number(
                            req.query.limit ||
                            50,
                        ),
                        1,
                    ),
                    100,
                );

            const offset =
                Math.max(
                    Number(
                        req.query.offset ||
                        0,
                    ),
                    0,
                );

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        wallet_id,
                        driver_id,
                        transaction_type,
                        amount,
                        balance_before,
                        balance_after,
                        reference,
                        description,
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
                        authReq.driverId,
                        limit,
                        offset,
                    ],
                );

            res.status(200).json({
                success: true,
                transactions:
                    result.rows.map(
                        (transaction) => ({
                            id:
                                Number(
                                    transaction.id,
                                ),

                            walletId:
                                Number(
                                    transaction.wallet_id,
                                ),

                            driverId:
                                Number(
                                    transaction.driver_id,
                                ),

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

                            reference:
                                transaction.reference,

                            description:
                                transaction.description,

                            status:
                                transaction.status,

                            metadata:
                                transaction.metadata,

                            createdAt:
                                transaction.created_at,
                        }),
                    ),
            });

        } catch (error: unknown) {

            console.error(
                '❌ Failed to load wallet transactions:',
                error,
            );

            const dbError =
                error as {
                    message?: string;
                };

            res.status(500).json({
                success: false,
                error:
                    'Failed to load wallet transactions',
                code:
                    'TRANSACTIONS_LOAD_FAILED',
                details:
                    dbError.message,
            });
        }
    },
);

/* ==========================================================================
 * GET PAYMENT ACCOUNT
 *
 * GET /api/drivers/wallet/payment-account
 * ========================================================================== */

router.get(
    '/wallet/payment-account',
    async (
        req: Request,
        res: Response,
    ) => {

        const authReq =
            req as AuthenticatedDriverRequest;

        const authenticated =
            await authenticateDriver(
                authReq,
                res,
            );

        if (!authenticated) {
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
                        mobile_number,
                        account_name,
                        is_verified,
                        is_active,
                        created_at,
                        updated_at
                    FROM public.driver_payment_accounts
                    WHERE driver_id = $1
                    LIMIT 1
                    `,
                    [
                        authReq.driverId,
                    ],
                );

            if (result.rows.length === 0) {
                res.status(200).json({
                    success: true,
                    account: null,
                });

                return;
            }

            const account =
                result.rows[0];

            res.status(200).json({
                success: true,

                account: {
                    id:
                        Number(account.id),

                    driver_id:
                        Number(
                            account.driver_id,
                        ),

                    mobile_network:
                        account.mobile_network,

                    mobile_money_number:
                        account.mobile_number,

                    account_name:
                        account.account_name,

                    is_verified:
                        account.is_verified,

                    is_active:
                        account.is_active,

                    created_at:
                        account.created_at,

                    updated_at:
                        account.updated_at,
                },
            });

        } catch (error: unknown) {

            console.error(
                '❌ Failed to load payment account:',
                error,
            );

            const dbError =
                error as {
                    message?: string;
                };

            res.status(500).json({
                success: false,
                error:
                    'Failed to load payment account',
                code:
                    'PAYMENT_ACCOUNT_LOAD_FAILED',
                details:
                    dbError.message,
            });
        }
    },
);

/* ==========================================================================
 * CREATE / UPDATE PAYMENT ACCOUNT
 *
 * POST /api/drivers/wallet/payment-account
 * ========================================================================== */

router.post(
    '/wallet/payment-account',
    async (
        req: Request,
        res: Response,
    ) => {

        const authReq =
            req as AuthenticatedDriverRequest;

        const authenticated =
            await authenticateDriver(
                authReq,
                res,
            );

        if (!authenticated) {
            return;
        }

        try {

            const mobileNetwork =
                req.body.mobileNetwork ??
                req.body.mobile_network;

            const mobileNumber =
                req.body.mobileNumber ??
                req.body.mobile_money_number;

            const accountName =
                req.body.accountName ??
                req.body.account_name ??
                null;

            if (!mobileNetwork || !mobileNumber) {
                res.status(400).json({
                    success: false,
                    error:
                        'Mobile network and mobile number are required',
                    code:
                        'PAYMENT_ACCOUNT_FIELDS_REQUIRED',
                });

                return;
            }

            const phone =
                String(
                    mobileNumber,
                ).trim();

            if (
                !/^(0\d{9}|\+233\d{9})$/.test(
                    phone,
                )
            ) {
                res.status(400).json({
                    success: false,
                    error:
                        'Invalid Ghana mobile number',
                    code:
                        'INVALID_MOBILE_NUMBER',
                });

                return;
            }

            const allowedNetworks = [
                'MTN',
                'Telecel',
                'AirtelTigo',
                'AT',
                'Vodafone',
            ];

            const normalizedNetwork =
                String(
                    mobileNetwork,
                ).trim();

            if (
                !allowedNetworks.includes(
                    normalizedNetwork,
                )
            ) {
                res.status(400).json({
                    success: false,
                    error:
                        'Invalid mobile network',
                    code:
                        'INVALID_MOBILE_NETWORK',
                });

                return;
            }

            const result =
                await pool.query(
                    `
                    INSERT INTO public.driver_payment_accounts (
                        driver_id,
                        mobile_network,
                        mobile_number,
                        account_name,
                        is_verified,
                        is_active
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        false,
                        true
                    )
                    ON CONFLICT (driver_id)
                    DO UPDATE SET
                        mobile_network = EXCLUDED.mobile_network,
                        mobile_number = EXCLUDED.mobile_number,
                        account_name = EXCLUDED.account_name,
                        is_active = true,
                        updated_at = NOW()
                    RETURNING
                        id,
                        driver_id,
                        mobile_network,
                        mobile_number,
                        account_name,
                        is_verified,
                        is_active,
                        created_at,
                        updated_at
                    `,
                    [
                        authReq.driverId,
                        normalizedNetwork,
                        phone,
                        accountName === null
                            ? null
                            : String(
                                accountName,
                            ).trim(),
                    ],
                );

            const account =
                result.rows[0];

            res.status(200).json({
                success: true,
                message:
                    'Payment account saved successfully',

                account: {
                    id:
                        Number(account.id),

                    driver_id:
                        Number(
                            account.driver_id,
                        ),

                    mobile_network:
                        account.mobile_network,

                    mobile_money_number:
                        account.mobile_number,

                    account_name:
                        account.account_name,

                    is_verified:
                        account.is_verified,

                    is_active:
                        account.is_active,

                    created_at:
                        account.created_at,

                    updated_at:
                        account.updated_at,
                },
            });

        } catch (error: unknown) {

            console.error(
                '❌ Failed to save payment account:',
                error,
            );

            const dbError =
                error as {
                    message?: string;
                };

            res.status(500).json({
                success: false,
                error:
                    'Failed to save payment account',
                code:
                    'PAYMENT_ACCOUNT_SAVE_FAILED',
                details:
                    dbError.message,
            });
        }
    },
);

/* ==========================================================================
 * TOP UP WALLET
 *
 * POST /api/drivers/wallet/topup
 * ========================================================================== */

router.post(
    '/wallet/topup',
    async (
        req: Request,
        res: Response,
    ) => {

        const authReq =
            req as AuthenticatedDriverRequest;

        const authenticated =
            await authenticateDriver(
                authReq,
                res,
            );

        if (!authenticated) {
            return;
        }

        res.status(501).json({
            success: false,
            error:
                'Wallet top-up is not yet available. A verified payment provider must be connected first.',
            code:
                'TOPUP_NOT_IMPLEMENTED',
        });
    },
);

/* ==========================================================================
 * WITHDRAW MONEY
 *
 * POST /api/drivers/wallet/withdraw
 *
 * Writes to public.driver_withdrawals (the real table).
 *
 * Columns per actual schema:
 *   id, driver_id, wallet_id, amount, fee, net_amount,
 *   mobile_network, mobile_money_number, status,
 *   failure_reason, withdrawal_reference, transaction_id,
 *   created_at, updated_at
 *
 * transaction_id is left NULL — driver_transactions ledger is not
 * yet wired up. The FK is nullable so this is valid.
 * ========================================================================== */

router.post(
    '/wallet/withdraw',
    async (
        req: Request,
        res: Response,
    ) => {

        const authReq =
            req as AuthenticatedDriverRequest;

        const authenticated =
            await authenticateDriver(
                authReq,
                res,
            );

        if (!authenticated) {
            return;
        }

        const amount =
            Number(req.body.amount);

        if (
            !Number.isFinite(amount) ||
            amount <= 0
        ) {
            res.status(400).json({
                success: false,
                error:
                    'A valid withdrawal amount is required',
                code:
                    'INVALID_WITHDRAWAL_AMOUNT',
            });

            return;
        }

        if (amount < MINIMUM_WITHDRAWAL) {
            res.status(400).json({
                success: false,
                error:
                    `Minimum withdrawal amount is GH₵${MINIMUM_WITHDRAWAL.toFixed(2)}`,
                code:
                    'MINIMUM_WITHDRAWAL_NOT_MET',
                minimumAmount:
                    MINIMUM_WITHDRAWAL,
            });

            return;
        }

        try {

            /* ----------------------------------------------------------------
             * PAYMENT ACCOUNT CHECK
             * ---------------------------------------------------------------- */

            const paymentAccountResult =
                await pool.query(
                    `
                    SELECT
                        id,
                        mobile_network,
                        mobile_number,
                        account_name,
                        is_verified,
                        is_active
                    FROM public.driver_payment_accounts
                    WHERE driver_id = $1
                    LIMIT 1
                    `,
                    [
                        authReq.driverId,
                    ],
                );

            if (paymentAccountResult.rows.length === 0) {
                res.status(400).json({
                    success: false,
                    error:
                        'Please add a payment account before requesting a withdrawal',
                    code:
                        'PAYMENT_ACCOUNT_REQUIRED',
                });

                return;
            }

            const paymentAccount =
                paymentAccountResult.rows[0];

            if (!paymentAccount.is_active) {
                res.status(400).json({
                    success: false,
                    error:
                        'Your payment account is inactive',
                    code:
                        'PAYMENT_ACCOUNT_INACTIVE',
                });

                return;
            }

            if (!paymentAccount.is_verified) {
                res.status(400).json({
                    success: false,
                    error:
                        'Your payment account must be verified before withdrawal',
                    code:
                        'PAYMENT_ACCOUNT_NOT_VERIFIED',
                });

                return;
            }

            /* ----------------------------------------------------------------
             * TRANSACTION
             * ---------------------------------------------------------------- */

            const client =
                await pool.connect();

            try {

                await client.query(
                    'BEGIN',
                );

                /* ------------------------------------------------------------
                 * LOCK WALLET
                 * ------------------------------------------------------------ */

                let walletResult =
                    await client.query(
                        `
                        SELECT
                            id,
                            driver_id,
                            balance,
                            pending_balance,
                            total_earnings,
                            total_withdrawn,
                            total_commission_paid,
                            amount_owed,
                            minimum_balance
                        FROM public.driver_wallets
                        WHERE driver_id = $1
                        FOR UPDATE
                        `,
                        [
                            authReq.driverId,
                        ],
                    );

                if (walletResult.rows.length === 0) {

                    await client.query(
                        `
                        INSERT INTO public.driver_wallets (
                            driver_id,
                            balance,
                            pending_balance,
                            total_earnings,
                            total_withdrawn,
                            total_commission_paid,
                            amount_owed,
                            minimum_balance
                        )
                        VALUES (
                            $1,
                            0.00,
                            0.00,
                            0.00,
                            0.00,
                            0.00,
                            0.00,
                            100.00
                        )
                        ON CONFLICT (driver_id)
                        DO NOTHING
                        `,
                        [
                            authReq.driverId,
                        ],
                    );

                    walletResult =
                        await client.query(
                            `
                            SELECT
                                id,
                                driver_id,
                                balance,
                                pending_balance,
                                total_earnings,
                                total_withdrawn,
                                total_commission_paid,
                                amount_owed,
                                minimum_balance
                            FROM public.driver_wallets
                            WHERE driver_id = $1
                            FOR UPDATE
                            `,
                            [
                                authReq.driverId,
                            ],
                        );
                }

                if (walletResult.rows.length === 0) {
                    throw new Error(
                        'Unable to create or load driver wallet',
                    );
                }

                const wallet =
                    walletResult.rows[0];

                const currentBalance =
                    Number(
                        wallet.balance,
                    );

                const minimumBalance =
                    Number(
                        wallet.minimum_balance,
                    );

                const netAmount =
                    amount - WITHDRAWAL_FEE;

                const remainingBalance =
                    currentBalance -
                    amount;

                /* ------------------------------------------------------------
                 * BALANCE CHECK
                 * ------------------------------------------------------------ */

                if (remainingBalance < minimumBalance) {

                    await client.query(
                        'ROLLBACK',
                    );

                    res.status(400).json({
                        success: false,
                        error:
                            `Insufficient available balance. You must maintain a minimum balance of GH₵${minimumBalance.toFixed(2)}.`,
                        code:
                            'INSUFFICIENT_BALANCE',
                        currentBalance,
                        requestedAmount:
                            amount,
                        withdrawalFee:
                            WITHDRAWAL_FEE,
                        minimumBalance,
                    });

                    return;
                }

                /* ------------------------------------------------------------
                 * UPDATE WALLET BALANCE
                 * ------------------------------------------------------------ */

                const newBalance =
                    remainingBalance;

                await client.query(
                    `
                    UPDATE public.driver_wallets
                    SET
                        balance = $1,
                        total_withdrawn =
                            total_withdrawn + $2,
                        last_transaction_at = NOW(),
                        updated_at = NOW()
                    WHERE driver_id = $3
                    `,
                    [
                        newBalance,
                        amount,
                        authReq.driverId,
                    ],
                );

                /* ------------------------------------------------------------
                 * INSERT WITHDRAWAL ROW
                 *
                 * driver_withdrawals is the real table.
                 * withdrawal_reference is NOT NULL + UNIQUE, so we
                 * generate it here before insert.
                 * ------------------------------------------------------------ */

                const withdrawalReference =
                    `WD-${Date.now()}-${Math.random()
                        .toString(36)
                        .slice(2, 8)
                        .toUpperCase()}`;

                const withdrawalResult =
                    await client.query(
                        `
                        INSERT INTO public.driver_withdrawals (
                            driver_id,
                            wallet_id,
                            amount,
                            fee,
                            net_amount,
                            mobile_network,
                            mobile_money_number,
                            status,
                            withdrawal_reference
                        )
                        VALUES (
                            $1,
                            $2,
                            $3,
                            $4,
                            $5,
                            $6,
                            $7,
                            'pending',
                            $8
                        )
                        RETURNING
                            id,
                            driver_id,
                            wallet_id,
                            amount,
                            fee,
                            net_amount,
                            mobile_network,
                            mobile_money_number,
                            status,
                            failure_reason,
                            withdrawal_reference,
                            created_at,
                            updated_at
                        `,
                        [
                            authReq.driverId,
                            wallet.id,
                            amount,
                            WITHDRAWAL_FEE,
                            netAmount,
                            paymentAccount.mobile_network,
                            paymentAccount.mobile_number,
                            withdrawalReference,
                        ],
                    );

                await client.query(
                    'COMMIT',
                );

                const withdrawal =
                    withdrawalResult.rows[0];

                res.status(201).json({
                    success: true,

                    message:
                        'Withdrawal request submitted successfully',

                    withdrawal: {
                        id:
                            Number(withdrawal.id),

                        driver_id:
                            Number(
                                withdrawal.driver_id,
                            ),

                        wallet_id:
                            Number(
                                withdrawal.wallet_id,
                            ),

                        amount:
                            Number(
                                withdrawal.amount,
                            ),

                        fee:
                            Number(
                                withdrawal.fee,
                            ),

                        net_amount:
                            Number(
                                withdrawal.net_amount,
                            ),

                        mobile_network:
                            withdrawal.mobile_network,

                        mobile_money_number:
                            withdrawal.mobile_money_number,

                        status:
                            withdrawal.status,

                        failure_reason:
                            withdrawal.failure_reason,

                        withdrawal_reference:
                            withdrawal.withdrawal_reference,

                        created_at:
                            withdrawal.created_at,

                        updated_at:
                            withdrawal.updated_at,
                    },

                    wallet: {
                        previousBalance:
                            currentBalance,

                        newBalance:
                            newBalance,

                        minimumBalance:
                            minimumBalance,
                    },
                });

            } catch (error: unknown) {

                try {
                    await client.query(
                        'ROLLBACK',
                    );
                } catch (rollbackError) {
                    console.error(
                        '❌ Rollback failed:',
                        rollbackError,
                    );
                }

                console.error(
                    '❌ Withdrawal transaction failed:',
                    error,
                );

                const dbError =
                    error as {
                        message?: string;
                        code?: string;
                        detail?: string;
                    };

                res.status(500).json({
                    success: false,
                    error:
                        'Failed to process withdrawal',
                    code:
                        'WITHDRAWAL_FAILED',
                    details:
                        dbError.message,
                });

            } finally {

                client.release();
            }

        } catch (error: unknown) {

            console.error(
                '❌ Failed to process withdrawal:',
                error,
            );

            const dbError =
                error as {
                    message?: string;
                };

            res.status(500).json({
                success: false,
                error:
                    'Failed to process withdrawal',
                code:
                    'WITHDRAWAL_FAILED',
                details:
                    dbError.message,
            });
        }
    },
);

/* ==========================================================================
 * GET WITHDRAWAL HISTORY
 *
 * GET /api/drivers/wallet/withdrawals
 *
 * Reads directly from public.driver_withdrawals (the real table).
 * Every column the Flutter DriverWithdrawal model expects is on
 * that table already — no join needed.
 * ========================================================================== */

router.get(
    '/wallet/withdrawals',
    async (
        req: Request,
        res: Response,
    ) => {

        const authReq =
            req as AuthenticatedDriverRequest;

        const authenticated =
            await authenticateDriver(
                authReq,
                res,
            );

        if (!authenticated) {
            return;
        }

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        driver_id,
                        wallet_id,
                        amount,
                        fee,
                        net_amount,
                        mobile_network,
                        mobile_money_number,
                        status,
                        failure_reason,
                        withdrawal_reference,
                        transaction_id,
                        created_at,
                        updated_at
                    FROM public.driver_withdrawals
                    WHERE driver_id = $1
                    ORDER BY created_at DESC
                    `,
                    [
                        authReq.driverId,
                    ],
                );

            res.status(200).json({
                success: true,

                withdrawals:
                    result.rows.map(
                        (w: any) => ({
                            id:
                                Number(w.id),

                            driver_id:
                                Number(w.driver_id),

                            wallet_id:
                                Number(w.wallet_id),

                            amount:
                                Number(w.amount),

                            fee:
                                Number(w.fee),

                            net_amount:
                                Number(w.net_amount),

                            mobile_network:
                                w.mobile_network,

                            mobile_money_number:
                                w.mobile_money_number,

                            status:
                                w.status,

                            failure_reason:
                                w.failure_reason,

                            // NOT NULL on the table — always present.
                            withdrawal_reference:
                                w.withdrawal_reference,

                            transaction_id:
                                w.transaction_id != null
                                    ? Number(w.transaction_id)
                                    : null,

                            created_at:
                                w.created_at,

                            updated_at:
                                w.updated_at,
                        }),
                    ),
            });

        } catch (error: unknown) {

            console.error(
                '❌ Failed to load withdrawal history:',
                error,
            );

            const dbError =
                error as {
                    message?: string;
                    code?: string;
                    detail?: string;
                    hint?: string;
                };

            console.error(
                'Withdrawals DB error:',
                {
                    code: dbError.code,
                    message: dbError.message,
                    detail: dbError.detail,
                    hint: dbError.hint,
                },
            );

            res.status(500).json({
                success: false,
                error:
                    'Failed to load withdrawal history',
                code:
                    'WITHDRAWALS_LOAD_FAILED',
                details:
                    dbError.message,
            });
        }
    },
);

/* ==========================================================================
 * EXPORT ROUTER
 * ========================================================================== */

export default router;
// src/routes/driverWalletRoutes.ts
import { Router, Request, Response, NextFunction } from 'express';
import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';

const router = Router();

/* ---------------------------------------------------------------------------
 * Types
 * ------------------------------------------------------------------------- */
interface AuthenticatedDriverRequest extends Request {
    driverId?: number;
    firebaseUid?: string;
}

/* ---------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */
const MIN_TOPUP_AMOUNT = 5.00;
const MIN_WITHDRAWAL_AMOUNT = 10.00;
const MINIMUM_WALLET_BALANCE = 100.00;
const COMMISSION_PER_RIDE = 2.00;

/* ---------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */
function generateTopupReference(driverId: number): string {
    const ts = Date.now();
    const rand = Math.random().toString(36).substring(2, 8).toUpperCase();
    return `TGA-TOPUP-${driverId}-${ts}-${rand}`;
}

function generateWithdrawalReference(driverId: number): string {
    const ts = Date.now();
    const rand = Math.random().toString(36).substring(2, 8).toUpperCase();
    return `TGA-WD-${driverId}-${ts}-${rand}`;
}

function toNumber(value: unknown): number {
    const n = Number(value);
    return Number.isFinite(n) ? n : 0;
}

function normalizeGhanaMobileNumber(value: unknown): string | null {
    if (value === null || value === undefined) return null;

    const number = String(value)
        .trim()
        .replace(/\s+/g, '')
        .replace(/-/g, '');

    if (/^0\d{9}$/.test(number)) return number;
    if (/^\+233\d{9}$/.test(number)) return `0${number.substring(4)}`;
    if (/^233\d{9}$/.test(number)) return `0${number.substring(3)}`;

    return null;
}

/* ---------------------------------------------------------------------------
 * Auth middleware
 * ------------------------------------------------------------------------- */
async function authenticateDriver(
    req: AuthenticatedDriverRequest,
    res: Response,
    next: NextFunction,
): Promise<void> {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            res.status(401).json({
                success: false,
                message: 'Authentication token is required.',
                code: 'TOKEN_MISSING',
            });
            return;
        }

        if (!authHeader.startsWith('Bearer ')) {
            res.status(401).json({
                success: false,
                message: 'Invalid authorization header format.',
                code: 'INVALID_AUTH_HEADER',
            });
            return;
        }

        const token = authHeader.substring(7).trim();
        if (!token) {
            res.status(401).json({
                success: false,
                message: 'Authentication token is empty.',
                code: 'TOKEN_MISSING',
            });
            return;
        }

        let decodedToken;
        try {
            decodedToken = await firebaseAuth.verifyIdToken(token, true);
        } catch (firebaseError: any) {
            console.error('Firebase token verification failed:', {
                code: firebaseError?.code,
                message: firebaseError?.message,
            });

            const code = firebaseError?.code;

            if (code === 'auth/id-token-expired') {
                res.status(401).json({
                    success: false,
                    message: 'Authentication session expired. Please sign in again.',
                    code: 'TOKEN_EXPIRED',
                });
                return;
            }

            if (code === 'auth/id-token-revoked') {
                res.status(401).json({
                    success: false,
                    message: 'Authentication session revoked. Please sign in again.',
                    code: 'TOKEN_REVOKED',
                });
                return;
            }

            res.status(401).json({
                success: false,
                message: 'Invalid or expired authentication token.',
                code: 'INVALID_OR_EXPIRED_TOKEN',
            });
            return;
        }

        if (!decodedToken?.uid) {
            res.status(401).json({
                success: false,
                message: 'Authentication token does not contain a valid Firebase UID.',
                code: 'INVALID_TOKEN',
            });
            return;
        }

        const driverResult = await pool.query(
            `SELECT id, uid, status
               FROM public.drivers
              WHERE uid = $1
              LIMIT 1`,
            [decodedToken.uid],
        );

        if (driverResult.rows.length === 0) {
            res.status(404).json({
                success: false,
                message: 'Driver account not found.',
                code: 'DRIVER_NOT_FOUND',
            });
            return;
        }

        req.driverId = Number(driverResult.rows[0].id);
        req.firebaseUid = decodedToken.uid;
        next();
    } catch (error: any) {
        console.error('Driver authentication error:', error);
        res.status(401).json({
            success: false,
            message: 'Authentication failed.',
            code: 'AUTHENTICATION_FAILED',
        });
    }
}

/* ---------------------------------------------------------------------------
 * Wallet bootstrap
 * ------------------------------------------------------------------------- */
async function getOrCreateWallet(driverId: number) {
    await pool.query(
        `INSERT INTO public.driver_wallets (
            driver_id, balance, pending_balance, total_earnings,
            total_withdrawn, total_commission_paid, amount_owed, minimum_balance
         ) VALUES ($1, 0.00, 0.00, 0.00, 0.00, 0.00, 0.00, $2)
         ON CONFLICT (driver_id) DO NOTHING`,
        [driverId, MINIMUM_WALLET_BALANCE],
    );

    const result = await pool.query(
        `SELECT * FROM public.driver_wallets WHERE driver_id = $1 LIMIT 1`,
        [driverId],
    );

    if (result.rows.length === 0) {
        throw new Error('Unable to create or load driver wallet.');
    }

    return result.rows[0];
}

/* ===========================================================================
 * GET /wallet
 * ========================================================================= */
router.get(
    '/wallet',
    authenticateDriver,
    async (req: AuthenticatedDriverRequest, res: Response) => {
        try {
            const driverId = req.driverId!;
            const wallet = await getOrCreateWallet(driverId);

            res.json({
                success: true,
                wallet: {
                    id: wallet.id,
                    driver_id: wallet.driver_id,
                    balance: toNumber(wallet.balance),
                    pending_balance: toNumber(wallet.pending_balance),
                    total_earnings: toNumber(wallet.total_earnings),
                    total_withdrawn: toNumber(wallet.total_withdrawn),
                    total_commission_paid: toNumber(wallet.total_commission_paid),
                    amount_owed: toNumber(wallet.amount_owed),
                    minimum_balance: toNumber(wallet.minimum_balance),
                    last_transaction_at: wallet.last_transaction_at,
                    created_at: wallet.created_at,
                    updated_at: wallet.updated_at,
                },
            });
        } catch (error) {
            console.error('GET /wallet error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to load wallet.',
            });
        }
    },
);

/* ===========================================================================
 * GET /wallet/transactions
 * ========================================================================= */
router.get(
    '/wallet/transactions',
    authenticateDriver,
    async (req: AuthenticatedDriverRequest, res: Response) => {
        try {
            const driverId = req.driverId!;

            const limit = Math.min(
                Math.max(Number(req.query.limit) || 50, 1),
                100,
            );

            const offset = Math.max(Number(req.query.offset) || 0, 0);

            const result = await pool.query(
                `SELECT
                    id, driver_id, wallet_id, ride_id, amount, type, status,
                    payment_method, provider, provider_reference,
                    transaction_reference, balance_before, balance_after,
                    description, metadata, created_at, updated_at
                   FROM public.driver_transactions
                  WHERE driver_id = $1
                  ORDER BY created_at DESC
                  LIMIT $2 OFFSET $3`,
                [driverId, limit, offset],
            );

            res.json({
                success: true,
                transactions: result.rows,
            });
        } catch (error) {
            console.error('GET /wallet/transactions error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to load wallet transactions.',
            });
        }
    },
);

/* ===========================================================================
 * GET /wallet/payment-account
 * ========================================================================= */
router.get(
    '/wallet/payment-account',
    authenticateDriver,
    async (req: AuthenticatedDriverRequest, res: Response) => {
        try {
            const driverId = req.driverId!;

            const result = await pool.query(
                `SELECT id, driver_id, mobile_network, mobile_money_number,
                        account_name, is_verified, is_active,
                        created_at, updated_at
                   FROM public.driver_payment_accounts
                  WHERE driver_id = $1
                    AND is_active = TRUE
                  LIMIT 1`,
                [driverId],
            );

            res.json({
                success: true,
                account: result.rows.length === 0 ? null : result.rows[0],
            });
        } catch (error) {
            console.error('GET /wallet/payment-account error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to load payment account.',
            });
        }
    },
);

/* ===========================================================================
 * POST /wallet/payment-account
 * ========================================================================= */
router.post(
    '/wallet/payment-account',
    authenticateDriver,
    async (req: AuthenticatedDriverRequest, res: Response) => {
        try {
            const driverId = req.driverId!;

            const mobileNetwork =
                req.body.mobile_network ?? req.body.mobileNetwork;

            const mobileNumber =
                req.body.mobile_money_number ??
                req.body.mobileMoneyNumber ??
                req.body.mobileNumber;

            const accountName =
                req.body.account_name ?? req.body.accountName;

            if (!mobileNetwork || !mobileNumber) {
                res.status(400).json({
                    success: false,
                    message: 'Mobile network and mobile number are required.',
                });
                return;
            }

            const allowedNetworks = [
                'MTN', 'Telecel', 'AirtelTigo', 'AT', 'Vodafone',
            ];

            const normalizedNetwork = String(mobileNetwork).trim();

            if (!allowedNetworks.includes(normalizedNetwork)) {
                res.status(400).json({
                    success: false,
                    message: 'Invalid mobile network.',
                });
                return;
            }

            const normalizedNumber = normalizeGhanaMobileNumber(mobileNumber);

            if (!normalizedNumber) {
                res.status(400).json({
                    success: false,
                    message: 'Enter a valid Ghana mobile number.',
                });
                return;
            }

            const normalizedAccountName =
                accountName ? String(accountName).trim() : null;

            const result = await pool.query(
                `INSERT INTO public.driver_payment_accounts (
                    driver_id, mobile_network, mobile_money_number,
                    account_name, is_verified, is_active,
                    created_at, updated_at
                 ) VALUES ($1, $2, $3, $4, FALSE, TRUE, NOW(), NOW())
                 ON CONFLICT (driver_id) DO UPDATE SET
                    mobile_network      = EXCLUDED.mobile_network,
                    mobile_money_number = EXCLUDED.mobile_money_number,
                    account_name        = EXCLUDED.account_name,
                    is_verified         = FALSE,
                    is_active           = TRUE,
                    updated_at          = NOW()
                 RETURNING *`,
                [driverId, normalizedNetwork, normalizedNumber, normalizedAccountName],
            );

            res.json({
                success: true,
                message: 'Payment account saved successfully.',
                account: result.rows[0],
            });
        } catch (error) {
            console.error('POST /wallet/payment-account error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to save payment account.',
            });
        }
    },
);

/* ===========================================================================
 * POST /wallet/topup
 *
 * Direct PostgreSQL top-up. No external payment gateway.
 *  - Validates amount
 *  - Locks the wallet row
 *  - Credits balance and records a driver_transactions row atomically
 * ========================================================================= */
router.post(
    '/wallet/topup',
    authenticateDriver,
    async (req: AuthenticatedDriverRequest, res: Response) => {
        const client = await pool.connect();

        try {
            const driverId = req.driverId!;
            const amount = Number(req.body.amount);

            const paymentMethod =
                req.body.payment_method ?? req.body.paymentMethod ?? null;

            const provider =
                req.body.provider ?? null;

            if (!Number.isFinite(amount) || amount <= 0) {
                res.status(400).json({
                    success: false,
                    message: 'Enter a valid top-up amount.',
                });
                return;
            }

            const normalizedAmount = Number(amount.toFixed(2));

            if (normalizedAmount < MIN_TOPUP_AMOUNT) {
                res.status(400).json({
                    success: false,
                    message: `Minimum wallet top-up is GHS ${MIN_TOPUP_AMOUNT.toFixed(2)}.`,
                });
                return;
            }

            await client.query('BEGIN');

            // Ensure wallet exists (idempotent)
            await client.query(
                `INSERT INTO public.driver_wallets (
                    driver_id, balance, pending_balance, total_earnings,
                    total_withdrawn, total_commission_paid, amount_owed,
                    minimum_balance
                 ) VALUES ($1, 0, 0, 0, 0, 0, 0, $2)
                 ON CONFLICT (driver_id) DO NOTHING`,
                [driverId, MINIMUM_WALLET_BALANCE],
            );

            const walletResult = await client.query(
                `SELECT * FROM public.driver_wallets
                  WHERE driver_id = $1
                  FOR UPDATE`,
                [driverId],
            );

            if (walletResult.rows.length === 0) {
                await client.query('ROLLBACK');
                res.status(404).json({
                    success: false,
                    message: 'Driver wallet not found.',
                });
                return;
            }

            const wallet = walletResult.rows[0];
            const balanceBefore = toNumber(wallet.balance);
            const balanceAfter = Number((balanceBefore + normalizedAmount).toFixed(2));

            const reference = generateTopupReference(driverId);

            await client.query(
                `UPDATE public.driver_wallets
                    SET balance             = $2,
                        last_transaction_at = NOW(),
                        updated_at          = NOW()
                  WHERE id = $1`,
                [wallet.id, balanceAfter],
            );

            await client.query(
                `INSERT INTO public.driver_transactions (
                    driver_id, wallet_id, amount, type, status,
                    payment_method, provider, transaction_reference,
                    balance_before, balance_after, description, metadata,
                    created_at, updated_at
                 ) VALUES (
                    $1, $2, $3, 'topup', 'completed',
                    $4, $5, $6,
                    $7, $8, $9, $10::jsonb,
                    NOW(), NOW()
                 )`,
                [
                    driverId,
                    wallet.id,
                    normalizedAmount,
                    paymentMethod,
                    provider,
                    reference,
                    balanceBefore,
                    balanceAfter,
                    'Driver wallet top-up',
                    JSON.stringify({
                        source: 'postgres_direct',
                        driver_id: driverId,
                        wallet_id: wallet.id,
                    }),
                ],
            );

            await client.query('COMMIT');

            res.status(200).json({
                success: true,
                message: 'Wallet top-up completed successfully.',
                reference,
                amount: normalizedAmount,
                balance_before: balanceBefore,
                balance_after: balanceAfter,
                wallet: {
                    id: wallet.id,
                    driver_id: driverId,
                    balance: balanceAfter,
                    pending_balance: toNumber(wallet.pending_balance),
                    total_earnings: toNumber(wallet.total_earnings),
                    total_withdrawn: toNumber(wallet.total_withdrawn),
                    total_commission_paid: toNumber(wallet.total_commission_paid),
                    amount_owed: toNumber(wallet.amount_owed),
                    minimum_balance: toNumber(wallet.minimum_balance),
                },
            });
        } catch (error) {
            try { await client.query('ROLLBACK'); } catch (_) { }
            console.error('POST /wallet/topup error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to process wallet top-up.',
            });
        } finally {
            client.release();
        }
    },
);

/* ===========================================================================
 * POST /wallet/withdraw
 * ========================================================================= */
router.post(
    '/wallet/withdraw',
    authenticateDriver,
    async (req: AuthenticatedDriverRequest, res: Response) => {
        const client = await pool.connect();

        try {
            const driverId = req.driverId!;
            const amount = Number(req.body.amount);

            if (!Number.isFinite(amount) || amount <= 0) {
                res.status(400).json({
                    success: false,
                    message: 'Enter a valid withdrawal amount.',
                });
                return;
            }

            const normalizedAmount = Number(amount.toFixed(2));

            if (normalizedAmount < MIN_WITHDRAWAL_AMOUNT) {
                res.status(400).json({
                    success: false,
                    message: `Minimum withdrawal is GHS ${MIN_WITHDRAWAL_AMOUNT.toFixed(2)}.`,
                });
                return;
            }

            await client.query('BEGIN');

            const accountResult = await client.query(
                `SELECT * FROM public.driver_payment_accounts
                  WHERE driver_id = $1 AND is_active = TRUE
                  LIMIT 1`,
                [driverId],
            );

            if (accountResult.rows.length === 0) {
                await client.query('ROLLBACK');
                res.status(400).json({
                    success: false,
                    message: 'Please add a mobile money payment account before withdrawing.',
                });
                return;
            }

            const account = accountResult.rows[0];

            const walletResult = await client.query(
                `SELECT * FROM public.driver_wallets
                  WHERE driver_id = $1
                  FOR UPDATE`,
                [driverId],
            );

            if (walletResult.rows.length === 0) {
                await client.query('ROLLBACK');
                res.status(404).json({
                    success: false,
                    message: 'Driver wallet not found.',
                });
                return;
            }

            const wallet = walletResult.rows[0];
            const balance = toNumber(wallet.balance);
            const minimumBalance = toNumber(wallet.minimum_balance) || MINIMUM_WALLET_BALANCE;
            const available = Number((balance - minimumBalance).toFixed(2));

            if (available <= 0) {
                await client.query('ROLLBACK');
                res.status(400).json({
                    success: false,
                    message: `You must maintain at least GHS ${minimumBalance.toFixed(2)} in your wallet.`,
                    balance,
                    minimum_balance: minimumBalance,
                });
                return;
            }

            if (normalizedAmount > available) {
                await client.query('ROLLBACK');
                res.status(400).json({
                    success: false,
                    message: 'Insufficient withdrawable wallet balance.',
                    balance,
                    minimum_balance: minimumBalance,
                    maximum_withdrawable: available,
                });
                return;
            }

            const reference = generateWithdrawalReference(driverId);
            const fee = 0.00;
            const netAmount = Number((normalizedAmount - fee).toFixed(2));
            const after = Number((balance - normalizedAmount).toFixed(2));

            await client.query(
                `UPDATE public.driver_wallets
                    SET balance             = $2,
                        pending_balance     = pending_balance + $3,
                        last_transaction_at = NOW(),
                        updated_at          = NOW()
                  WHERE id = $1`,
                [wallet.id, after, normalizedAmount],
            );

            const withdrawalResult = await client.query(
                `INSERT INTO public.driver_withdrawals (
                    driver_id, wallet_id, amount, fee, net_amount,
                    mobile_network, mobile_money_number,
                    status, withdrawal_reference,
                    created_at, updated_at
                 ) VALUES (
                    $1, $2, $3, $4, $5,
                    $6, $7,
                    'pending', $8,
                    NOW(), NOW()
                 )
                 RETURNING *`,
                [
                    driverId,
                    wallet.id,
                    normalizedAmount,
                    fee,
                    netAmount,
                    account.mobile_network,
                    account.mobile_money_number,
                    reference,
                ],
            );

            const withdrawal = withdrawalResult.rows[0];

            await client.query(
                `INSERT INTO public.driver_transactions (
                    driver_id, wallet_id, amount, type, status,
                    payment_method, transaction_reference,
                    balance_before, balance_after,
                    description, metadata,
                    created_at, updated_at
                 ) VALUES (
                    $1, $2, $3, 'withdrawal', 'pending',
                    $4, $5,
                    $6, $7,
                    $8, $9::jsonb,
                    NOW(), NOW()
                 )`,
                [
                    driverId,
                    wallet.id,
                    normalizedAmount,
                    account.mobile_network,
                    reference,
                    balance,
                    after,
                    'Driver wallet withdrawal',
                    JSON.stringify({
                        withdrawal_id: withdrawal.id,
                        mobile_network: account.mobile_network,
                        mobile_money_number: account.mobile_money_number,
                        fee,
                        net_amount: netAmount,
                    }),
                ],
            );

            await client.query('COMMIT');

            res.status(201).json({
                success: true,
                message: 'Withdrawal request submitted successfully.',
                withdrawal,
                wallet_balance: after,
            });
        } catch (error) {
            try { await client.query('ROLLBACK'); } catch (_) { }
            console.error('POST /wallet/withdraw error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to create withdrawal request.',
            });
        } finally {
            client.release();
        }
    },
);

/* ===========================================================================
 * GET /wallet/withdrawals
 * ========================================================================= */
router.get(
    '/wallet/withdrawals',
    authenticateDriver,
    async (req: AuthenticatedDriverRequest, res: Response) => {
        try {
            const driverId = req.driverId!;
            const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
            const offset = Math.max(Number(req.query.offset) || 0, 0);

            const result = await pool.query(
                `SELECT id, driver_id, wallet_id, amount, fee, net_amount,
                        mobile_network, mobile_money_number,
                        status, failure_reason, withdrawal_reference,
                        created_at, updated_at
                   FROM public.driver_withdrawals
                  WHERE driver_id = $1
                  ORDER BY created_at DESC
                  LIMIT $2 OFFSET $3`,
                [driverId, limit, offset],
            );

            res.json({
                success: true,
                withdrawals: result.rows,
            });
        } catch (error) {
            console.error('GET /wallet/withdrawals error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to load withdrawals.',
            });
        }
    },
);

/* ===========================================================================
 * GET /wallet/commission-info
 *
 * Public info endpoint so the app can display the current rules.
 * ========================================================================= */
router.get(
    '/wallet/commission-info',
    authenticateDriver,
    async (_req: AuthenticatedDriverRequest, res: Response) => {
        res.json({
            success: true,
            minimum_balance: MINIMUM_WALLET_BALANCE,
            commission_per_ride: COMMISSION_PER_RIDE,
            minimum_topup_amount: MIN_TOPUP_AMOUNT,
            minimum_withdrawal_amount: MIN_WITHDRAWAL_AMOUNT,
            currency: 'GHS',
        });
    },
);

export default router;
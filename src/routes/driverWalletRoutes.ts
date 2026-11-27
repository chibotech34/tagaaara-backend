// src/routes/driverWalletRoutes.ts
import { Router, Request, Response, NextFunction } from 'express';
import pool from '../config/database';
import { firebaseAuth } from '../config/firebase';
import {
    initializeMobileMoneyCharge,
    verifyTransaction,
    generateReference,
    fromPesewas,
    submitOtp,
    type PaystackProvider,
} from '../services/paystackService';

const router = Router();

/* --------------------------------------------------------------------------- */
/* Types & constants                                                           */
/* --------------------------------------------------------------------------- */

interface AuthenticatedDriverRequest extends Request {
    driverId?: number;
    firebaseUid?: string;
}

const MIN_TOPUP_AMOUNT = 5.0;
const MAX_TOPUP_AMOUNT = 10000.0;
const MIN_WITHDRAWAL_AMOUNT = 10.0;
const MINIMUM_WALLET_BALANCE = 100.0;
const COMMISSION_PER_RIDE = 2.0;

type PaymentStatus =
    | 'success'
    | 'pending'
    | 'pay_offline'
    | 'send_otp'
    | 'failed'
    | 'reversed';

/* --------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* --------------------------------------------------------------------------- */

function generateWithdrawalReference(driverId: number): string {
    const ts = Date.now();
    const rand = Math.random().toString(36).substring(2, 8).toUpperCase();
    return `TGA-WD-${driverId}-${ts}-${rand}`;
}

function toNumber(value: unknown): number {
    const n = Number(value);
    return Number.isFinite(n) ? n : 0;
}

function amountToGHS(value: unknown): number {
    const n = Number(value);
    return Number.isFinite(n) ? Math.round(n * 100) / 100 : 0;
}

function normaliseStatus(value: unknown): PaymentStatus {
    const status = String(value ?? 'pending').toLowerCase();
    const allowed: PaymentStatus[] = [
        'success', 'pending', 'pay_offline', 'send_otp', 'failed', 'reversed',
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

function normalizeGhanaMobileNumber(value: unknown): string | null {
    if (value === null || value === undefined) return null;
    const number = String(value).trim().replace(/\s+/g, '').replace(/-/g, '');
    if (/^0\d{9}$/.test(number)) return number;
    if (/^\+233\d{9}$/.test(number)) return `0${number.substring(4)}`;
    if (/^233\d{9}$/.test(number)) return `0${number.substring(3)}`;
    return null;
}

/** Map "MTN"/"Telecel"/"AirtelTigo"/'vod'/'atl' → Paystack provider codes. */
function toPaystackProvider(value: unknown): PaystackProvider | null {
    const s = String(value ?? '').trim().toLowerCase();
    if (!s) return null;
    if (s.includes('mtn')) return 'mtn';
    if (s.includes('vod') || s.includes('telecel')) return 'vod';
    if (s.includes('atl') || s.includes('airtel')) return 'atl';
    if (s === 'mtn' || s === 'vod' || s === 'atl') return s as PaystackProvider;
    return null;
}

/* --------------------------------------------------------------------------- */
/* Auth middleware                                                             */
/* --------------------------------------------------------------------------- */

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
    } catch (error) {
        console.error('Driver authentication error:', error);
        res.status(401).json({
            success: false,
            message: 'Authentication failed.',
            code: 'AUTHENTICATION_FAILED',
        });
    }
}

/* --------------------------------------------------------------------------- */
/* Wallet bootstrap                                                            */
/* --------------------------------------------------------------------------- */

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

async function findDriverProfile(driverId: number) {
    const result = await pool.query(
        `SELECT id, uid, full_name, email, phone,
                mobile_money_provider, mobile_money_number
           FROM public.drivers
          WHERE id = $1
          LIMIT 1`,
        [driverId],
    );
    return result.rows[0] ?? null;
}

async function getDriverMomoContact(
    driverId: number,
): Promise<{ phone: string | null; provider: PaystackProvider | null }> {
    // Prefer the dedicated payment account, then the driver's own fields.
    const acct = await pool.query(
        `SELECT mobile_network, mobile_money_number
           FROM public.driver_payment_accounts
          WHERE driver_id = $1 AND is_active = TRUE
          LIMIT 1`,
        [driverId],
    );

    if (acct.rows.length) {
        return {
            phone: normalizeGhanaMobileNumber(acct.rows[0].mobile_money_number),
            provider: toPaystackProvider(acct.rows[0].mobile_network),
        };
    }

    const driver = await pool.query(
        `SELECT phone, mobile_money_provider, mobile_money_number
           FROM public.drivers
          WHERE id = $1
          LIMIT 1`,
        [driverId],
    );

    if (driver.rows.length) {
        return {
            phone: normalizeGhanaMobileNumber(
                driver.rows[0].mobile_money_number ?? driver.rows[0].phone,
            ),
            provider: toPaystackProvider(driver.rows[0].mobile_money_provider),
        };
    }

    return { phone: null, provider: null };
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
            const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
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

            res.json({ success: true, transactions: result.rows });
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

            const allowedNetworks = ['MTN', 'Telecel', 'AirtelTigo', 'AT', 'Vodafone'];
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
 * Legacy endpoint — replaced by Paystack. Kept for backward compatibility
 * so old clients get a clear signal.
 * ========================================================================= */
router.post(
    '/wallet/topup',
    authenticateDriver,
    (_req: AuthenticatedDriverRequest, res: Response) => {
        res.status(410).json({
            success: false,
            code: 'LEGACY_TOPUP_DISABLED',
            message:
                'Direct wallet top-ups are disabled. Use Paystack Mobile Money ' +
                '(POST /wallet/topup/initialize).',
        });
    },
);

/* ===========================================================================
 * POST /wallet/topup/initialize
 * -------------------------------------------------------------------------
 * Creates a paystack_transactions row (purpose='driver_wallet_topup'),
 * initiates the MoMo charge. Returns {reference, status, displayText}.
 * ========================================================================= */
router.post(
    '/wallet/topup/initialize',
    authenticateDriver,
    async (req: AuthenticatedDriverRequest, res: Response) => {
        const driverId = req.driverId!;
        const uid = req.firebaseUid!;

        const amount = amountToGHS(req.body?.amount);
        const providedPhone = String(req.body?.phone ?? '').trim();
        const providerText = String(req.body?.provider ?? '')
            .trim()
            .toLowerCase();

        if (amount < MIN_TOPUP_AMOUNT) {
            return res.status(400).json({
                success: false,
                message: `Minimum wallet top-up is GHS ${MIN_TOPUP_AMOUNT.toFixed(2)}.`,
            });
        }
        if (amount > MAX_TOPUP_AMOUNT) {
            return res.status(400).json({
                success: false,
                message: `Maximum wallet top-up is GHS ${MAX_TOPUP_AMOUNT.toFixed(2)}.`,
            });
        }

        const provider = toPaystackProvider(providerText);
        if (!provider) {
            return res.status(400).json({
                success: false,
                message: 'Unsupported mobile money provider.',
            });
        }

        try {
            const driver = await findDriverProfile(driverId);
            if (!driver) {
                return res.status(404).json({
                    success: false,
                    message: 'Driver profile not found.',
                });
            }

            const wallet = await getOrCreateWallet(driverId);

            const fallback = await getDriverMomoContact(driverId);

            const phone =
                normalizeGhanaMobileNumber(providedPhone) ?? fallback.phone;
            if (!phone) {
                return res.status(400).json({
                    success: false,
                    code: 'PHONE_REQUIRED',
                    message:
                        'No mobile money number on file. Add one to your ' +
                        'payment account or pass it in the request body.',
                });
            }

            const email =
                (req as any).decodedToken?.email ||
                driver.email ||
                `driver+${uid.slice(0, 8)}@tegaara.app`;
            const reference = generateReference('topup', uid);

            await pool.query(
                `INSERT INTO public.paystack_transactions (
                    reference, user_firebase_uid, purpose, amount, status,
                    channel, provider, phone, passenger_id, wallet_id,
                    driver_id, driver_wallet_id, ride_id
                 ) VALUES (
                    $1::varchar, $2::varchar, 'driver_wallet_topup',
                    $3::numeric, 'pending', 'mobile_money',
                    $4::varchar, $5::varchar, NULL, NULL,
                    $6::bigint, $7::bigint, NULL
                 )`,
                [reference, uid, amount, provider, phone, driver.id, wallet.id],
            );

            const charge = await initializeMobileMoneyCharge({
                email,
                amountGHS: amount,
                phone,
                provider,
                reference,
                metadata: {
                    purpose: 'driver_wallet_topup',
                    userFirebaseUid: uid,
                    driverId: driver.id,
                    driverWalletId: wallet.id,
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
            });
        } catch (error: any) {
            console.error('Initialize driver top-up failed:', error);
            return res.status(500).json({
                success: false,
                message:
                    'Could not initiate the Mobile Money payment. Please try again.',
            });
        }
    },
);

/* ===========================================================================
 * POST /wallet/topup/submit-otp
 * ========================================================================= */
router.post(
    '/wallet/topup/submit-otp',
    authenticateDriver,
    async (req: AuthenticatedDriverRequest, res: Response) => {
        const driverId = req.driverId!;
        const uid = req.firebaseUid!;

        const reference = String(req.body?.reference ?? '').trim();
        const otp = String(req.body?.otp ?? '').trim();

        if (!reference) {
            return res.status(400).json({
                success: false,
                message: 'Reference is required.',
            });
        }
        if (!/^\d{4,8}$/.test(otp)) {
            return res.status(400).json({
                success: false,
                message: 'Enter a valid verification code.',
            });
        }

        try {
            const txResult = await pool.query(
                `SELECT *
                   FROM public.paystack_transactions
                  WHERE reference = $1::varchar
                    AND user_firebase_uid = $2::varchar
                    AND purpose = 'driver_wallet_topup'
                  LIMIT 1`,
                [reference, uid],
            );

            if (!txResult.rows.length) {
                return res.status(404).json({
                    success: false,
                    message: 'Payment not found.',
                });
            }

            const tx = txResult.rows[0];

            if (tx.applied === true) {
                const bal = await pool.query(
                    `SELECT balance FROM public.driver_wallets WHERE id = $1::bigint`,
                    [tx.driver_wallet_id],
                );
                return res.json({
                    success: true,
                    status: 'success',
                    alreadyApplied: true,
                    newBalance: bal.rows.length
                        ? Number(bal.rows[0].balance) || 0
                        : null,
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
                    message:
                        'The verification code could not be accepted. Check ' +
                        'the code and try again.',
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
                const result = await applySuccessfulDriverPayment(
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
                            'The payment may have been received, but the ' +
                            'wallet update is not yet confirmed. Do not pay ' +
                            'again; check the transaction status shortly.',
                    });
                }

                return res.json({
                    success: true,
                    status: 'success',
                    alreadyApplied: result.alreadyApplied,
                    newBalance: result.newBalance,
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
            console.error('Driver top-up OTP submission failed:', error);
            return res.status(500).json({
                success: false,
                message: 'Failed to submit verification code.',
            });
        }
    },
);

/* ===========================================================================
 * GET /wallet/topup/verify/:reference
 * ========================================================================= */
router.get(
    '/wallet/topup/verify/:reference',
    authenticateDriver,
    async (req: AuthenticatedDriverRequest, res: Response) => {
        const uid = req.firebaseUid!;
        const reference = String(req.params.reference ?? '').trim();

        if (!reference) {
            return res.status(400).json({
                success: false,
                message: 'Reference is required.',
            });
        }

        try {
            const txResult = await pool.query(
                `SELECT *
                   FROM public.paystack_transactions
                  WHERE reference = $1::varchar
                    AND user_firebase_uid = $2::varchar
                    AND purpose = 'driver_wallet_topup'
                  LIMIT 1`,
                [reference, uid],
            );

            if (!txResult.rows.length) {
                return res.status(404).json({
                    success: false,
                    message: 'Payment not found.',
                });
            }

            const tx = txResult.rows[0];

            if (tx.applied === true) {
                const bal = await pool.query(
                    `SELECT balance FROM public.driver_wallets WHERE id = $1::bigint`,
                    [tx.driver_wallet_id],
                );
                return res.json({
                    success: true,
                    status: 'success',
                    alreadyApplied: true,
                    newBalance: bal.rows.length
                        ? Number(bal.rows[0].balance) || 0
                        : null,
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
                const result = await applySuccessfulDriverPayment(
                    reference,
                    paystackData,
                );

                if (!result.applied) {
                    return res.status(503).json({
                        success: false,
                        status: 'pending',
                        code: 'PAYMENT_CREDIT_PENDING',
                        reference,
                        message:
                            'Payment confirmation was received, but the ' +
                            'wallet update is not yet confirmed. Do not pay ' +
                            'again; check the status shortly.',
                    });
                }

                return res.json({
                    success: true,
                    status: 'success',
                    alreadyApplied: result.alreadyApplied,
                    newBalance: result.newBalance,
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
            console.error('Driver top-up verification failed:', error);
            return res.status(500).json({
                success: false,
                message: 'Failed to verify payment. Please try again.',
            });
        }
    },
);

/* ===========================================================================
 * POST /wallet/withdraw  (unchanged)
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
                    message:
                        'Please add a mobile money payment account before withdrawing.',
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
            const minimumBalance =
                toNumber(wallet.minimum_balance) || MINIMUM_WALLET_BALANCE;
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
            const fee = 0.0;
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
            try { await client.query('ROLLBACK'); } catch { }
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

            res.json({ success: true, withdrawals: result.rows });
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
            maximum_topup_amount: MAX_TOPUP_AMOUNT,
            minimum_withdrawal_amount: MIN_WITHDRAWAL_AMOUNT,
            currency: 'GHS',
        });
    },
);

/* ===========================================================================
 * applySuccessfulDriverPayment — idempotent wallet credit for driver top-ups
 * -------------------------------------------------------------------------
 * Called from both the verify endpoint and the Paystack webhook.
 * Uses FOR UPDATE on the paystack_transactions row so OTP resubmits, verify
 * races, and webhook retries cannot double-credit the driver wallet.
 * The notify_driver_topup trigger fires on driver_transactions insert.
 * ========================================================================= */
export async function applySuccessfulDriverPayment(
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

        const txResult = await client.query(
            `SELECT *
               FROM public.paystack_transactions
              WHERE reference = $1::varchar
                AND purpose = 'driver_wallet_topup'
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
            if (tx.driver_wallet_id) {
                const r = await client.query(
                    `SELECT balance FROM public.driver_wallets WHERE id = $1::bigint`,
                    [tx.driver_wallet_id],
                );
                if (r.rows.length) balance = Number(r.rows[0].balance) || 0;
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
            console.error('Driver top-up amount mismatch:', {
                reference,
                paidGHS,
                expectedGHS,
            });
            await client.query(
                `UPDATE public.paystack_transactions
                 SET paystack_verify = $1::jsonb, updated_at = NOW()
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

        const walletResult = await client.query(
            `SELECT id, driver_id, balance
               FROM public.driver_wallets
              WHERE id = $1::bigint
              LIMIT 1
              FOR UPDATE`,
            [tx.driver_wallet_id],
        );

        if (!walletResult.rows.length) {
            throw new Error('Driver wallet not found for verified top-up.');
        }

        const wallet = walletResult.rows[0];
        const before = Number(wallet.balance) || 0;
        const after = Math.round((before + expectedGHS) * 100) / 100;

        await client.query(
            `UPDATE public.driver_wallets
             SET balance             = $1::numeric,
                 last_transaction_at = NOW(),
                 updated_at          = NOW()
             WHERE id = $2::bigint`,
            [after, wallet.id],
        );

        // The notify_driver_topup trigger turns this into a driver_notification.
        await client.query(
            `INSERT INTO public.driver_transactions (
                driver_id, wallet_id, ride_id, amount, type, status,
                payment_method, provider, provider_reference,
                transaction_reference, balance_before, balance_after,
                description, metadata, created_at, updated_at
             ) VALUES (
                $1::bigint, $2::bigint, NULL, $3::numeric, 'topup', 'completed',
                'paystack_momo', $4::varchar, $5::varchar,
                $6::varchar, $7::numeric, $8::numeric,
                $9::text, $10::jsonb, NOW(), NOW()
             )`,
            [
                wallet.driver_id,
                wallet.id,
                expectedGHS,
                tx.provider ?? 'mtn',
                reference,
                `PAYSTACK-${reference}`,
                before,
                after,
                `Paystack top-up reference ${reference}`,
                JSON.stringify({ source: 'paystack', reference }),
            ],
        );

        await client.query(
            `UPDATE public.paystack_transactions
             SET applied        = TRUE,
                 status         = 'success',
                 paystack_verify = $1::jsonb,
                 completed_at   = NOW(),
                 updated_at     = NOW()
             WHERE reference = $2::varchar AND applied = FALSE`,
            [JSON.stringify(paystackData), reference],
        );

        await client.query('COMMIT');

        return {
            applied: true,
            alreadyApplied: false,
            purpose: tx.purpose,
            newBalance: after,
        };
    } catch (error) {
        try { await client.query('ROLLBACK'); } catch { }
        console.error(
            `Driver top-up application failed for ${reference}:`,
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

export default router;
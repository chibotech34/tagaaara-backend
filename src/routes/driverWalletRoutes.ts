// src/routes/driverWalletRoutes.ts

import {
    Router,
    Request,
    Response,
    NextFunction,
} from 'express';

import axios from 'axios';

import pool from '../config/database';

import { firebaseAuth } from '../config/firebase';

const router = Router();

/*
|--------------------------------------------------------------------------
| TYPES
|--------------------------------------------------------------------------
*/

interface AuthenticatedDriverRequest extends Request {
    driverId?: number;
    firebaseUid?: string;
}

/*
|--------------------------------------------------------------------------
| PAYSTACK CONFIGURATION
|--------------------------------------------------------------------------
*/

const PAYSTACK_BASE_URL = 'https://api.paystack.co';

const PAYSTACK_SECRET_KEY =
    process.env.PAYSTACK_SECRET_KEY || '';

const PAYSTACK_CURRENCY =
    process.env.PAYSTACK_CURRENCY || 'GHS';

/*
|--------------------------------------------------------------------------
| CONSTANTS
|--------------------------------------------------------------------------
*/

const MIN_TOPUP_AMOUNT = 5.00;

const MIN_WITHDRAWAL_AMOUNT = 10.00;

const MINIMUM_WALLET_BALANCE = 100.00;

/*
|--------------------------------------------------------------------------
| PAYSTACK HEADERS
|--------------------------------------------------------------------------
*/

function getPaystackHeaders() {
    if (!PAYSTACK_SECRET_KEY) {
        throw new Error(
            'PAYSTACK_SECRET_KEY is not configured'
        );
    }

    return {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json',
    };
}

/*
|--------------------------------------------------------------------------
| HELPERS
|--------------------------------------------------------------------------
*/

/**
 * Generate a unique wallet top-up reference.
 */
function generateTopupReference(
    driverId: number
): string {
    const timestamp = Date.now();

    const randomPart =
        Math.random()
            .toString(36)
            .substring(2, 8)
            .toUpperCase();

    return `TGA-TOPUP-${driverId}-${timestamp}-${randomPart}`;
}

/**
 * Generate a unique withdrawal reference.
 */
function generateWithdrawalReference(
    driverId: number
): string {
    const timestamp = Date.now();

    const randomPart =
        Math.random()
            .toString(36)
            .substring(2, 8)
            .toUpperCase();

    return `TGA-WD-${driverId}-${timestamp}-${randomPart}`;
}

/**
 * Convert Ghana Cedis to Paystack subunit.
 *
 * GHS 10.50 -> 1050
 */
function toPaystackAmount(
    amount: number
): number {
    return Math.round(amount * 100);
}

/**
 * Convert Paystack amount back to GHS.
 */
function fromPaystackAmount(
    amount: number
): number {
    return Number(
        (amount / 100).toFixed(2)
    );
}

/**
 * Safely convert database numeric values.
 */
function toNumber(
    value: unknown
): number {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return 0;
    }

    return number;
}

/*
|--------------------------------------------------------------------------
| DRIVER EMAIL
|--------------------------------------------------------------------------
*/

async function getDriverEmail(
    driverId: number
): Promise<string> {

    const result = await pool.query(
        `
        SELECT *
        FROM public.drivers
        WHERE id = $1
        LIMIT 1
        `,
        [driverId]
    );

    if (result.rows.length === 0) {
        throw new Error(
            'Driver account not found'
        );
    }

    const driver = result.rows[0];

    const possibleEmailFields = [
        'email',
        'email_address',
        'contact_email',
        'user_email',
    ];

    for (const field of possibleEmailFields) {

        if (
            driver[field] &&
            typeof driver[field] === 'string'
        ) {
            const email =
                driver[field].trim();

            if (email.includes('@')) {
                return email;
            }
        }
    }

    return `driver-${driverId}@tegaara.app`;
}

/*
|--------------------------------------------------------------------------
| AUTHENTICATE DRIVER
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| Flutter must send a Firebase ID token:
|
| Authorization: Bearer <FIREBASE_ID_TOKEN>
|
| NOT the Firebase custom token.
|
|--------------------------------------------------------------------------
*/

async function authenticateDriver(
    req: AuthenticatedDriverRequest,
    res: Response,
    next: NextFunction
): Promise<void> {

    try {

        const authHeader =
            req.headers.authorization;

        /*
        |--------------------------------------------------------------------------
        | Authorization header missing
        |--------------------------------------------------------------------------
        */

        if (!authHeader) {
            res.status(401).json({
                success: false,
                message:
                    'Authentication token is required.',
                code: 'TOKEN_MISSING',
            });

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Authorization header malformed
        |--------------------------------------------------------------------------
        */

        if (
            !authHeader.startsWith('Bearer ')
        ) {
            res.status(401).json({
                success: false,
                message:
                    'Invalid authorization header format.',
                code: 'INVALID_AUTH_HEADER',
            });

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Extract token
        |--------------------------------------------------------------------------
        */

        const token =
            authHeader
                .substring(7)
                .trim();

        if (!token) {
            res.status(401).json({
                success: false,
                message:
                    'Authentication token is empty.',
                code: 'TOKEN_MISSING',
            });

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Verify Firebase ID token
        |--------------------------------------------------------------------------
        */

        const decodedToken =
            await firebaseAuth.verifyIdToken(
                token,
                false
            );

        if (!decodedToken?.uid) {
            res.status(401).json({
                success: false,
                message:
                    'Authentication token does not contain a valid Firebase UID.',
                code: 'INVALID_TOKEN',
            });

            return;
        }

        const firebaseUid =
            decodedToken.uid;

        /*
        |--------------------------------------------------------------------------
        | Find driver
        |--------------------------------------------------------------------------
        |
        | IMPORTANT:
        |
        | Your drivers table uses:
        |
        | uid
        |
        | NOT:
        |
        | firebase_uid
        |
        |--------------------------------------------------------------------------
        */

        const driverResult =
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
                [firebaseUid]
            );

        if (
            driverResult.rows.length === 0
        ) {
            res.status(404).json({
                success: false,
                message:
                    'Driver account not found.',
                code: 'DRIVER_NOT_FOUND',
            });

            return;
        }

        const driver =
            driverResult.rows[0];

        /*
        |--------------------------------------------------------------------------
        | Attach authenticated driver
        |--------------------------------------------------------------------------
        */

        req.driverId =
            Number(driver.id);

        req.firebaseUid =
            firebaseUid;

        /*
        |--------------------------------------------------------------------------
        | Continue
        |--------------------------------------------------------------------------
        */

        next();

    } catch (error: any) {

        console.error(
            'Driver authentication error:',
            {
                code: error?.code,
                message: error?.message,
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Firebase ID token expired
        |--------------------------------------------------------------------------
        */

        if (
            error?.code ===
            'auth/id-token-expired'
        ) {
            res.status(401).json({
                success: false,
                message:
                    'Your authentication session has expired. Please refresh your session and try again.',
                code: 'TOKEN_EXPIRED',
            });

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Firebase ID token revoked
        |--------------------------------------------------------------------------
        */

        if (
            error?.code ===
            'auth/id-token-revoked'
        ) {
            res.status(401).json({
                success: false,
                message:
                    'Your authentication session has been revoked. Please sign in again.',
                code: 'TOKEN_REVOKED',
            });

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Firebase invalid token
        |--------------------------------------------------------------------------
        */

        if (
            error?.code ===
            'auth/invalid-id-token'
        ) {
            res.status(401).json({
                success: false,
                message:
                    'Invalid authentication token.',
                code: 'INVALID_TOKEN',
            });

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Generic Firebase authentication failure
        |--------------------------------------------------------------------------
        */

        res.status(401).json({
            success: false,
            message:
                'Invalid or expired authentication token.',
            code: 'INVALID_OR_EXPIRED_TOKEN',
        });
    }
}

/*
|--------------------------------------------------------------------------
| GET OR CREATE DRIVER WALLET
|--------------------------------------------------------------------------
*/

async function getOrCreateWallet(
    driverId: number
) {

    let result =
        await pool.query(
            `
            SELECT *
            FROM public.driver_wallets
            WHERE driver_id = $1
            LIMIT 1
            `,
            [driverId]
        );

    if (result.rows.length > 0) {
        return result.rows[0];
    }

    result =
        await pool.query(
            `
            INSERT INTO public.driver_wallets (
                driver_id,
                balance,
                pending_balance,
                total_earnings,
                total_withdrawn,
                minimum_balance
            )
            VALUES (
                $1,
                0.00,
                0.00,
                0.00,
                0.00,
                $2
            )
            RETURNING *
            `,
            [
                driverId,
                MINIMUM_WALLET_BALANCE,
            ]
        );

    return result.rows[0];
}

/*
|--------------------------------------------------------------------------
| GET WALLET
|--------------------------------------------------------------------------
*/

router.get(
    '/wallet',
    authenticateDriver,
    async (
        req: AuthenticatedDriverRequest,
        res: Response
    ) => {

        try {

            const driverId =
                req.driverId!;

            const wallet =
                await getOrCreateWallet(
                    driverId
                );

            res.json({
                success: true,

                wallet: {
                    id: wallet.id,

                    driverId:
                        wallet.driver_id,

                    balance:
                        toNumber(
                            wallet.balance
                        ),

                    pendingBalance:
                        toNumber(
                            wallet.pending_balance
                        ),

                    totalEarnings:
                        toNumber(
                            wallet.total_earnings
                        ),

                    totalWithdrawn:
                        toNumber(
                            wallet.total_withdrawn
                        ),

                    totalCommissionPaid:
                        toNumber(
                            wallet.total_commission_paid
                        ),

                    amountOwed:
                        toNumber(
                            wallet.amount_owed
                        ),

                    minimumBalance:
                        toNumber(
                            wallet.minimum_balance
                        ),

                    lastTransactionAt:
                        wallet.last_transaction_at,

                    createdAt:
                        wallet.created_at,

                    updatedAt:
                        wallet.updated_at,
                },
            });

        } catch (error) {

            console.error(
                'GET /wallet error:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Failed to load wallet.',
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| GET WALLET TRANSACTIONS
|--------------------------------------------------------------------------
*/

router.get(
    '/wallet/transactions',
    authenticateDriver,
    async (
        req: AuthenticatedDriverRequest,
        res: Response
    ) => {

        try {

            const driverId =
                req.driverId!;

            const limit =
                Math.min(
                    Math.max(
                        Number(
                            req.query.limit
                        ) || 50,
                        1
                    ),
                    100
                );

            const offset =
                Math.max(
                    Number(
                        req.query.offset
                    ) || 0,
                    0
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
                        driverId,
                        limit,
                        offset,
                    ]
                );

            res.json({
                success: true,

                transactions:
                    result.rows.map(
                        (transaction) => ({
                            id:
                                transaction.id,

                            walletId:
                                transaction.wallet_id,

                            driverId:
                                transaction.driver_id,

                            transactionType:
                                transaction.transaction_type,

                            amount:
                                toNumber(
                                    transaction.amount
                                ),

                            balanceBefore:
                                toNumber(
                                    transaction.balance_before
                                ),

                            balanceAfter:
                                toNumber(
                                    transaction.balance_after
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
                        })
                    ),
            });

        } catch (error) {

            console.error(
                'GET /wallet/transactions error:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Failed to load wallet transactions.',
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| GET PAYMENT ACCOUNT
|--------------------------------------------------------------------------
*/

router.get(
    '/wallet/payment-account',
    authenticateDriver,
    async (
        req: AuthenticatedDriverRequest,
        res: Response
    ) => {

        try {

            const driverId =
                req.driverId!;

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
                      AND is_active = TRUE
                    LIMIT 1
                    `,
                    [driverId]
                );

            if (
                result.rows.length === 0
            ) {
                res.json({
                    success: true,
                    paymentAccount: null,
                });

                return;
            }

            const account =
                result.rows[0];

            res.json({
                success: true,

                paymentAccount: {
                    id:
                        account.id,

                    driverId:
                        account.driver_id,

                    mobileNetwork:
                        account.mobile_network,

                    mobileNumber:
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

        } catch (error) {

            console.error(
                'GET /wallet/payment-account error:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Failed to load payment account.',
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| SAVE / UPDATE PAYMENT ACCOUNT
|--------------------------------------------------------------------------
*/

router.post(
    '/wallet/payment-account',
    authenticateDriver,
    async (
        req: AuthenticatedDriverRequest,
        res: Response
    ) => {

        try {

            const driverId =
                req.driverId!;

            const {
                mobileNetwork,
                mobileNumber,
                accountName,
            } = req.body;

            if (
                !mobileNetwork ||
                !mobileNumber ||
                !accountName
            ) {
                res.status(400).json({
                    success: false,
                    message:
                        'Mobile network, mobile number and account name are required.',
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

            if (
                !allowedNetworks.includes(
                    String(mobileNetwork)
                )
            ) {
                res.status(400).json({
                    success: false,
                    message:
                        'Invalid mobile network.',
                });

                return;
            }

            const cleanedNumber =
                String(mobileNumber)
                    .replace(/\s+/g, '')
                    .replace(/-/g, '');

            /*
            |--------------------------------------------------------------------------
            | Correct Ghana phone regex
            |--------------------------------------------------------------------------
            */

            const ghanaPhoneRegex =
                /^(?:0\d{9}|\+233\d{9})$/;

            if (
                !ghanaPhoneRegex.test(
                    cleanedNumber
                )
            ) {
                res.status(400).json({
                    success: false,
                    message:
                        'Enter a valid Ghana mobile number.',
                });

                return;
            }

            /*
            |--------------------------------------------------------------------------
            | UPSERT
            |--------------------------------------------------------------------------
            |
            | driver_payment_accounts.driver_id is UNIQUE.
            |
            | Therefore we update the existing account instead
            | of inserting another row.
            |
            |--------------------------------------------------------------------------
            */

            const result =
                await pool.query(
                    `
                    INSERT INTO public.driver_payment_accounts (
                        driver_id,
                        mobile_network,
                        mobile_money_number,
                        account_name,
                        is_verified,
                        is_active,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        FALSE,
                        TRUE,
                        NOW(),
                        NOW()
                    )
                    ON CONFLICT (driver_id)
                    DO UPDATE SET
                        mobile_network =
                            EXCLUDED.mobile_network,

                        mobile_money_number =
                            EXCLUDED.mobile_money_number,

                        account_name =
                            EXCLUDED.account_name,

                        is_verified =
                            FALSE,

                        is_active =
                            TRUE,

                        updated_at =
                            NOW()

                    RETURNING *
                    `,
                    [
                        driverId,
                        String(
                            mobileNetwork
                        ).trim(),

                        cleanedNumber,

                        String(
                            accountName
                        ).trim(),
                    ]
                );

            res.status(200).json({
                success: true,
                message:
                    'Payment account saved successfully.',

                paymentAccount:
                    result.rows[0],
            });

        } catch (error) {

            console.error(
                'POST /wallet/payment-account error:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Failed to save payment account.',
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| POST WALLET TOP-UP
|--------------------------------------------------------------------------
*/

router.post(
    '/wallet/topup',
    authenticateDriver,
    async (
        req: AuthenticatedDriverRequest,
        res: Response
    ) => {

        try {

            const driverId =
                req.driverId!;

            if (!PAYSTACK_SECRET_KEY) {
                res.status(500).json({
                    success: false,
                    message:
                        'Paystack is not configured on the server. Please add PAYSTACK_SECRET_KEY.',
                });

                return;
            }

            const amount =
                Number(
                    req.body.amount
                );

            if (
                !Number.isFinite(amount) ||
                amount <= 0
            ) {
                res.status(400).json({
                    success: false,
                    message:
                        'Enter a valid top-up amount.',
                });

                return;
            }

            const normalizedAmount =
                Number(
                    amount.toFixed(2)
                );

            if (
                normalizedAmount <
                MIN_TOPUP_AMOUNT
            ) {
                res.status(400).json({
                    success: false,
                    message:
                        `Minimum wallet top-up is GHS ${MIN_TOPUP_AMOUNT.toFixed(2)}.`,
                });

                return;
            }

            const wallet =
                await getOrCreateWallet(
                    driverId
                );

            const driverEmail =
                await getDriverEmail(
                    driverId
                );

            const reference =
                generateTopupReference(
                    driverId
                );

            const paystackAmount =
                toPaystackAmount(
                    normalizedAmount
                );

            const topupResult =
                await pool.query(
                    `
                    INSERT INTO public.wallet_topups (
                        driver_id,
                        wallet_id,
                        reference,
                        provider,
                        amount,
                        currency,
                        status,
                        metadata
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        'paystack',
                        $4,
                        $5,
                        'pending',
                        $6::jsonb
                    )
                    RETURNING *
                    `,
                    [
                        driverId,

                        wallet.id,

                        reference,

                        normalizedAmount,

                        PAYSTACK_CURRENCY,

                        JSON.stringify({
                            driver_id:
                                driverId,

                            wallet_id:
                                wallet.id,

                            purpose:
                                'driver_wallet_topup',

                            provider:
                                'paystack',
                        }),
                    ]
                );

            let paystackResponse;

            try {

                paystackResponse =
                    await axios.post(
                        `${PAYSTACK_BASE_URL}/transaction/initialize`,

                        {
                            email:
                                driverEmail,

                            amount:
                                String(
                                    paystackAmount
                                ),

                            currency:
                                PAYSTACK_CURRENCY,

                            reference,

                            channels: [
                                'card',
                                'mobile_money',
                            ],

                            metadata:
                                JSON.stringify({
                                    driver_id:
                                        driverId,

                                    wallet_id:
                                        wallet.id,

                                    topup_id:
                                        topupResult
                                            .rows[0]
                                            .id,

                                    topup_reference:
                                        reference,

                                    purpose:
                                        'driver_wallet_topup',
                                }),
                        },

                        {
                            headers:
                                getPaystackHeaders(),

                            timeout:
                                30000,
                        }
                    );

            } catch (paystackError: any) {

                console.error(
                    'Paystack initialization error:',
                    paystackError?.response?.data ||
                    paystackError
                );

                await pool.query(
                    `
                    UPDATE public.wallet_topups
                    SET
                        status = 'failed',
                        paystack_status = $2,
                        updated_at = NOW()
                    WHERE reference = $1
                    `,
                    [
                        reference,

                        paystackError
                            ?.response
                            ?.data
                            ?.message ||
                        'Paystack initialization failed',
                    ]
                );

                res.status(502).json({
                    success: false,
                    message:
                        'Unable to initialize Paystack payment.',
                    reference,
                });

                return;
            }

            if (
                !paystackResponse.data?.status ||
                !paystackResponse.data?.data
            ) {

                await pool.query(
                    `
                    UPDATE public.wallet_topups
                    SET
                        status = 'failed',
                        paystack_status = $2,
                        updated_at = NOW()
                    WHERE reference = $1
                    `,
                    [
                        reference,

                        paystackResponse
                            .data
                            ?.message ||
                        'Paystack initialization failed',
                    ]
                );

                res.status(502).json({
                    success: false,
                    message:
                        'Paystack could not initialize the payment.',
                    reference,
                });

                return;
            }

            const paystackData =
                paystackResponse
                    .data
                    .data;

            if (
                paystackData.reference !==
                reference
            ) {

                await pool.query(
                    `
                    UPDATE public.wallet_topups
                    SET
                        status = 'failed',
                        paystack_status = 'reference_mismatch',
                        updated_at = NOW()
                    WHERE reference = $1
                    `,
                    [reference]
                );

                res.status(502).json({
                    success: false,
                    message:
                        'Payment reference verification failed.',
                });

                return;
            }

            await pool.query(
                `
                UPDATE public.wallet_topups
                SET
                    authorization_url = $2,
                    access_code = $3,
                    updated_at = NOW()
                WHERE reference = $1
                `,
                [
                    reference,

                    paystackData
                        .authorization_url,

                    paystackData
                        .access_code,
                ]
            );

            res.status(200).json({
                success: true,

                message:
                    'Wallet top-up initialized successfully.',

                topup: {
                    reference,

                    amount:
                        normalizedAmount,

                    currency:
                        PAYSTACK_CURRENCY,

                    status:
                        'pending',

                    authorizationUrl:
                        paystackData
                            .authorization_url,

                    accessCode:
                        paystackData
                            .access_code,
                },
            });

        } catch (error) {

            console.error(
                'POST /wallet/topup error:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Failed to initialize wallet top-up.',
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| VERIFY WALLET TOP-UP
|--------------------------------------------------------------------------
*/

router.get(
    '/wallet/topup/verify/:reference',
    authenticateDriver,
    async (
        req: AuthenticatedDriverRequest,
        res: Response
    ) => {

        const client =
            await pool.connect();

        try {

            const driverId =
                req.driverId!;

            const reference =
                String(
                    req.params.reference || ''
                ).trim();

            if (!reference) {
                res.status(400).json({
                    success: false,
                    message:
                        'Payment reference is required.',
                });

                return;
            }

            const topupResult =
                await client.query(
                    `
                    SELECT *
                    FROM public.wallet_topups
                    WHERE reference = $1
                      AND driver_id = $2
                    LIMIT 1
                    `,
                    [
                        reference,
                        driverId,
                    ]
                );

            if (
                topupResult.rows.length === 0
            ) {
                res.status(404).json({
                    success: false,
                    message:
                        'Wallet top-up transaction not found.',
                });

                return;
            }

            const topup =
                topupResult.rows[0];

            if (
                topup.status ===
                'successful'
            ) {

                const wallet =
                    await getOrCreateWallet(
                        driverId
                    );

                res.json({
                    success: true,

                    alreadyProcessed:
                        true,

                    message:
                        'Wallet top-up has already been completed.',

                    reference,

                    amount:
                        toNumber(
                            topup.amount
                        ),

                    walletBalance:
                        toNumber(
                            wallet.balance
                        ),
                });

                return;
            }

            let paystackResponse;

            try {

                paystackResponse =
                    await axios.get(
                        `${PAYSTACK_BASE_URL}/transaction/verify/${encodeURIComponent(reference)}`,

                        {
                            headers:
                                getPaystackHeaders(),

                            timeout:
                                30000,
                        }
                    );

            } catch (paystackError: any) {

                console.error(
                    'Paystack verification error:',
                    paystackError?.response?.data ||
                    paystackError
                );

                res.status(502).json({
                    success: false,
                    message:
                        'Unable to verify payment with Paystack.',
                    reference,
                });

                return;
            }

            if (
                !paystackResponse
                    .data
                    ?.status ||
                !paystackResponse
                    .data
                    ?.data
            ) {
                res.status(400).json({
                    success: false,
                    message:
                        'Paystack could not verify this transaction.',
                    reference,
                });

                return;
            }

            const payment =
                paystackResponse
                    .data
                    .data;

            if (
                payment.reference !==
                reference
            ) {
                res.status(400).json({
                    success: false,
                    message:
                        'Payment reference does not match.',
                });

                return;
            }

            if (
                payment.status !==
                'success'
            ) {

                await pool.query(
                    `
                    UPDATE public.wallet_topups
                    SET
                        paystack_status = $2,
                        updated_at = NOW()
                    WHERE reference = $1
                    `,
                    [
                        reference,

                        payment.status ||
                        'unknown',
                    ]
                );

                res.status(400).json({
                    success: false,

                    message:
                        'Payment has not been completed.',

                    paymentStatus:
                        payment.status,

                    reference,
                });

                return;
            }

            if (
                payment.currency !==
                PAYSTACK_CURRENCY
            ) {
                res.status(400).json({
                    success: false,
                    message:
                        'Payment currency does not match.',
                });

                return;
            }

            const expectedAmount =
                toPaystackAmount(
                    toNumber(
                        topup.amount
                    )
                );

            const paidAmount =
                Number(
                    payment.amount
                );

            if (
                paidAmount !==
                expectedAmount
            ) {

                await pool.query(
                    `
                    UPDATE public.wallet_topups
                    SET
                        status = 'amount_mismatch',
                        paystack_status = $2,
                        updated_at = NOW()
                    WHERE reference = $1
                    `,
                    [
                        reference,
                        'amount_mismatch',
                    ]
                );

                res.status(400).json({
                    success: false,

                    message:
                        'Payment amount does not match the requested top-up amount.',

                    expectedAmount:
                        fromPaystackAmount(
                            expectedAmount
                        ),

                    paidAmount:
                        fromPaystackAmount(
                            paidAmount
                        ),
                });

                return;
            }

            /*
            |--------------------------------------------------------------------------
            | START TRANSACTION
            |--------------------------------------------------------------------------
            */

            await client.query(
                'BEGIN'
            );

            /*
            |--------------------------------------------------------------------------
            | LOCK TOP-UP
            |--------------------------------------------------------------------------
            */

            const lockedTopup =
                await client.query(
                    `
                    SELECT *
                    FROM public.wallet_topups
                    WHERE reference = $1
                      AND driver_id = $2
                    FOR UPDATE
                    `,
                    [
                        reference,
                        driverId,
                    ]
                );

            if (
                lockedTopup.rows.length === 0
            ) {

                await client.query(
                    'ROLLBACK'
                );

                res.status(404).json({
                    success: false,
                    message:
                        'Top-up transaction no longer exists.',
                });

                return;
            }

            const currentTopup =
                lockedTopup.rows[0];

            if (
                currentTopup.status ===
                'successful'
            ) {

                await client.query(
                    'COMMIT'
                );

                const wallet =
                    await getOrCreateWallet(
                        driverId
                    );

                res.json({
                    success: true,

                    alreadyProcessed:
                        true,

                    message:
                        'Wallet top-up has already been completed.',

                    reference,

                    amount:
                        toNumber(
                            currentTopup.amount
                        ),

                    walletBalance:
                        toNumber(
                            wallet.balance
                        ),
                });

                return;
            }

            /*
            |--------------------------------------------------------------------------
            | LOCK WALLET
            |--------------------------------------------------------------------------
            */

            const walletResult =
                await client.query(
                    `
                    SELECT *
                    FROM public.driver_wallets
                    WHERE id = $1
                      AND driver_id = $2
                    FOR UPDATE
                    `,
                    [
                        currentTopup.wallet_id,
                        driverId,
                    ]
                );

            if (
                walletResult.rows.length === 0
            ) {

                await client.query(
                    'ROLLBACK'
                );

                res.status(404).json({
                    success: false,
                    message:
                        'Driver wallet not found.',
                });

                return;
            }

            const wallet =
                walletResult.rows[0];

            const balanceBefore =
                toNumber(
                    wallet.balance
                );

            const topupAmount =
                toNumber(
                    currentTopup.amount
                );

            const balanceAfter =
                Number(
                    (
                        balanceBefore +
                        topupAmount
                    ).toFixed(2)
                );

            /*
            |--------------------------------------------------------------------------
            | CREDIT WALLET
            |--------------------------------------------------------------------------
            */

            await client.query(
                `
                UPDATE public.driver_wallets
                SET
                    balance = $2,
                    last_transaction_at = NOW(),
                    updated_at = NOW()
                WHERE id = $1
                `,
                [
                    wallet.id,
                    balanceAfter,
                ]
            );

            /*
            |--------------------------------------------------------------------------
            | RECORD TRANSACTION
            |--------------------------------------------------------------------------
            */

            await client.query(
                `
                INSERT INTO public.driver_wallet_transactions (
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
                )
                VALUES (
                    $1,
                    $2,
                    'top_up',
                    $3,
                    $4,
                    $5,
                    $6,
                    $7,
                    'completed',
                    $8::jsonb,
                    NOW()
                )
                `,
                [
                    wallet.id,

                    driverId,

                    topupAmount,

                    balanceBefore,

                    balanceAfter,

                    reference,

                    'Wallet top-up via Paystack',

                    JSON.stringify({
                        provider:
                            'paystack',

                        paystackTransactionId:
                            String(
                                payment.id
                            ),

                        paystackStatus:
                            payment.status,

                        paymentChannel:
                            payment.channel,

                        paidAt:
                            payment.paid_at ||
                            null,
                    }),
                ]
            );

            /*
            |--------------------------------------------------------------------------
            | MARK TOP-UP SUCCESSFUL
            |--------------------------------------------------------------------------
            */

            await client.query(
                `
                UPDATE public.wallet_topups
                SET
                    status = 'successful',
                    paystack_transaction_id = $2,
                    paystack_status = $3,
                    completed_at = NOW(),
                    updated_at = NOW()
                WHERE id = $1
                `,
                [
                    currentTopup.id,

                    String(
                        payment.id
                    ),

                    payment.status,
                ]
            );

            await client.query(
                'COMMIT'
            );

            res.json({
                success: true,

                message:
                    'Wallet top-up completed successfully.',

                reference,

                amount:
                    topupAmount,

                currency:
                    PAYSTACK_CURRENCY,

                walletBalance:
                    balanceAfter,

                transactionId:
                    payment.id,
            });

        } catch (error) {

            try {
                await client.query(
                    'ROLLBACK'
                );
            } catch (_) {
                // Ignore rollback failure.
            }

            console.error(
                'GET /wallet/topup/verify error:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Failed to verify wallet top-up.',
            });

        } finally {

            client.release();
        }
    }
);

/*
|--------------------------------------------------------------------------
| CREATE WITHDRAWAL
|--------------------------------------------------------------------------
*/

router.post(
    '/wallet/withdraw',
    authenticateDriver,
    async (
        req: AuthenticatedDriverRequest,
        res: Response
    ) => {

        const client =
            await pool.connect();

        try {

            const driverId =
                req.driverId!;

            const amount =
                Number(
                    req.body.amount
                );

            if (
                !Number.isFinite(amount) ||
                amount <= 0
            ) {
                res.status(400).json({
                    success: false,
                    message:
                        'Enter a valid withdrawal amount.',
                });

                return;
            }

            const normalizedAmount =
                Number(
                    amount.toFixed(2)
                );

            if (
                normalizedAmount <
                MIN_WITHDRAWAL_AMOUNT
            ) {
                res.status(400).json({
                    success: false,
                    message:
                        `Minimum withdrawal is GHS ${MIN_WITHDRAWAL_AMOUNT.toFixed(2)}.`,
                });

                return;
            }

            /*
            |--------------------------------------------------------------------------
            | PAYMENT ACCOUNT
            |--------------------------------------------------------------------------
            */

            const paymentAccountResult =
                await client.query(
                    `
                    SELECT *
                    FROM public.driver_payment_accounts
                    WHERE driver_id = $1
                      AND is_active = TRUE
                    LIMIT 1
                    `,
                    [driverId]
                );

            if (
                paymentAccountResult.rows.length === 0
            ) {
                res.status(400).json({
                    success: false,
                    message:
                        'Please add a mobile money payment account before withdrawing.',
                });

                return;
            }

            const paymentAccount =
                paymentAccountResult.rows[0];

            /*
            |--------------------------------------------------------------------------
            | START TRANSACTION
            |--------------------------------------------------------------------------
            */

            await client.query(
                'BEGIN'
            );

            /*
            |--------------------------------------------------------------------------
            | LOCK WALLET
            |--------------------------------------------------------------------------
            */

            const walletResult =
                await client.query(
                    `
                    SELECT *
                    FROM public.driver_wallets
                    WHERE driver_id = $1
                    FOR UPDATE
                    `,
                    [driverId]
                );

            if (
                walletResult.rows.length === 0
            ) {

                await client.query(
                    'ROLLBACK'
                );

                res.status(404).json({
                    success: false,
                    message:
                        'Driver wallet not found.',
                });

                return;
            }

            const wallet =
                walletResult.rows[0];

            const balance =
                toNumber(
                    wallet.balance
                );

            /*
            |--------------------------------------------------------------------------
            | CHECK MINIMUM WALLET BALANCE
            |--------------------------------------------------------------------------
            */

            const availableToWithdraw =
                Number(
                    (
                        balance -
                        MINIMUM_WALLET_BALANCE
                    ).toFixed(2)
                );

            if (
                availableToWithdraw <= 0
            ) {

                await client.query(
                    'ROLLBACK'
                );

                res.status(400).json({
                    success: false,

                    message:
                        `You must maintain at least GHS ${MINIMUM_WALLET_BALANCE.toFixed(2)} in your wallet.`,

                    balance,
                });

                return;
            }

            if (
                normalizedAmount >
                availableToWithdraw
            ) {

                await client.query(
                    'ROLLBACK'
                );

                res.status(400).json({
                    success: false,

                    message:
                        'Insufficient withdrawable wallet balance.',

                    balance,

                    maximumWithdrawable:
                        availableToWithdraw,
                });

                return;
            }

            /*
            |--------------------------------------------------------------------------
            | CREATE REFERENCE
            |--------------------------------------------------------------------------
            */

            const withdrawalReference =
                generateWithdrawalReference(
                    driverId
                );

            /*
            |--------------------------------------------------------------------------
            | WITHDRAWAL FEE
            |--------------------------------------------------------------------------
            |
            | Currently zero.
            |
            |--------------------------------------------------------------------------
            */

            const withdrawalFee =
                0.00;

            const netAmount =
                Number(
                    (
                        normalizedAmount -
                        withdrawalFee
                    ).toFixed(2)
                );

            /*
            |--------------------------------------------------------------------------
            | CALCULATE BALANCE
            |--------------------------------------------------------------------------
            */

            const balanceAfter =
                Number(
                    (
                        balance -
                        normalizedAmount
                    ).toFixed(2)
                );

            /*
            |--------------------------------------------------------------------------
            | RESERVE FUNDS
            |--------------------------------------------------------------------------
            */

            await client.query(
                `
                UPDATE public.driver_wallets
                SET
                    balance = $2,
                    pending_balance =
                        pending_balance + $3,
                    last_transaction_at = NOW(),
                    updated_at = NOW()
                WHERE id = $1
                `,
                [
                    wallet.id,

                    balanceAfter,

                    normalizedAmount,
                ]
            );

            /*
            |--------------------------------------------------------------------------
            | CREATE WITHDRAWAL
            |--------------------------------------------------------------------------
            |
            | Uses your NEW table:
            |
            | driver_wallet_withdrawals
            |
            |--------------------------------------------------------------------------
            */

            const withdrawalResult =
                await client.query(
                    `
                    INSERT INTO public.driver_wallet_withdrawals (
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
                        reference,
                        failure_reason,
                        processed_at,
                        created_at,
                        updated_at
                    )
                    VALUES (
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
                        $10,
                        NULL,
                        NULL,
                        NOW(),
                        NOW()
                    )
                    RETURNING *
                    `,
                    [
                        driverId,

                        wallet.id,

                        paymentAccount.id,

                        normalizedAmount,

                        withdrawalFee,

                        netAmount,

                        paymentAccount
                            .mobile_network,

                        paymentAccount
                            .mobile_money_number,

                        paymentAccount
                            .account_name,

                        withdrawalReference,
                    ]
                );

            /*
            |--------------------------------------------------------------------------
            | RECORD WALLET TRANSACTION
            |--------------------------------------------------------------------------
            */

            await client.query(
                `
                INSERT INTO public.driver_wallet_transactions (
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
                )
                VALUES (
                    $1,
                    $2,
                    'withdrawal',
                    $3,
                    $4,
                    $5,
                    $6,
                    $7,
                    'pending',
                    $8::jsonb,
                    NOW()
                )
                `,
                [
                    wallet.id,

                    driverId,

                    normalizedAmount,

                    balance,

                    balanceAfter,

                    withdrawalReference,

                    'Driver wallet withdrawal',

                    JSON.stringify({
                        withdrawalId:
                            withdrawalResult
                                .rows[0]
                                .id,

                        paymentAccountId:
                            paymentAccount.id,

                        mobileNetwork:
                            paymentAccount
                                .mobile_network,

                        mobileMoneyNumber:
                            paymentAccount
                                .mobile_money_number,

                        accountName:
                            paymentAccount
                                .account_name,

                        fee:
                            withdrawalFee,

                        netAmount:
                            netAmount,

                        status:
                            'pending',
                    }),
                ]
            );

            /*
            |--------------------------------------------------------------------------
            | COMMIT
            |--------------------------------------------------------------------------
            */

            await client.query(
                'COMMIT'
            );

            res.status(201).json({
                success: true,

                message:
                    'Withdrawal request submitted successfully.',

                withdrawal:
                    withdrawalResult.rows[0],

                walletBalance:
                    balanceAfter,
            });

        } catch (error) {

            try {
                await client.query(
                    'ROLLBACK'
                );
            } catch (_) {
                // Ignore rollback failure.
            }

            console.error(
                'POST /wallet/withdraw error:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Failed to create withdrawal request.',
            });

        } finally {

            client.release();
        }
    }
);

/*
|--------------------------------------------------------------------------
| GET WITHDRAWALS
|--------------------------------------------------------------------------
*/

router.get(
    '/wallet/withdrawals',
    authenticateDriver,
    async (
        req: AuthenticatedDriverRequest,
        res: Response
    ) => {

        try {

            const driverId =
                req.driverId!;

            const limit =
                Math.min(
                    Math.max(
                        Number(
                            req.query.limit
                        ) || 50,
                        1
                    ),
                    100
                );

            const offset =
                Math.max(
                    Number(
                        req.query.offset
                    ) || 0,
                    0
                );

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
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
                        reference,
                        failure_reason,
                        processed_at,
                        created_at,
                        updated_at
                    FROM public.driver_wallet_withdrawals
                    WHERE driver_id = $1
                    ORDER BY created_at DESC
                    LIMIT $2
                    OFFSET $3
                    `,
                    [
                        driverId,
                        limit,
                        offset,
                    ]
                );

            res.json({
                success: true,

                withdrawals:
                    result.rows.map(
                        (withdrawal) => ({
                            id:
                                withdrawal.id,

                            driverId:
                                withdrawal.driver_id,

                            walletId:
                                withdrawal.wallet_id,

                            paymentAccountId:
                                withdrawal.payment_account_id,

                            amount:
                                toNumber(
                                    withdrawal.amount
                                ),

                            fee:
                                toNumber(
                                    withdrawal.fee
                                ),

                            netAmount:
                                toNumber(
                                    withdrawal.net_amount
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
                        })
                    ),
            });

        } catch (error) {

            console.error(
                'GET /wallet/withdrawals error:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Failed to load withdrawals.',
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| EXPORT
|--------------------------------------------------------------------------
*/

export default router;
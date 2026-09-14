import {
    Router,
    Request,
    Response,
} from 'express';

import crypto from 'crypto';

import pool from '../config/database';

const router = Router();

const PAYSTACK_SECRET_KEY =
    process.env.PAYSTACK_SECRET_KEY || '';

/*
|--------------------------------------------------------------------------
| RAW BODY TYPE
|--------------------------------------------------------------------------
*/

interface RawBodyRequest extends Request {
    rawBody?: Buffer;
}

/*
|--------------------------------------------------------------------------
| VERIFY PAYSTACK SIGNATURE
|--------------------------------------------------------------------------
*/

function verifyPaystackSignature(
    req: RawBodyRequest
): boolean {

    if (!PAYSTACK_SECRET_KEY) {
        return false;
    }

    const signature =
        req.headers[
        'x-paystack-signature'
        ];

    if (
        typeof signature !== 'string'
    ) {
        return false;
    }

    if (!req.rawBody) {
        return false;
    }

    const hash =
        crypto
            .createHmac(
                'sha512',
                PAYSTACK_SECRET_KEY
            )
            .update(req.rawBody)
            .digest('hex');

    try {

        return crypto.timingSafeEqual(
            Buffer.from(hash, 'utf8'),
            Buffer.from(signature, 'utf8')
        );

    } catch (_) {

        return false;
    }
}

/*
|--------------------------------------------------------------------------
| PAYSTACK WEBHOOK
|--------------------------------------------------------------------------
*/

router.post(
    '/paystack/webhook',
    async (
        req: RawBodyRequest,
        res: Response
    ) => {

        try {

            /*
             * Validate Paystack origin.
             */
            if (
                !verifyPaystackSignature(
                    req
                )
            ) {

                console.warn(
                    'Invalid Paystack webhook signature.'
                );

                res.status(401).json({
                    success: false,
                    message:
                        'Invalid webhook signature.',
                });

                return;
            }

            /*
             * Acknowledge webhook quickly.
             */
            res.status(200).send('OK');

            const event =
                req.body;

            console.log(
                'Paystack webhook:',
                event?.event
            );

            /*
             * We only need successful
             * wallet top-ups here.
             */
            if (
                event?.event !==
                'charge.success'
            ) {
                return;
            }

            const payment =
                event.data;

            if (!payment) {
                return;
            }

            const reference =
                String(
                    payment.reference || ''
                ).trim();

            if (!reference) {
                return;
            }

            /*
             * Find Tegaara top-up.
             */
            const topupResult =
                await pool.query(
                    `
                    SELECT *
                    FROM public.wallet_topups
                    WHERE reference = $1
                    LIMIT 1
                    `,
                    [reference]
                );

            if (
                topupResult.rows.length === 0
            ) {

                console.warn(
                    'Paystack webhook reference not found:',
                    reference
                );

                return;
            }

            const topup =
                topupResult.rows[0];

            /*
             * Already processed.
             */
            if (
                topup.status ===
                'successful'
            ) {

                console.log(
                    'Top-up already processed:',
                    reference
                );

                return;
            }

            /*
             * Verify amount.
             */
            const expectedAmount =
                Math.round(
                    Number(
                        topup.amount
                    ) * 100
                );

            const paidAmount =
                Number(
                    payment.amount
                );

            if (
                expectedAmount !==
                paidAmount
            ) {

                console.error(
                    'Paystack webhook amount mismatch:',
                    {
                        reference,
                        expectedAmount,
                        paidAmount,
                    }
                );

                await pool.query(
                    `
                    UPDATE public.wallet_topups
                    SET
                        status = 'amount_mismatch',
                        paystack_status = 'amount_mismatch',
                        updated_at = NOW()
                    WHERE reference = $1
                    `,
                    [reference]
                );

                return;
            }

            /*
             * Verify currency.
             */
            if (
                payment.currency !==
                'GHS'
            ) {

                console.error(
                    'Paystack webhook currency mismatch:',
                    reference
                );

                return;
            }

            const client =
                await pool.connect();

            try {

                await client.query(
                    'BEGIN'
                );

                /*
                 * Lock top-up.
                 */
                const lockedTopup =
                    await client.query(
                        `
                        SELECT *
                        FROM public.wallet_topups
                        WHERE reference = $1
                        FOR UPDATE
                        `,
                        [reference]
                    );

                if (
                    lockedTopup.rows.length === 0
                ) {

                    await client.query(
                        'ROLLBACK'
                    );

                    return;
                }

                const currentTopup =
                    lockedTopup.rows[0];

                /*
                 * Double-processing protection.
                 */
                if (
                    currentTopup.status ===
                    'successful'
                ) {

                    await client.query(
                        'COMMIT'
                    );

                    return;
                }

                /*
                 * Lock wallet.
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
                            currentTopup.driver_id,
                        ]
                    );

                if (
                    walletResult.rows.length === 0
                ) {

                    await client.query(
                        'ROLLBACK'
                    );

                    console.error(
                        'Wallet not found for top-up:',
                        reference
                    );

                    return;
                }

                const wallet =
                    walletResult.rows[0];

                const balanceBefore =
                    Number(
                        wallet.balance
                    );

                const amount =
                    Number(
                        currentTopup.amount
                    );

                const balanceAfter =
                    Number(
                        (
                            balanceBefore +
                            amount
                        ).toFixed(2)
                    );

                /*
                 * Credit wallet.
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
                 * Record transaction.
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

                        currentTopup.driver_id,

                        amount,

                        balanceBefore,

                        balanceAfter,

                        reference,

                        'Wallet top-up via Paystack webhook',

                        JSON.stringify({
                            provider:
                                'paystack',

                            paystackTransactionId:
                                String(
                                    payment.id
                                ),

                            channel:
                                payment.channel,

                            status:
                                payment.status,

                            paidAt:
                                payment.paid_at ||
                                null,
                        }),
                    ]
                );

                /*
                 * Mark top-up successful.
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

                console.log(
                    `Wallet top-up completed: ${reference}, GHS ${amount}`
                );

            } catch (error) {

                await client.query(
                    'ROLLBACK'
                );

                console.error(
                    'Paystack webhook database error:',
                    error
                );

            } finally {

                client.release();
            }

        } catch (error) {

            /*
             * At this point the HTTP response may
             * already have been acknowledged.
             */
            console.error(
                'Paystack webhook error:',
                error
            );
        }
    }
);

export default router;
// src/routes/paystackWebhookRoutes.ts
import { Router, Request, Response } from 'express';

import pool from '../config/database';
import { verifyWebhookSignature } from '../services/paystackService';
import { applySuccessfulPayment } from './passengerWalletRoutes';

const router = Router();

/* ==========================================================================
 * POST /webhooks/paystack
 * ==========================================================================
 * Registered with express.json({ verify }) so we can access the raw body
 * required for HMAC signature verification.
 *
 * Always responds 200 quickly. Paystack retries on non-2xx.
 * ========================================================================== */

router.post(
    '/webhooks/paystack',
    async (req: Request, res: Response) => {
        const signature = req.headers['x-paystack-signature'] as
            | string
            | undefined;

        const rawBody: Buffer | undefined = (req as any).rawBody;

        if (!rawBody) {
            console.error(
                '❌ Paystack webhook: missing raw body. ' +
                'Ensure express.json({ verify }) is configured.'
            );
            return res.status(400).json({ received: false });
        }

        if (!verifyWebhookSignature(rawBody, signature)) {
            console.warn('⚠️ Paystack webhook: invalid signature.');
            return res.status(401).json({ received: false });
        }

        let event: any;
        try {
            event = JSON.parse(rawBody.toString('utf8'));
        } catch (err) {
            console.error('❌ Paystack webhook: invalid JSON.', err);
            return res.status(400).json({ received: false });
        }

        const eventType = String(event?.event ?? '');
        const data = event?.data ?? {};
        const reference = String(data?.reference ?? '');

        console.log(
            `📩 Paystack webhook: event=${eventType} ref=${reference} status=${data?.status}`
        );

        // Ack immediately; process async.
        res.status(200).json({ received: true });

        if (!reference) return;

        try {
            if (eventType === 'charge.success') {
                await applySuccessfulPayment(reference, data);
            } else if (
                eventType === 'charge.failed' ||
                eventType === 'transfer.failed'
            ) {
                await pool.query(
                    `
                    UPDATE public.paystack_transactions
                    SET status = 'failed',
                        paystack_verify = $1::jsonb,
                        updated_at = NOW()
                    WHERE reference = $2
                      AND applied = FALSE
                    `,
                    [JSON.stringify(data), reference]
                );
            }
        } catch (error) {
            console.error(
                '❌ Paystack webhook processing failed:',
                error
            );
        }
    }
);

export default router;
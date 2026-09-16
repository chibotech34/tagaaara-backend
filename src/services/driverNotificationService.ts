import pool from '../config/database';
import { firebaseMessaging } from '../config/firebase'; // your admin.messaging()

export type DriverNotificationCategory =
    | 'ride' | 'wallet' | 'account' | 'security' | 'system' | 'promotion';

export type DriverNotificationPriority =
    | 'low' | 'normal' | 'high' | 'urgent';

export interface CreateDriverNotificationInput {
    driverId: number;
    type: string;
    category: DriverNotificationCategory;
    title: string;
    message: string;
    priority?: DriverNotificationPriority;
    rideId?: number | null;
    transactionId?: number | null;
    withdrawalId?: number | null;
    targetScreen?: string | null;
    metadata?: Record<string, unknown>;
    sendPush?: boolean;
}

/**
 * Insert a driver notification into Postgres and (optionally) push it
 * to all of the driver's FCM tokens.
 *
 * Safe to call from anywhere — never throws upward by default.
 */
export async function createDriverNotification(
    input: CreateDriverNotificationInput,
): Promise<number | null> {
    const {
        driverId,
        type,
        category,
        title,
        message,
        priority = 'normal',
        rideId = null,
        transactionId = null,
        withdrawalId = null,
        targetScreen = null,
        metadata = {},
        sendPush = true,
    } = input;

    try {
        const result = await pool.query(
            `
            INSERT INTO public.driver_notifications (
                driver_id, type, category, title, message, priority,
                ride_id, transaction_id, withdrawal_id,
                target_screen, metadata
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            RETURNING id
            `,
            [
                driverId,
                type,
                category,
                title,
                message,
                priority,
                rideId,
                transactionId,
                withdrawalId,
                targetScreen,
                metadata,
            ],
        );

        const notificationId = result.rows[0]?.id ?? null;

        if (sendPush && notificationId) {
            // fire-and-forget (do not block response)
            void pushDriverNotification(driverId, {
                notificationId,
                type,
                category,
                title,
                message,
                priority,
                rideId,
                transactionId,
                withdrawalId,
                targetScreen,
            });
        }

        return notificationId;
    } catch (error) {
        console.error('❌ createDriverNotification failed:', error);
        return null;
    }
}

async function pushDriverNotification(
    driverId: number,
    payload: {
        notificationId: number;
        type: string;
        category: string;
        title: string;
        message: string;
        priority: string;
        rideId?: number | null;
        transactionId?: number | null;
        withdrawalId?: number | null;
        targetScreen?: string | null;
    },
) {
    try {
        const driverRes = await pool.query(
            `SELECT uid FROM public.drivers WHERE id = $1 LIMIT 1`,
            [driverId],
        );

        if (driverRes.rows.length === 0) return;

        const uid = driverRes.rows[0].uid as string;

        const tokensRes = await pool.query(
            `SELECT token FROM public.fcm_tokens WHERE user_id = $1`,
            [uid],
        );

        const tokens = tokensRes.rows.map((r) => r.token as string).filter(Boolean);
        if (tokens.length === 0) return;

        const response = await firebaseMessaging.sendEachForMulticast({
            tokens,
            notification: {
                title: payload.title,
                body: payload.message,
            },
            data: {
                kind: 'driver_notification',
                notificationId: String(payload.notificationId),
                type: payload.type,
                category: payload.category,
                priority: payload.priority,
                rideId: payload.rideId != null ? String(payload.rideId) : '',
                transactionId: payload.transactionId != null ? String(payload.transactionId) : '',
                withdrawalId: payload.withdrawalId != null ? String(payload.withdrawalId) : '',
                targetScreen: payload.targetScreen ?? '',
            },
            android: {
                priority: payload.priority === 'urgent' || payload.priority === 'high'
                    ? 'high'
                    : 'normal',
                notification: { channelId: 'tegaara_driver_notifications' },
            },
            apns: { payload: { aps: { sound: 'default' } } },
        });

        // Prune invalid tokens
        const invalidTokens: string[] = [];
        response.responses.forEach((r, i) => {
            if (!r.success) {
                const code = r.error?.code ?? '';
                if (
                    code === 'messaging/registration-token-not-registered' ||
                    code === 'messaging/invalid-registration-token'
                ) {
                    invalidTokens.push(tokens[i]);
                }
            }
        });

        if (invalidTokens.length > 0) {
            await pool.query(
                `DELETE FROM public.fcm_tokens WHERE token = ANY($1::text[])`,
                [invalidTokens],
            );
        }
    } catch (error) {
        console.error('❌ pushDriverNotification failed:', error);
    }
}
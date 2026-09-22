// utils/paymentNotifications.ts

import pool from '../config/database';
import { firebaseMessaging } from '../config/firebase';

/*
|--------------------------------------------------------------------------
| FCM: Notify driver that payment was received
|--------------------------------------------------------------------------
|
| Fire-and-forget. Never throws. Payment must succeed even if FCM fails.
|
| Behaviour:
|   • Looks up the driver's most recent FCM token by Firebase UID.
|   • Sends a high-priority notification on the `tegaara_ride_channel`
|     channel that the Flutter app listens to.
|   • Includes `notificationType: 'payment_received'` so the app can
|     route the driver to their wallet screen on tap.
|   • Cleans up stale / unregistered tokens silently.
|
*/

export async function notifyDriverPaymentReceived(
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

        // Flutter's NotificationService reads these for the local
        // heads-up notification while the app is in the foreground.
        title,
        body,
    };

    try {
        await firebaseMessaging.send({
            token: driverToken,

            notification: {
                title,
                body,
            },

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
            `balance=${newDriverBalance != null ? newDriverBalance.toFixed(2) : 'n/a'})`
        );
    } catch (error: any) {
        // Clean up dead tokens silently.
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
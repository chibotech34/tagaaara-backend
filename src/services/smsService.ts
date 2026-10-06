import { sailupConfig, assertSailupConfigured } from '../config/sailup';

export interface SendSmsResult {
    success: boolean;
    provider: 'sailup';
    messageId?: string;
    raw?: unknown;
    error?: string;
}

/**
 * Normalise Ghana phone numbers to E.164 digits (no "+").
 *  "0244123456"    -> "233244123456"
 *  "+233244123456" -> "233244123456"
 *  "233244123456"  -> "233244123456"
 *  "244123456"     -> "233244123456"
 */
export const normalizeGhanaPhone = (
    phone: string | null | undefined,
): string | null => {
    if (!phone) return null;
    const digits = String(phone).replace(/\D/g, '');
    if (digits.length === 12 && digits.startsWith('233')) return digits;
    if (digits.length === 10 && digits.startsWith('0')) return `233${digits.slice(1)}`;
    if (digits.length === 9) return `233${digits}`;
    return null;
};

interface SailupResponse {
    status?: string;
    message?: string;
    data?: { message_id?: string; id?: string } | unknown;
    message_id?: string;
    id?: string;
    [key: string]: unknown;
}

export const sendSms = async (
    toPhone: string,
    message: string,
    senderId?: string,
): Promise<SendSmsResult> => {
    const normalized = normalizeGhanaPhone(toPhone);

    if (!normalized) {
        return {
            success: false,
            provider: 'sailup',
            error: `Invalid phone number: ${toPhone}`,
        };
    }

    try {
        assertSailupConfigured();
    } catch (err) {
        const e = err as { message?: string };
        return {
            success: false,
            provider: 'sailup',
            error: e.message ?? 'SailUp not configured',
        };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), sailupConfig.timeoutMs);

    try {
        const body = {
            sender: senderId ?? sailupConfig.senderId,
            recipient: normalized,
            recipients: [normalized],
            message,
        };

        const response = await fetch(sailupConfig.apiUrl, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${sailupConfig.apiKey}`,
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            body: JSON.stringify(body),
            signal: controller.signal,
        });

        const text = await response.text();
        let json: SailupResponse | null = null;

        try {
            json = text ? (JSON.parse(text) as SailupResponse) : null;
        } catch {
            json = { raw: text };
        }

        if (!response.ok) {
            console.error('❌ SailUp SMS failed:', {
                status: response.status,
                body: json ?? text,
            });
            return {
                success: false,
                provider: 'sailup',
                raw: json,
                error:
                    (json?.message as string | undefined) ??
                    `SailUp responded with HTTP ${response.status}`,
            };
        }

        const messageId =
            json?.message_id ??
            json?.id ??
            (json?.data as { message_id?: string; id?: string } | undefined)?.message_id ??
            (json?.data as { message_id?: string; id?: string } | undefined)?.id;

        console.log(`📨 SailUp SMS sent to ${normalized} (id=${messageId ?? 'n/a'})`);

        return {
            success: true,
            provider: 'sailup',
            messageId,
            raw: json,
        };
    } catch (err: unknown) {
        const e = err as { name?: string; message?: string };

        if (e.name === 'AbortError') {
            return {
                success: false,
                provider: 'sailup',
                error: 'SailUp request timed out',
            };
        }

        return {
            success: false,
            provider: 'sailup',
            error: e.message ?? 'Unknown SailUp error',
        };
    } finally {
        clearTimeout(timeout);
    }
};

export const sendOtpSms = async (
    phone: string,
    code: string,
    ttlMinutes: number,
): Promise<SendSmsResult> => {
    const message =
        `Your Tegaara verification code is ${code}. ` +
        `It expires in ${ttlMinutes} minute${ttlMinutes === 1 ? '' : 's'}. ` +
        `Do not share this code with anyone.`;
    return sendSms(phone, message);
};
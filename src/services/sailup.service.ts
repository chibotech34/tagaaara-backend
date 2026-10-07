/* -------------------------------------------------------------------------- */
/* Sailup SMS client                                                          */
/* -------------------------------------------------------------------------- */

export interface SailupResponse {
    id: string;
    to: string[];
    sender: string;
    body: string;
    quantity: number;
    status: string;
    delivery_status: string;
    created_at: string;
}

export async function sendSailupSms(
    phone: string,
    message: string,
): Promise<SailupResponse> {
    const apiKey = process.env.SAILUP_API_KEY;
    const senderId = process.env.SAILUP_SENDER_ID;

    if (!apiKey) {
        throw new Error('SAILUP_API_KEY is not configured');
    }

    if (!senderId) {
        throw new Error('SAILUP_SENDER_ID is not configured');
    }

    const response = await fetch('https://api.sailup.io/v1/sms/', {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            from: senderId,
            to: [phone],
            body: message,
        }),
    });

    const data = await response.json();

    if (!response.ok) {
        console.error('Sailup error:', data);
        throw new Error(
            `Sailup SMS failed with status ${response.status}`,
        );
    }

    return data as SailupResponse;
}

export function normalizeGhanaPhone(phone: string): string | null {
    if (!phone || typeof phone !== 'string') return null;

    const digits = phone.replace(/\D/g, '');

    let local: string;

    if (digits.startsWith('233') && digits.length === 12) {
        local = digits.slice(3);
    } else if (digits.startsWith('0') && digits.length === 10) {
        local = digits.slice(1);
    } else if (digits.length === 9) {
        local = digits;
    } else {
        return null;
    }

    // Ghana mobile numbers (after stripping leading 0 / 233) start with 2 or 5
    // and are 9 digits long.
    if (!/^[25]\d{8}$/.test(local)) return null;

    return `+233${local}`;
}


export interface SendOtpSmsResult {
    success: boolean;
    error?: string;
    providerId?: string;
}

export async function sendOtpSms(
    phone: string,
    code: string,
    ttlMinutes: number,
): Promise<SendOtpSmsResult> {
    const message =
        `Your SailUp verification code is: ${code}. ` +
        `It expires in ${ttlMinutes} minute${ttlMinutes === 1 ? '' : 's'}. ` +
        `Do not share this code with anyone.`;

    try {
        const result = await sendSailupSms(phone, message);
        return { success: true, providerId: result.id };
    } catch (error) {
        const e = error as { message?: string };
        return {
            success: false,
            error: e.message ?? 'Failed to send SMS via Sailup.',
        };
    }
}
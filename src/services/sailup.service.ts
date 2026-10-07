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

const getSailupConfig = () => {
    const apiKey = process.env.SAILUP_API_KEY?.trim();
    const senderId = process.env.SAILUP_SENDER_ID?.trim();
    const apiUrl =
        process.env.SAILUP_API_URL?.trim() ||
        'https://api.sailup.io/v1/sms/';

    if (!apiKey) {
        throw new Error('SAILUP_API_KEY is not configured');
    }

    if (!senderId) {
        throw new Error('SAILUP_SENDER_ID is not configured');
    }

    return {
        apiKey,
        senderId,
        apiUrl,
    };
};

export async function sendSailupSms(
    phone: string,
    message: string,
): Promise<SailupResponse> {
    const {
        apiKey,
        senderId,
        apiUrl,
    } = getSailupConfig();

    console.log('📨 Sending SMS via Sailup:', {
        url: apiUrl,
        sender: senderId,
        phone,
        apiKeyConfigured: Boolean(apiKey),
        apiKeyPrefix: apiKey.substring(0, 8),
    });

    const response = await fetch(apiUrl, {
        method: 'POST',

        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },

        body: JSON.stringify({
            from: senderId,
            to: [phone],
            body: message,
        }),
    });

    const rawResponse = await response.text();

    let data: unknown;

    try {
        data = JSON.parse(rawResponse);
    } catch {
        data = rawResponse;
    }

    if (!response.ok) {
        console.error('❌ Sailup HTTP error:', {
            status: response.status,
            statusText: response.statusText,
            response: data,
        });

        throw new Error(
            `Sailup SMS failed with status ${response.status}: ${typeof data === 'string'
                ? data
                : JSON.stringify(data)
            }`,
        );
    }

    console.log('✅ Sailup SMS accepted:', data);

    return data as SailupResponse;
};


/* -------------------------------------------------------------------------- */
/* Ghana phone normalization                                                  */
/* -------------------------------------------------------------------------- */

export function normalizeGhanaPhone(
    phone: string,
): string | null {
    if (!phone || typeof phone !== 'string') {
        return null;
    }

    const digits = phone.replace(/\D/g, '');

    let local: string;

    // +233XXXXXXXXX / 233XXXXXXXXX
    if (
        digits.startsWith('233') &&
        digits.length === 12
    ) {
        local = digits.slice(3);

        // 0XXXXXXXXX
    } else if (
        digits.startsWith('0') &&
        digits.length === 10
    ) {
        local = digits.slice(1);

        // XXXXXXXXX
    } else if (digits.length === 9) {
        local = digits;

    } else {
        return null;
    }

    // Ghana mobile numbers:
    // 2XXXXXXXX / 5XXXXXXXX
    if (!/^[25]\d{8}$/.test(local)) {
        return null;
    }

    return `+233${local}`;
}


/* -------------------------------------------------------------------------- */
/* OTP SMS helper                                                             */
/* -------------------------------------------------------------------------- */

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
        `Your Tegaara verification code is: ${code}. ` +
        `It expires in ${ttlMinutes} minute${ttlMinutes === 1 ? '' : 's'
        }. ` +
        `Do not share this code with anyone.`;

    try {
        const normalizedPhone =
            normalizeGhanaPhone(phone);

        if (!normalizedPhone) {
            return {
                success: false,
                error: 'Invalid Ghana phone number.',
            };
        }

        const result = await sendSailupSms(
            normalizedPhone,
            message,
        );

        return {
            success: true,
            providerId: result.id,
        };

    } catch (error: unknown) {
        const e = error as {
            message?: string;
        };

        console.error(
            '❌ sendOtpSms error:',
            e.message ?? error,
        );

        return {
            success: false,
            error:
                e.message ??
                'Failed to send SMS via Sailup.',
        };
    }
}
import crypto from "crypto";

const ZAVU_API_URL = "https://api.zavu.dev/v1/messages";

interface SendOtpResult {
    success: boolean;
    messageId?: string;
    status?: string;
}

export function normalizeGhanaPhone(phone: string): string {
    let value = phone.trim().replace(/\s+/g, "");

    if (value.startsWith("+233")) {
        value = value;
    } else if (value.startsWith("233")) {
        value = `+${value}`;
    } else if (value.startsWith("0")) {
        value = `+233${value.substring(1)}`;
    } else {
        throw new Error("Invalid Ghana phone number");
    }

    if (!/^\+233\d{9}$/.test(value)) {
        throw new Error("Invalid Ghana phone number");
    }

    return value;
}

export function generateOtp(length = 6): string {
    const min = Math.pow(10, length - 1);
    const max = Math.pow(10, length) - 1;

    return crypto.randomInt(min, max + 1).toString();
}

export function hashOtp(otp: string): string {
    return crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");
}

export async function sendZavuOtp(
    phone: string,
    otp: string,
): Promise<SendOtpResult> {
    const apiKey = process.env.ZAVU_API_KEY;

    if (!apiKey) {
        throw new Error("ZAVU_API_KEY is not configured");
    }

    const normalizedPhone = normalizeGhanaPhone(phone);

    const senderId = process.env.ZAVU_SENDER_ID;

    const headers: Record<string, string> = {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
    };

    if (senderId) {
        headers["Zavu-Sender"] = senderId;
    }

    const response = await fetch(ZAVU_API_URL, {
        method: "POST",
        headers,
        body: JSON.stringify({
            to: normalizedPhone,
            channel: "sms",
            messageType: "text",
            text: `Your Tegaara verification code is ${otp}. It expires in 5 minutes. Do not share this code with anyone.`,
        }),
    });

    const body = await response.json().catch(() => ({}));

    console.log("Zavu response:", response.status, body);

    if (!response.ok) {
        const errorMessage =
            body?.error?.message ||
            body?.message ||
            `Zavu SMS failed with status ${response.status}`;

        throw new Error(errorMessage);
    }

    return {
        success: true,
        messageId: body?.message?.id,
        status: body?.message?.status,
    };
}
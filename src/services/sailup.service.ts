interface SailupResponse {
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
    message: string
): Promise<SailupResponse> {

    const apiKey = process.env.SAILUP_API_KEY;
    const senderId = process.env.SAILUP_SENDER_ID;

    if (!apiKey) {
        throw new Error("SAILUP_API_KEY is not configured");
    }

    if (!senderId) {
        throw new Error("SAILUP_SENDER_ID is not configured");
    }

    const response = await fetch(
        "https://api.sailup.io/v1/sms/",
        {
            method: "POST",

            headers: {
                "Authorization": `Bearer ${apiKey}`,
                "Content-Type": "application/json",
            },

            body: JSON.stringify({
                from: senderId,
                to: [phone],
                body: message,
            }),
        }
    );

    const data = await response.json();

    if (!response.ok) {
        console.error("Sailup error:", data);

        throw new Error(
            `Sailup SMS failed with status ${response.status}`
        );
    }

    return data as SailupResponse;
}
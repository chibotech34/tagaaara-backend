export async function sendSms(
    phone: string,
    message: string
): Promise<void> {

    const hubtelUrl =
        process.env.HUBTEL_SMS_URL ||
        "https://smsc.hubtel.com/v1/messages/send";

    const clientId = process.env.HUBTEL_SMS_CLIENT_ID;
    const clientSecret = process.env.HUBTEL_SMS_CLIENT_SECRET;
    const senderId = process.env.HUBTEL_SMS_FROM;

    if (!clientId) {
        throw new Error("HUBTEL_SMS_CLIENT_ID is not configured");
    }

    if (!clientSecret) {
        throw new Error("HUBTEL_SMS_CLIENT_SECRET is not configured");
    }

    if (!senderId) {
        throw new Error("HUBTEL_SMS_FROM is not configured");
    }

    const params = new URLSearchParams({
        clientid: clientId,
        clientsecret: clientSecret,
        from: senderId,
        to: phone,
        content: message,
    });

    const url = `${hubtelUrl}?${params.toString()}`;

    const response = await fetch(url, {
        method: "GET",
        headers: {
            Accept: "application/json",
        },
    });

    const responseText = await response.text();

    if (!response.ok) {
        console.error("Hubtel SMS error:", {
            status: response.status,
            response: responseText,
        });

        throw new Error("Failed to send SMS");
    }

    console.log("Hubtel SMS response:", responseText);
}
// ============================================================
// HUBTEL SMS SERVICE
// ============================================================

// Hard cap on how long we wait for Hubtel before giving up.
// Must be well below the client timeout (90 s in the Flutter
// AuthService), and below typical reverse-proxy idle limits.
const HUBTEL_TIMEOUT_MS = 15_000;

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

    // --------------------------------------------------------
    // ABORT CONTROLLER: hard timeout for the Hubtel call.
    // Without this, a stalled Hubtel connection hangs the
    // entire /send-otp request indefinitely.
    // --------------------------------------------------------
    const controller = new AbortController();
    const timeoutId = setTimeout(
        () => controller.abort(),
        HUBTEL_TIMEOUT_MS,
    );

    const startedAt = Date.now();

    try {
        const response = await fetch(url, {
            method: "GET",
            headers: { Accept: "application/json" },
            signal: controller.signal,
        });

        const responseText = await response.text();
        const elapsed = Date.now() - startedAt;

        if (!response.ok) {
            console.error("Hubtel SMS error:", {
                status: response.status,
                elapsedMs: elapsed,
                response: responseText,
            });
            throw new Error(
                `Hubtel SMS failed with status ${response.status}`,
            );
        }

        console.log("Hubtel SMS sent:", {
            elapsedMs: elapsed,
            response: responseText,
        });
    } catch (err: any) {
        const elapsed = Date.now() - startedAt;

        if (err?.name === "AbortError") {
            console.error("Hubtel SMS request timed out:", {
                elapsedMs: elapsed,
                timeoutMs: HUBTEL_TIMEOUT_MS,
            });
            throw new Error(
                `Hubtel SMS timed out after ${HUBTEL_TIMEOUT_MS} ms`,
            );
        }

        console.error("Hubtel SMS request failed:", {
            elapsedMs: elapsed,
            error: err?.message ?? err,
        });
        throw err;
    } finally {
        clearTimeout(timeoutId);
    }
}
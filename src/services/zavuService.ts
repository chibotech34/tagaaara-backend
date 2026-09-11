import Zavudev from "@zavudev/sdk";

const zavu = new Zavudev({
    apiKey: process.env.ZAVU_API_KEY,
});

export async function sendSms(
    phoneNumber: string,
    message: string
) {
    try {
        const result = await zavu.messages.send({
            to: phoneNumber,
            channel: "sms",
            text: message,
        });

        console.log("Zavu SMS:", result);

        return result;
    } catch (error: any) {
        console.error(
            "Zavu SMS error:",
            error?.response?.data || error?.message || error
        );

        throw new Error("Failed to send SMS");
    }
}
export interface SailupConfig {
    apiUrl: string;
    apiKey: string;
    senderId: string;
    timeoutMs: number;
}

const readEnv = (key: string, fallback = ''): string =>
    (process.env[key] ?? fallback).trim();

export const sailupConfig: SailupConfig = {
    apiUrl: readEnv('SAILUP_API_URL', 'https://api.sailup.io/api/sms/send'),
    apiKey: readEnv('SAILUP_API_KEY'),
    senderId: readEnv('SAILUP_SENDER_ID', 'TEGAARA'),
    timeoutMs: Number(readEnv('SAILUP_TIMEOUT_MS', '15000')) || 15000,
};

export const assertSailupConfigured = (): void => {
    if (!sailupConfig.apiUrl || !sailupConfig.apiKey) {
        throw new Error(
            'SailUp SMS is not configured. Set SAILUP_API_URL and SAILUP_API_KEY on the server.',
        );
    }
};
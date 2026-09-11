/**
 * Normalize Ghana phone numbers to E.164 format.
 *
 * Examples:
 *
 * 0241234567   -> +233241234567
 * 541234567    -> +233541234567
 * +233241234567 -> +233241234567
 * 233241234567 -> +233241234567
 */

export function normalizeGhanaPhone(phone: string): string {
    if (!phone) {
        throw new Error("Phone number is required");
    }

    let value = phone.trim().replace(/[\s\-()]/g, "");

    // Already +233
    if (value.startsWith("+233")) {
        value = value;
    }

    // 233XXXXXXXXX
    else if (value.startsWith("233")) {
        value = `+${value}`;
    }

    // 0XXXXXXXXX
    else if (value.startsWith("0")) {
        value = `+233${value.substring(1)}`;
    }

    // XXXXXXXXX
    else if (value.length === 9) {
        value = `+233${value}`;
    }

    else {
        throw new Error(
            "Invalid Ghana phone number. Use 0241234567 or +233241234567"
        );
    }

    // Ghana mobile numbers should be +233 followed by 9 digits.
    if (!/^\+233\d{9}$/.test(value)) {
        throw new Error(
            "Invalid Ghana phone number. Use 0241234567 or +233241234567"
        );
    }

    return value;
}
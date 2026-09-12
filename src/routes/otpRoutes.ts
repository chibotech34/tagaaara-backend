import express, { Request, Response } from "express";
import crypto from "crypto";

import { sendZavuOtp } from "../services/zavuService";
import pool from "../config/database";

const router = express.Router();

function generateOtp(): string {
    return crypto.randomInt(100000, 1000000).toString();
}

function hashOtp(otp: string): string {
    return crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");
}

function normalizePhone(phone: string): string {
    let value = phone.trim();

    // Ghana local format:
    // 0241234567 -> +233241234567
    if (value.startsWith("0")) {
        value = "+233" + value.substring(1);
    }

    if (!value.startsWith("+")) {
        value = "+" + value;
    }

    return value;
}

router.post(
    "/send-otp",
    async (req: Request, res: Response) => {
        try {
            const { phoneNumber } = req.body;

            if (!phoneNumber) {
                return res.status(400).json({
                    success: false,
                    message: "Phone number is required",
                });
            }

            const phone = normalizePhone(phoneNumber);

            // Generate OTP
            const otp = generateOtp();

            // Hash OTP
            const otpHash = hashOtp(otp);

            // Expire after 5 minutes
            const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

            // Remove previous OTPs
            await pool.query(
                `
                DELETE FROM phone_otps
                WHERE phone_number = $1
                `,
                [phone]
            );

            // Store new OTP
            await pool.query(
                `
                INSERT INTO phone_otps
                (
                  phone_number,
                  otp_hash,
                  expires_at
                )
                VALUES ($1, $2, $3)
                `,
                [phone, otpHash, expiresAt]
            );

            // Send SMS via Zavu
            await sendZavuOtp(phone, otp);

            return res.status(200).json({
                success: true,
                message: "OTP sent successfully",
            });
        } catch (error) {
            console.error("SEND OTP ERROR:", error);

            return res.status(500).json({
                success: false,
                message: "Failed to send OTP",
            });
        }
    }
);

router.post(
    "/verify-otp",
    async (req: Request, res: Response) => {
        try {
            const { phoneNumber, otp } = req.body;

            if (!phoneNumber || !otp) {
                return res.status(400).json({
                    success: false,
                    message: "Phone number and OTP are required",
                });
            }

            const phone = normalizePhone(phoneNumber);

            const result = await pool.query(
                `
                SELECT *
                FROM phone_otps
                WHERE phone_number = $1
                AND verified = FALSE
                ORDER BY created_at DESC
                LIMIT 1
                `,
                [phone]
            );

            if (result.rows.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: "OTP not found or already used",
                });
            }

            const record = result.rows[0];

            // Check expiry
            if (new Date(record.expires_at) < new Date()) {
                await pool.query(
                    `
                    DELETE FROM phone_otps
                    WHERE id = $1
                    `,
                    [record.id]
                );

                return res.status(400).json({
                    success: false,
                    message: "OTP has expired",
                });
            }

            // Check attempts
            if (record.attempts >= 5) {
                return res.status(429).json({
                    success: false,
                    message: "Too many verification attempts",
                });
            }

            const otpHash = hashOtp(otp);

            // Wrong OTP
            if (otpHash !== record.otp_hash) {
                await pool.query(
                    `
                    UPDATE phone_otps
                    SET attempts = attempts + 1
                    WHERE id = $1
                    `,
                    [record.id]
                );

                return res.status(400).json({
                    success: false,
                    message: "Invalid OTP",
                });
            }

            // Correct OTP
            await pool.query(
                `
                UPDATE phone_otps
                SET verified = TRUE
                WHERE id = $1
                `,
                [record.id]
            );

            return res.status(200).json({
                success: true,
                verified: true,
                phoneNumber: phone,
            });
        } catch (error) {
            console.error("VERIFY OTP ERROR:", error);

            return res.status(500).json({
                success: false,
                message: "OTP verification failed",
            });
        }
    }
);

export default router;
import express, { Request, Response } from "express";
import crypto from "crypto";

import { firebaseAuth } from "../config/firebase";
import { sendSms } from "../services/smsService";
import { normalizeGhanaPhone } from "../utils/phoneUtils";
import pool from "../config/database";

const router = express.Router();


// ============================================================
// CONFIGURATION
// ============================================================

const OTP_EXPIRY_MINUTES = 5;

const OTP_MAX_ATTEMPTS = 5;

const RESEND_COOLDOWN_SECONDS = 60;

const MAX_REQUESTS_PER_10_MINUTES = 3;


// ============================================================
// GENERATE OTP
// ============================================================

function generateOtp(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
}


// ============================================================
// HASH OTP
// ============================================================

function hashOtp(otp: string): string {
    return crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");
}


// ============================================================
// SEND OTP
// POST /api/auth/send-otp
// ============================================================

router.post("/send-otp", async (req: Request, res: Response) => {

    try {

        const { phone } = req.body;

        if (!phone) {
            return res.status(400).json({
                success: false,
                message: "Phone number is required",
            });
        }


        // ----------------------------------------------------
        // NORMALIZE PHONE
        // ----------------------------------------------------

        let normalizedPhone: string;

        try {

            normalizedPhone = normalizeGhanaPhone(phone);

        } catch (error: any) {

            return res.status(400).json({
                success: false,
                message: error.message,
            });
        }


        // ----------------------------------------------------
        // CHECK RECENT OTP REQUESTS
        // ----------------------------------------------------

        const requestCountResult = await pool.query(
            `
            SELECT COUNT(*) AS count
            FROM phone_otps
            WHERE phone = $1
              AND created_at > NOW() - INTERVAL '10 minutes'
            `,
            [normalizedPhone]
        );

        const requestCount = Number(
            requestCountResult.rows[0].count
        );


        if (requestCount >= MAX_REQUESTS_PER_10_MINUTES) {

            return res.status(429).json({
                success: false,
                message:
                    "Too many OTP requests. Please try again later.",
            });
        }


        // ----------------------------------------------------
        // CHECK RESEND COOLDOWN
        // ----------------------------------------------------

        const latestResult = await pool.query(
            `
            SELECT created_at
            FROM phone_otps
            WHERE phone = $1
            ORDER BY created_at DESC
            LIMIT 1
            `,
            [normalizedPhone]
        );


        if (latestResult.rows.length > 0) {

            const createdAt = new Date(
                latestResult.rows[0].created_at
            ).getTime();

            const elapsed =
                (Date.now() - createdAt) / 1000;

            if (elapsed < RESEND_COOLDOWN_SECONDS) {

                const remaining = Math.ceil(
                    RESEND_COOLDOWN_SECONDS - elapsed
                );

                return res.status(429).json({
                    success: false,
                    message:
                        `Please wait ${remaining} seconds before requesting another OTP.`,
                    retryAfter: remaining,
                });
            }
        }


        // ----------------------------------------------------
        // GENERATE OTP
        // ----------------------------------------------------

        const otp = generateOtp();

        const otpHash = hashOtp(otp);


        // ----------------------------------------------------
        // EXPIRATION
        // ----------------------------------------------------

        const expiresAt = new Date(
            Date.now() +
            OTP_EXPIRY_MINUTES * 60 * 1000
        );


        // ----------------------------------------------------
        // REMOVE PREVIOUS ACTIVE OTP
        // ----------------------------------------------------

        await pool.query(
            `
            DELETE FROM phone_otps
            WHERE phone = $1
            `,
            [normalizedPhone]
        );


        // ----------------------------------------------------
        // STORE HASHED OTP
        // ----------------------------------------------------

        await pool.query(
            `
            INSERT INTO phone_otps
            (
                phone,
                otp_hash,
                expires_at,
                attempts,
                verified
            )
            VALUES ($1, $2, $3, 0, false)
            `,
            [
                normalizedPhone,
                otpHash,
                expiresAt,
            ]
        );


        // ----------------------------------------------------
        // SMS
        // ----------------------------------------------------

        const message =
            `Your Tegaara verification code is ${otp}. ` +
            `It expires in ${OTP_EXPIRY_MINUTES} minutes. ` +
            `Do not share this code.`;


        try {

            await sendSms(
                normalizedPhone,
                message
            );

        } catch (smsError) {

            // Remove OTP if SMS failed.
            await pool.query(
                `
                DELETE FROM phone_otps
                WHERE phone = $1
                `,
                [normalizedPhone]
            );

            console.error(
                "SMS sending failed:",
                smsError
            );

            return res.status(502).json({
                success: false,
                message:
                    "We could not send the OTP. Please try again.",
            });
        }


        // ----------------------------------------------------
        // RESPONSE
        // ----------------------------------------------------

        return res.status(200).json({
            success: true,
            message: "OTP sent successfully",
            phone: normalizedPhone,
            expiresIn: OTP_EXPIRY_MINUTES * 60,
            resendAfter: RESEND_COOLDOWN_SECONDS,
        });

    } catch (error) {

        console.error(
            "SEND OTP ERROR:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Server error while sending OTP",
        });
    }
});


// ============================================================
// VERIFY OTP
// POST /api/auth/verify-otp
// ============================================================

router.post("/verify-otp", async (req: Request, res: Response) => {

    try {

        const {
            phone,
            otp,
        } = req.body;


        if (!phone || !otp) {

            return res.status(400).json({
                success: false,
                message:
                    "Phone number and OTP are required",
            });
        }


        // ----------------------------------------------------
        // NORMALIZE PHONE
        // ----------------------------------------------------

        let normalizedPhone: string;

        try {

            normalizedPhone =
                normalizeGhanaPhone(phone);

        } catch (error: any) {

            return res.status(400).json({
                success: false,
                message: error.message,
            });
        }


        // ----------------------------------------------------
        // VALIDATE OTP FORMAT
        // ----------------------------------------------------

        if (!/^\d{6}$/.test(otp.toString())) {

            return res.status(400).json({
                success: false,
                message:
                    "OTP must be a 6-digit number",
            });
        }


        // ----------------------------------------------------
        // FIND OTP
        // ----------------------------------------------------

        const result = await pool.query(
            `
            SELECT *
            FROM phone_otps
            WHERE phone = $1
            ORDER BY created_at DESC
            LIMIT 1
            `,
            [normalizedPhone]
        );


        if (result.rows.length === 0) {

            return res.status(400).json({
                success: false,
                message:
                    "OTP not found. Please request a new OTP.",
            });
        }


        const record = result.rows[0];


        // ----------------------------------------------------
        // ALREADY VERIFIED
        // ----------------------------------------------------

        if (record.verified) {

            return res.status(400).json({
                success: false,
                message:
                    "This OTP has already been used.",
            });
        }


        // ----------------------------------------------------
        // EXPIRATION
        // ----------------------------------------------------

        if (
            new Date(record.expires_at).getTime()
            < Date.now()
        ) {

            await pool.query(
                `
                DELETE FROM phone_otps
                WHERE id = $1
                `,
                [record.id]
            );

            return res.status(400).json({
                success: false,
                message:
                    "OTP has expired. Please request a new OTP.",
            });
        }


        // ----------------------------------------------------
        // ATTEMPT LIMIT
        // ----------------------------------------------------

        if (
            Number(record.attempts)
            >= OTP_MAX_ATTEMPTS
        ) {

            return res.status(429).json({
                success: false,
                message:
                    "Too many incorrect attempts. Request a new OTP.",
            });
        }


        // ----------------------------------------------------
        // COMPARE HASH
        // ----------------------------------------------------

        const suppliedHash =
            hashOtp(otp.toString());


        if (
            suppliedHash !== record.otp_hash
        ) {

            await pool.query(
                `
                UPDATE phone_otps
                SET attempts = attempts + 1
                WHERE id = $1
                `,
                [record.id]
            );


            const attemptsLeft =
                OTP_MAX_ATTEMPTS -
                (Number(record.attempts) + 1);


            return res.status(400).json({
                success: false,
                message:
                    attemptsLeft > 0
                        ? `Incorrect OTP. ${attemptsLeft} attempt(s) remaining.`
                        : "Too many incorrect attempts. Request a new OTP.",
            });
        }


        // ----------------------------------------------------
        // MARK VERIFIED
        // ----------------------------------------------------

        await pool.query(
            `
            UPDATE phone_otps
            SET verified = true
            WHERE id = $1
            `,
            [record.id]
        );


        // ----------------------------------------------------
        // GET OR CREATE FIREBASE USER
        // ----------------------------------------------------

        let firebaseUser;

        try {

            firebaseUser =
                await firebaseAuth.getUserByPhoneNumber(
                    normalizedPhone
                );

        } catch (error: any) {

            if (
                error.code ===
                "auth/user-not-found"
            ) {

                firebaseUser =
                    await firebaseAuth.createUser({
                        phoneNumber:
                            normalizedPhone,
                    });

            } else {

                throw error;
            }
        }


        // ----------------------------------------------------
        // CREATE FIREBASE CUSTOM TOKEN
        // ----------------------------------------------------

        const customToken =
            await firebaseAuth.createCustomToken(
                firebaseUser.uid
            );


        // ----------------------------------------------------
        // DELETE USED OTP
        // ----------------------------------------------------

        await pool.query(
            `
            DELETE FROM phone_otps
            WHERE id = $1
            `,
            [record.id]
        );


        // ----------------------------------------------------
        // SUCCESS
        // ----------------------------------------------------

        return res.status(200).json({
            success: true,

            message:
                "Phone number verified successfully",

            phone: normalizedPhone,

            firebaseUid:
                firebaseUser.uid,

            customToken,
        });

    } catch (error) {

        console.error(
            "VERIFY OTP ERROR:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Server error while verifying OTP",
        });
    }
});


// ============================================================
// RESEND OTP
// POST /api/auth/resend-otp
// ============================================================

router.post(
    "/resend-otp",
    async (req: Request, res: Response) => {

        try {

            const { phone } = req.body;

            if (!phone) {
                return res.status(400).json({
                    success: false,
                    message: "Phone number is required",
                });
            }

            // Call the same endpoint internally through HTTP
            // instead of using router.handle().
            //
            // BUT: this requires duplicating the OTP logic
            // or moving it into a shared function.

            return res.status(400).json({
                success: false,
                message:
                    "Please use /send-otp to request or resend an OTP.",
            });

        } catch (error) {

            console.error(
                "RESEND OTP ERROR:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Server error while resending OTP",
            });
        }
    }
);



export default router;
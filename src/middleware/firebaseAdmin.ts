
import { Request, Response, NextFunction } from 'express';
import { firebaseAuth } from '../config/firebase';
import pool from '../config/database';

export interface AdminUser {
    id: number;
    firebase_uid: string;
    email: string;
    full_name: string;
    phone_number: string | null;
    username: string | null;
    profile_photo_url: string | null;
    account_status: string;
    role: string;
    created_at: string;
}

export interface AuthenticatedRequest extends Request {
    decodedToken?: {
        uid: string;
        email?: string;
        name?: string;
    };
    adminUser?: AdminUser;
}

export const verifyFirebaseToken = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
        res.status(401).json({
            success: false,
            message: 'Missing or invalid Authorization header.',
            code: 'AUTH_HEADER_MISSING',
        });
        return;
    }

    const token = authHeader.substring(7).trim();

    if (!token) {
        res.status(401).json({
            success: false,
            message: 'Firebase ID token is missing.',
            code: 'AUTH_TOKEN_MISSING',
        });
        return;
    }

    try {
        // 1. Verify Firebase ID token
        const decodedToken = await firebaseAuth.verifyIdToken(token);

        req.decodedToken = {
            uid: decodedToken.uid,
            email: decodedToken.email,
            name: decodedToken.name,
        };

        // 2. Find admin using Firebase UID
        const result = await pool.query(
            `
            SELECT
                id,
                firebase_uid,
                email,
                full_name,
                phone_number,
                username,
                profile_photo_url,
                account_status,
                role,
                created_at
            FROM public.admins
            WHERE firebase_uid = $1
            LIMIT 1
            `,
            [decodedToken.uid]
        );

        if (result.rows.length === 0) {
            res.status(403).json({
                success: false,
                message: 'This Firebase account is not registered as an admin.',
                code: 'ADMIN_NOT_FOUND',
            });
            return;
        }

        const admin = result.rows[0] as AdminUser;

        // 3. Check admin account status
        if (admin.account_status?.toLowerCase() !== 'active') {
            res.status(403).json({
                success: false,
                message: 'Your admin account is not active.',
                code: 'ADMIN_ACCOUNT_INACTIVE',
            });
            return;
        }

        // 4. Attach admin record to request
        req.adminUser = admin;

        next();

    } catch (error: unknown) {
        console.error('❌ Admin authentication error:', error);

        const authError = error as {
            code?: string;
            message?: string;
        };

        if (
            authError.code === 'auth/id-token-expired' ||
            authError.code === 'auth/id-token-revoked'
        ) {
            res.status(401).json({
                success: false,
                message: 'Your Firebase session has expired. Please sign in again.',
                code: 'AUTH_TOKEN_EXPIRED',
            });
            return;
        }

        if (
            authError.code?.startsWith('auth/')
        ) {
            res.status(401).json({
                success: false,
                message: 'Firebase authentication failed.',
                code: 'AUTH_TOKEN_INVALID',
            });
            return;
        }

        res.status(500).json({
            success: false,
            message: 'Failed to authenticate admin.',
            code: 'ADMIN_AUTH_ERROR',
        });
    }
};

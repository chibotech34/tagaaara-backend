import {
    Request,
    Response,
    NextFunction,
} from 'express';

import {
    getAuth,
} from 'firebase-admin/auth';

import pool from '../config/database';

/*
|--------------------------------------------------------------------------
| Admin Authentication Middleware
|--------------------------------------------------------------------------
|
| This middleware is ONLY for protected admin routes.
|
| It expects:
|
| Authorization: Bearer <Firebase ID Token>
|
| It is NOT used by:
|
| POST /api/admin/create
|
| because that endpoint creates the FIRST administrator.
|
*/

export default async function adminAuth(
    req: Request,
    res: Response,
    next: NextFunction
) {
    try {
        /*
        |--------------------------------------------------------------------------
        | Get Authorization header
        |--------------------------------------------------------------------------
        */

        const authorization =
            req.headers.authorization;

        if (!authorization) {
            return res.status(401).json({
                error:
                    'Authorization header is missing',
            });
        }

        /*
        |--------------------------------------------------------------------------
        | Check Bearer format
        |--------------------------------------------------------------------------
        */

        if (
            !authorization.startsWith(
                'Bearer '
            )
        ) {
            return res.status(401).json({
                error:
                    'Invalid authorization format. Expected Bearer token.',
            });
        }

        /*
        |--------------------------------------------------------------------------
        | Extract Firebase ID token
        |--------------------------------------------------------------------------
        */

        const token =
            authorization.substring(7).trim();

        if (!token) {
            return res.status(401).json({
                error:
                    'Firebase token is missing',
            });
        }

        /*
        |--------------------------------------------------------------------------
        | Verify Firebase ID token
        |--------------------------------------------------------------------------
        */

        const decodedToken =
            await getAuth().verifyIdToken(
                token
            );

        console.log(
            'Firebase UID:',
            decodedToken.uid
        );

        /*
        |--------------------------------------------------------------------------
        | Find admin in PostgreSQL
        |--------------------------------------------------------------------------
        */

        const result =
            await pool.query(
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

        /*
        |--------------------------------------------------------------------------
        | Firebase user is not an admin
        |--------------------------------------------------------------------------
        */

        if (
            result.rows.length === 0
        ) {
            console.log(
                'No admin found for Firebase UID:',
                decodedToken.uid
            );

            return res.status(403).json({
                error:
                    'Not an admin',
                firebase_uid:
                    decodedToken.uid,
            });
        }

        const adminUser =
            result.rows[0];

        /*
        |--------------------------------------------------------------------------
        | Check account status
        |--------------------------------------------------------------------------
        */

        if (
            adminUser.account_status !==
            'active'
        ) {
            return res.status(403).json({
                error:
                    'Admin account is not active',
            });
        }

        /*
        |--------------------------------------------------------------------------
        | Check role
        |--------------------------------------------------------------------------
        */

        if (
            adminUser.role !==
            'admin'
        ) {
            return res.status(403).json({
                error:
                    'User does not have administrator privileges',
            });
        }

        /*
        |--------------------------------------------------------------------------
        | Attach admin to request
        |--------------------------------------------------------------------------
        */

        (
            req as any
        ).adminUser = adminUser;

        /*
        |--------------------------------------------------------------------------
        | Continue
        |--------------------------------------------------------------------------
        */

        next();
    } catch (error: any) {
        console.error(
            'Admin authentication error:',
            error
        );

        /*
        |--------------------------------------------------------------------------
        | Firebase token errors
        |--------------------------------------------------------------------------
        */

        return res.status(401).json({
            error:
                'Invalid authentication',
            details:
                error?.message ||
                'Unable to verify Firebase token',
        });
    }
}
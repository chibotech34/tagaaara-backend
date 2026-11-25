import { Request, Response, NextFunction } from 'express';
import { firebaseAuth } from '../config/firebase';

export interface DecodedFirebaseToken {
    uid: string;
    email?: string;
    name?: string;
    // Admin / RBAC claims (set via Firebase Admin SDK custom claims)
    admin?: boolean;
    role?: string;
    roles?: string[];
    [key: string]: unknown;
}

export interface AuthenticatedRequest extends Request {
    decodedToken?: DecodedFirebaseToken;
}

/* -------------------------------------------------------------------------- */
/*                                Helpers                                     */
/* -------------------------------------------------------------------------- */

// Emails that are always treated as admins (fallback for accounts that
// don't have Firebase custom claims set yet). Configure via env:
//   ADMIN_EMAILS="boss@example.com,ops@example.com"
const ADMIN_EMAILS: string[] = (process.env.ADMIN_EMAILS ?? '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);

const ROLES_CACHE = new Set<string>();

const hasAdminClaim = (token: DecodedFirebaseToken): boolean => {
    if (token.admin === true) return true;

    if (typeof token.role === 'string' && token.role.toLowerCase() === 'admin') {
        return true;
    }

    if (Array.isArray(token.roles)) {
        return token.roles.some((r) => String(r).toLowerCase() === 'admin');
    }

    return false;
};

const hasAnyRole = (token: DecodedFirebaseToken, roles: string[]): boolean => {
    if (roles.length === 0) return true;

    const wanted = roles.map((r) => r.toLowerCase());
    const owned: string[] = [];

    if (typeof token.role === 'string') owned.push(token.role.toLowerCase());
    if (Array.isArray(token.roles)) owned.push(...token.roles.map((r) => String(r).toLowerCase()));

    return owned.some((r) => wanted.includes(r));
};

/* -------------------------------------------------------------------------- */
/*                          Token verification                                */
/* -------------------------------------------------------------------------- */

export const verifyFirebaseToken = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
            success: false,
            message: 'Missing or invalid Authorization header. Expected Bearer token.',
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
        // `true` = check whether the token was revoked / user disabled.
        const decodedToken = await firebaseAuth.verifyIdToken(token, true);

        // Preserve custom claims (admin, role, roles, etc.) so downstream
        // middleware can perform RBAC checks.
        req.decodedToken = {
            ...(decodedToken as unknown as DecodedFirebaseToken),
        };

        next();
    } catch (error: unknown) {
        console.error('❌ Firebase token verification failed:', error);
        const firebaseError = error as { code?: string; message?: string };

        if (firebaseError.code === 'auth/id-token-expired') {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token expired.',
                code: 'AUTH_TOKEN_EXPIRED',
            });
            return;
        }

        if (firebaseError.code === 'auth/id-token-revoked') {
            res.status(401).json({
                success: false,
                message: 'Firebase ID token revoked.',
                code: 'AUTH_TOKEN_REVOKED',
            });
            return;
        }

        if (firebaseError.code === 'auth/user-disabled') {
            res.status(403).json({
                success: false,
                message: 'User account has been disabled.',
                code: 'AUTH_USER_DISABLED',
            });
            return;
        }

        res.status(401).json({
            success: false,
            message: 'Firebase authentication failed.',
            code: 'AUTH_TOKEN_INVALID',
        });
    }
};

/* -------------------------------------------------------------------------- */
/*                            Admin / RBAC                                    */
/* -------------------------------------------------------------------------- */

/**
 * Requires the caller to be an admin.
 *
 * Admin is granted if ANY of the following is true:
 *   1. Firebase custom claim `admin === true`
 *   2. Firebase custom claim `role === 'admin'`
 *   3. Firebase custom claim `roles` contains `'admin'`
 *   4. The token email is listed in the `ADMIN_EMAILS` env var
 *
 * Always mount AFTER `verifyFirebaseToken`, e.g.:
 *   router.get('/admin/users',
 *       verifyFirebaseToken,
 *       requireAdmin,
 *       listUsersHandler);
 */
export const requireAdmin = (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): void => {
    const token = req.decodedToken;

    if (!token) {
        res.status(401).json({
            success: false,
            message: 'Authentication required before admin authorization.',
            code: 'AUTH_TOKEN_MISSING',
        });
        return;
    }

    const emailIsAdmin =
        !!token.email && ADMIN_EMAILS.includes(token.email.toLowerCase());

    if (hasAdminClaim(token) || emailIsAdmin) {
        next();
        return;
    }

    res.status(403).json({
        success: false,
        message: 'Admin privileges are required to access this resource.',
        code: 'ADMIN_FORBIDDEN',
    });
};

/**
 * Role-based access control factory.
 *
 * Example:
 *   router.get('/reports',
 *       verifyFirebaseToken,
 *       requireRole('admin', 'analyst'),
 *       reportsHandler);
 */
export const requireRole = (...roles: string[]) => {
    if (roles.length === 0) {
        throw new Error('requireRole() requires at least one role.');
    }

    // Minor cache to avoid re-lowercasing on every request.
    roles.forEach((r) => ROLES_CACHE.add(r.toLowerCase()));

    return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
        const token = req.decodedToken;

        if (!token) {
            res.status(401).json({
                success: false,
                message: 'Authentication required before role authorization.',
                code: 'AUTH_TOKEN_MISSING',
            });
            return;
        }

        if (hasAnyRole(token, roles)) {
            next();
            return;
        }

        res.status(403).json({
            success: false,
            message: `Access denied. Required role(s): ${roles.join(', ')}.`,
            code: 'ROLE_FORBIDDEN',
        });
    };
};

/**
 * Convenience: verify the Firebase token AND require admin in one middleware.
 * Useful for endpoints where you don't need the decoded token elsewhere.
 */
export const verifyFirebaseTokenAndRequireAdmin = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> => {
    await verifyFirebaseToken(req, res, () => {
        requireAdmin(req, res, next);
    });
};
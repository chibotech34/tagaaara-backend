import dotenv from 'dotenv';

dotenv.config();

import express, {
    Request,
    Response,
    NextFunction,
} from 'express';

import cors from 'cors';

import path from 'path';   // ⭐ CHANGED
import fs from 'fs';       // ⭐ CHANGED

import pool from './config/database';

// Initialize Firebase ONCE.
import './config/firebase';

import {
    verifyFirebaseToken as adminAuth,
} from './middleware/firebaseAdmin';

import passengerRoutes from './routes/passengerRoutes';
import passengerWalletRoutes from './routes/passengerWalletRoutes';
import driverRoutes from './routes/driverRoutes';
import driverWalletRoutes from './routes/driverWalletRoutes';
import driverSubscriptionRoutes from './routes/driverSubscriptionRoutes';
import rideRoutes from './routes/rideRoutes';
import mapRoutes from './routes/mapRoutes';
import notificationRoutes from './routes/notificationRoutes';
import paystackWebhookRoutes from './routes/paystackWebhookRoutes';

/*
|--------------------------------------------------------------------------
| Types
|--------------------------------------------------------------------------
*/

interface AdminUser {
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

interface AuthRequest extends Request {
    adminUser?: AdminUser;
}

/*
|--------------------------------------------------------------------------
| App
|--------------------------------------------------------------------------
*/

const app = express();

/*
|--------------------------------------------------------------------------
| Environment
|--------------------------------------------------------------------------
*/

const PORT = Number(process.env.PORT) || 5000;

if (!process.env.DATABASE_URL) {
    throw new Error('Missing DATABASE_URL');
}

if (!process.env.FIREBASE_DATABASE_URL) {
    throw new Error('Missing FIREBASE_DATABASE_URL');
}

/*
|--------------------------------------------------------------------------
| Request logging (early)
|--------------------------------------------------------------------------
*/

app.use((req, _res, next) => {
    console.log(
        `[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`,
    );
    next();
});

/*
|--------------------------------------------------------------------------
| CORS
|--------------------------------------------------------------------------
*/

app.use(
    cors({
        origin: true,
        credentials: true,
    }),
);

/*
|--------------------------------------------------------------------------
| BODY PARSERS
|--------------------------------------------------------------------------
*/

app.use(
    express.json({
        limit: '10mb',
        verify: (req: Request, _res: Response, buf: Buffer) => {
            (req as any).rawBody = buf;
        },
    }),
);

app.use(
    express.urlencoded({
        extended: true,
        limit: '10mb',
    }),
);

/*
|--------------------------------------------------------------------------
| Paystack Webhook
|--------------------------------------------------------------------------
| POST /api/webhooks/paystack
*/

app.use(
    '/api',
    paystackWebhookRoutes,
);

/*
|--------------------------------------------------------------------------
| Notification Routes
|--------------------------------------------------------------------------
*/

app.use(
    '/api/notifications',
    notificationRoutes,
);

/*
|--------------------------------------------------------------------------
| Health Check
|--------------------------------------------------------------------------
*/

app.get(
    '/api/health',
    async (_req: Request, res: Response) => {
        try {
            await pool.query('SELECT 1');

            return res.status(200).json({
                success: true,
                message: 'Tegaara backend is running',
                database: 'connected',
                firebase: 'configured',
                timestamp: new Date().toISOString(),
            });
        } catch (error: unknown) {
            console.error('❌ Health check database error:', error);

            const dbError = error as { message?: string };

            return res.status(500).json({
                success: false,
                message: 'Database connection failed',
                database: 'disconnected',
                firebase: 'configured',
                error: dbError.message,
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| Database Connection Test
|--------------------------------------------------------------------------
*/

pool.query('SELECT NOW()')
    .then((result) => {
        console.log('✅ PostgreSQL connected successfully');
        console.log('   Server time:', result.rows[0].now);
    })
    .catch((error) => {
        console.error('❌ PostgreSQL connection failed:', error);
    });

/*
|--------------------------------------------------------------------------
| RIDE ROUTES
|--------------------------------------------------------------------------
*/

app.use('/api', rideRoutes);

/*
|--------------------------------------------------------------------------
| Passenger Wallet Routes  (Paystack + wallet ledger)
|--------------------------------------------------------------------------
*/

app.use('/api', passengerWalletRoutes);

/*
|--------------------------------------------------------------------------
| Passenger Routes
|--------------------------------------------------------------------------
*/

app.use('/api/passengers', passengerRoutes);

/*
|--------------------------------------------------------------------------
| Driver Routes
|--------------------------------------------------------------------------
*/

app.use('/api/drivers', driverRoutes);

/*
|--------------------------------------------------------------------------
| Driver Wallet Routes
|--------------------------------------------------------------------------
*/

app.use('/api/drivers', driverWalletRoutes);

/*
|--------------------------------------------------------------------------
| Driver Subscription Routes
|--------------------------------------------------------------------------
| Plans, current subscription, trial activation, payments and verification.
*/

app.use('/api/drivers/subscription', driverSubscriptionRoutes);

/*
|--------------------------------------------------------------------------
| Map Routes
|--------------------------------------------------------------------------
*/

app.use('/api/maps', mapRoutes);

/*
|--------------------------------------------------------------------------
| PUBLIC ADMIN ROUTES
|--------------------------------------------------------------------------
*/

app.get(
    '/api/admin/exists',
    async (_req: Request, res: Response) => {
        try {
            const result = await pool.query(
                `SELECT id FROM public.admins LIMIT 1`,
            );

            return res.status(200).json({
                exists: result.rows.length > 0,
            });
        } catch (error: unknown) {
            console.error('❌ Error checking admin existence:', error);

            return res.status(500).json({
                success: false,
                error: 'Database error',
            });
        }
    },
);

app.post(
    '/api/admin/create',
    async (req: Request, res: Response) => {
        const {
            email,
            password,
            fullName,
            phoneNumber,
            username,
            profilePhoto,
            accountStatus,
        } = req.body ?? {};

        if (!email || !password || !fullName) {
            return res.status(400).json({
                success: false,
                error: 'Email, password and full name are required',
            });
        }

        try {
            const { firebaseAuth, realtimeDb } = await import(
                './config/firebase'
            );

            const normalizedEmail = String(email).trim().toLowerCase();

            const existingAdmin = await pool.query(
                `
                SELECT id
                FROM public.admins
                WHERE LOWER(email) = $1
                LIMIT 1
                `,
                [normalizedEmail],
            );

            if (existingAdmin.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    error: 'An admin with this email already exists',
                });
            }

            try {
                const existingFirebaseUser =
                    await firebaseAuth.getUserByEmail(normalizedEmail);

                if (existingFirebaseUser) {
                    return res.status(409).json({
                        success: false,
                        error: 'A Firebase user with this email already exists',
                    });
                }
            } catch (firebaseError: any) {
                if (firebaseError.code !== 'auth/user-not-found') {
                    throw firebaseError;
                }
            }

            const userRecord = await firebaseAuth.createUser({
                email: normalizedEmail,
                password,
                displayName: fullName,
            });

            const firebaseUid = userRecord.uid;

            console.log('✅ Created Firebase admin UID:', firebaseUid);

            const result = await pool.query(
                `
                INSERT INTO public.admins
                (
                    firebase_uid,
                    email,
                    full_name,
                    phone_number,
                    username,
                    profile_photo_url,
                    account_status,
                    role
                )
                VALUES
                (
                    $1, $2, $3, $4, $5, $6, $7, $8
                )
                RETURNING *
                `,
                [
                    firebaseUid,
                    normalizedEmail,
                    fullName,
                    phoneNumber || null,
                    username || null,
                    profilePhoto || null,
                    accountStatus || 'active',
                    'admin',
                ],
            );

            await realtimeDb.ref(`admins/${firebaseUid}`).set({
                firebaseUid,
                email: normalizedEmail,
                fullName,
                phoneNumber: phoneNumber || '',
                username: username || '',
                profilePhoto: profilePhoto || '',
                accountStatus: accountStatus || 'active',
                role: 'admin',
                createdAt: new Date().toISOString(),
            });

            const admin = result.rows[0];

            return res.status(201).json({
                success: true,
                message: 'Admin created successfully',
                uid: firebaseUid,
                adminId: admin.id,
                admin: {
                    id: admin.id,
                    firebaseUid: admin.firebase_uid,
                    email: admin.email,
                    fullName: admin.full_name,
                    phoneNumber: admin.phone_number,
                    username: admin.username,
                    profilePhoto: admin.profile_photo_url,
                    accountStatus: admin.account_status,
                    role: admin.role,
                    createdAt: admin.created_at,
                },
            });
        } catch (error: unknown) {
            console.error('❌ Error creating admin:', error);

            const firebaseError = error as {
                code?: string;
                message?: string;
            };

            return res.status(500).json({
                success: false,
                error:
                    firebaseError.message || 'Failed to create admin',
                code: firebaseError.code || 'ADMIN_CREATE_FAILED',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| ADMIN AUTHENTICATION
|--------------------------------------------------------------------------
| ⭐ CHANGED: scope auth to /api only.
| Everything below this line is an API route that requires a Firebase
| token + admin record. Non-API requests (the SPA) are NOT intercepted,
| so the SPA fallback further down works without an auth token.
*/

app.use('/api', adminAuth);   // ⭐ CHANGED from: app.use(adminAuth);

/*
|--------------------------------------------------------------------------
| Admin Profile
|--------------------------------------------------------------------------
*/

app.get(
    '/api/admin/me',
    (req: AuthRequest, res: Response) => {
        if (!req.adminUser) {
            return res.status(404).json({
                success: false,
                error: 'Admin not found',
            });
        }

        const admin = req.adminUser;

        return res.status(200).json({
            success: true,
            admin: {
                id: admin.id,
                firebaseUid: admin.firebase_uid,
                email: admin.email,
                fullName: admin.full_name,
                phoneNumber: admin.phone_number,
                username: admin.username,
                profilePhoto: admin.profile_photo_url,
                accountStatus: admin.account_status,
                role: admin.role || 'admin',
                createdAt: admin.created_at,
            },
        });
    },
);

/*
|--------------------------------------------------------------------------
| Dashboard Statistics  (extended)
|--------------------------------------------------------------------------
*/

app.get(
    '/api/stats',
    async (_req: AuthRequest, res: Response) => {
        const safeCount = async (
            label: string,
            sql: string,
            params: any[] = [],
        ): Promise<number> => {
            try {
                const r = await pool.query(sql, params);
                return Number(r.rows[0]?.v ?? 0);
            } catch (err) {
                console.warn(`⚠️  Stats sub-query failed [${label}]:`, err);
                return 0;
            }
        };

        try {
            const [
                totalPassengers,
                activeDrivers,
                activeRides,
                todaysRevenue,
                averageDriverRating,
                cancelledCount,
                totalRidesForRate,
            ] = await Promise.all([
                safeCount(
                    'totalPassengers',
                    `SELECT COUNT(*)::int AS v FROM public.passengers`,
                ),
                safeCount(
                    'activeDrivers',
                    `SELECT COUNT(*)::int AS v FROM public.drivers WHERE is_online = true`,
                ),
                safeCount(
                    'activeRides',
                    `
                    SELECT COUNT(*)::int AS v FROM public.rides
                    WHERE status IN
                        ('pending','accepted','in_progress','ongoing','started')
                    `,
                ),
                safeCount(
                    'todaysRevenue',
                    `
                    SELECT COALESCE(SUM(COALESCE(fare, amount, 0)), 0)::float AS v
                    FROM public.rides
                    WHERE status = 'completed'
                      AND DATE(COALESCE(completed_at, updated_at, created_at))
                          = CURRENT_DATE
                    `,
                ),
                safeCount(
                    'averageDriverRating',
                    `
                    SELECT COALESCE(AVG(rating), 0)::float AS v
                    FROM public.drivers
                    WHERE rating IS NOT NULL
                    `,
                ),
                safeCount(
                    'cancelledCount',
                    `
                    SELECT COUNT(*)::int AS v FROM public.rides
                    WHERE status = 'cancelled'
                    `,
                ),
                safeCount(
                    'totalRidesForRate',
                    `SELECT COUNT(*)::int AS v FROM public.rides`,
                ),
            ]);

            const cancellationRate =
                totalRidesForRate === 0
                    ? 0
                    : Math.round(
                        (cancelledCount / totalRidesForRate) * 1000,
                    ) / 10;

            return res.status(200).json({
                totalPassengers,
                activeDrivers,
                activeRides,
                todaysRevenue,
                averageDriverRating,
                cancellationRate,
            });
        } catch (error: unknown) {
            console.error('❌ Stats error:', error);

            return res.status(200).json({
                totalPassengers: 0,
                activeDrivers: 0,
                activeRides: 0,
                todaysRevenue: 0,
                averageDriverRating: 0,
                cancellationRate: 0,
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| Admin Drivers
|--------------------------------------------------------------------------
*/

app.get(
    '/api/admin/drivers',
    async (_req: AuthRequest, res: Response) => {
        try {
            let result;

            try {
                result = await pool.query(`
                    SELECT
                        d.*,
                        d.full_name AS name,
                        (SELECT COUNT(*)::int
                         FROM public.rides r
                         WHERE r.driver_id = d.id) AS "rideCount"
                    FROM public.drivers d
                    ORDER BY d.created_at DESC
                `);
            } catch (innerErr) {
                console.warn(
                    '⚠️  drivers rideCount sub-query failed, falling back to 0:',
                    innerErr,
                );
                result = await pool.query(`
                    SELECT
                        d.*,
                        d.full_name AS name,
                        0::int AS "rideCount"
                    FROM public.drivers d
                    ORDER BY d.created_at DESC
                `);
            }

            return res.status(200).json({
                success: true,
                drivers: result.rows,
            });
        } catch (error: unknown) {
            console.error('❌ Error fetching drivers:', error);

            return res.status(500).json({
                success: false,
                error: 'Failed to fetch drivers',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| Admin Passengers  (list)
|--------------------------------------------------------------------------
*/

app.get(
    '/api/admin/passengers',
    async (_req: AuthRequest, res: Response) => {
        try {
            let result;

            try {
                result = await pool.query(`
                    SELECT
                        id,
                        full_name AS name,
                        phone,
                        region,
                        status,
                        COALESCE(total_rides, 0)::int AS "totalRides"
                    FROM public.passengers
                    ORDER BY created_at DESC
                `);
            } catch (innerErr) {
                console.warn(
                    '⚠️  passengers.total_rides missing, falling back to 0:',
                    innerErr,
                );
                result = await pool.query(`
                    SELECT
                        id,
                        full_name AS name,
                        phone,
                        region,
                        status,
                        0::int AS "totalRides"
                    FROM public.passengers
                    ORDER BY created_at DESC
                `);
            }

            return res.status(200).json({
                success: true,
                passengers: result.rows,
            });
        } catch (error: unknown) {
            console.error('❌ Admin passengers error:', error);

            return res.status(500).json({
                success: false,
                error: 'Failed to fetch passengers',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| Rickshaws
|--------------------------------------------------------------------------
*/

app.get(
    '/api/rickshaws',
    async (_req: AuthRequest, res: Response) => {
        try {
            try {
                const result = await pool.query(`
                    SELECT
                        r.id,
                        r.registration_number AS "registrationNumber",
                        COALESCE(d.full_name, 'Unassigned') AS driver,
                        r.status,
                        COALESCE(r.verification_status, r.status) AS "verificationStatus"
                    FROM public.rickshaws r
                    LEFT JOIN public.drivers d ON r.driver_id = d.id
                    ORDER BY r.created_at DESC
                `);

                return res.status(200).json({
                    success: true,
                    rickshaws: result.rows,
                });
            } catch (innerErr) {
                console.warn(
                    '⚠️  public.rickshaws missing, deriving from drivers:',
                    innerErr,
                );

                const result = await pool.query(`
                    SELECT
                        d.id,
                        COALESCE(d.registration_number, 'N/A') AS "registrationNumber",
                        d.full_name AS driver,
                        CASE
                            WHEN d.is_online THEN 'active'
                            ELSE 'inactive'
                        END AS status,
                        d.status AS "verificationStatus"
                    FROM public.drivers d
                    WHERE d.registration_number IS NOT NULL
                    ORDER BY d.created_at DESC
                `);

                return res.status(200).json({
                    success: true,
                    rickshaws: result.rows,
                });
            }
        } catch (error: unknown) {
            console.error('❌ Rickshaws error:', error);

            return res.status(500).json({
                success: false,
                error: 'Failed to fetch rickshaws',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| Finance  (transaction ledger)
|--------------------------------------------------------------------------
*/

app.get(
    '/api/finance',
    async (_req: AuthRequest, res: Response) => {
        const tables = [
            'transactions',
            'payments',
            'wallet_transactions',
        ];

        for (const table of tables) {
            try {
                const result = await pool.query(`
                    SELECT
                        t.id,
                        t.ride_id AS "rideId",
                        COALESCE(p.full_name, 'Unknown') AS passenger,
                        COALESCE(t.amount, 0)::float AS amount,
                        COALESCE(t.status, 'unknown') AS status
                    FROM public.${table} t
                    LEFT JOIN public.passengers p
                        ON t.passenger_id = p.id
                    ORDER BY t.created_at DESC
                    LIMIT 200
                `);

                return res.status(200).json({
                    success: true,
                    finance: result.rows,
                });
            } catch (err) {
                console.warn(
                    `⚠️  Finance table "${table}" not usable, trying next:`,
                    (err as any)?.message ?? err,
                );
            }
        }

        console.warn(
            '⚠️  No finance table found — returning empty finance list.',
        );

        return res.status(200).json({
            success: true,
            finance: [],
        });
    },
);

/*
|--------------------------------------------------------------------------
| Settings  (system configuration)
|--------------------------------------------------------------------------
*/

app.get(
    '/api/settings',
    async (_req: AuthRequest, res: Response) => {
        const defaults = {
            name: 'Tegaara',
            supportEmail: 'support@tegaara.app',
            driverSearchRadius: '5 km',
            sessionTimeout: '30 min',
            notificationEnabled: true,
        };

        try {
            const result = await pool.query(`
                SELECT *
                FROM public.system_settings
                LIMIT 1
            `);

            const s = result.rows[0] ?? {};

            return res.status(200).json({
                name: s.name ?? defaults.name,
                supportEmail:
                    s.support_email ?? defaults.supportEmail,
                driverSearchRadius:
                    s.driver_search_radius ??
                    defaults.driverSearchRadius,
                sessionTimeout:
                    s.session_timeout ?? defaults.sessionTimeout,
                notificationEnabled:
                    s.notification_enabled ??
                    defaults.notificationEnabled,
            });
        } catch (err) {
            console.warn(
                '⚠️  public.system_settings unavailable, using defaults:',
                (err as any)?.message ?? err,
            );

            return res.status(200).json(defaults);
        }
    },
);

/*
|--------------------------------------------------------------------------
| Pending Drivers
|--------------------------------------------------------------------------
*/

app.get(
    '/api/admin/pending-drivers',
    async (req: AuthRequest, res: Response) => {
        try {
            const page = Math.max(Number(req.query.page) || 1, 1);

            const limit = Math.min(
                Math.max(Number(req.query.limit) || 10, 1),
                100,
            );

            const offset = (page - 1) * limit;

            const search = String(req.query.search || '').trim();
            const status = String(req.query.status || 'pending').trim();

            const params: any[] = [status];

            let whereClause = `WHERE d.status = $1`;
            let parameterIndex = 2;

            if (search) {
                whereClause += `
                    AND (
                        d.full_name ILIKE $${parameterIndex}
                        OR d.phone ILIKE $${parameterIndex}
                        OR d.email ILIKE $${parameterIndex}
                        OR d.registration_number ILIKE $${parameterIndex}
                    )
                `;

                params.push(`%${search}%`);
                parameterIndex++;
            }

            const countResult = await pool.query(
                `
                SELECT COUNT(*)::int AS total
                FROM public.drivers d
                ${whereClause}
                `,
                params,
            );

            const total = countResult.rows[0]?.total || 0;

            const dataParams = [...params, limit, offset];

            const dataResult = await pool.query(
                `
                SELECT
                    d.*,
                    a.full_name AS reviewer_name,
                    a.id AS reviewer_id
                FROM public.drivers d
                LEFT JOIN public.admins a
                    ON d.reviewer_id = a.id
                ${whereClause}
                ORDER BY d.created_at DESC
                LIMIT $${parameterIndex}
                OFFSET $${parameterIndex + 1}
                `,
                dataParams,
            );

            return res.status(200).json({
                success: true,
                drivers: dataResult.rows,
                pagination: {
                    page,
                    limit,
                    total,
                    totalPages: Math.ceil(total / limit),
                },
            });
        } catch (error: unknown) {
            console.error('❌ Pending drivers error:', error);

            const dbError = error as { message?: string };

            return res.status(500).json({
                success: false,
                error:
                    dbError.message || 'Failed to fetch pending drivers',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| Get Driver
|--------------------------------------------------------------------------
*/

app.get(
    '/api/admin/drivers/:id',
    async (req: AuthRequest, res: Response) => {
        const driverId = Number(req.params.id);

        if (!Number.isInteger(driverId)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid driver ID',
            });
        }

        try {
            const result = await pool.query(
                `
                SELECT
                    d.*,
                    a.full_name AS reviewer_name
                FROM public.drivers d
                LEFT JOIN public.admins a
                    ON d.reviewer_id = a.id
                WHERE d.id = $1
                `,
                [driverId],
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    error: 'Driver not found',
                });
            }

            return res.status(200).json({
                success: true,
                driver: result.rows[0],
            });
        } catch (error: unknown) {
            console.error('❌ Driver details error:', error);

            return res.status(500).json({
                success: false,
                error: 'Failed to fetch driver',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| Approve Driver
|--------------------------------------------------------------------------
*/

app.post(
    '/api/admin/drivers/:id/approve',
    async (req: AuthRequest, res: Response) => {
        const driverId = Number(req.params.id);

        if (!Number.isInteger(driverId)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid driver ID',
            });
        }

        if (!req.adminUser) {
            return res.status(403).json({
                success: false,
                error: 'Admin authentication required',
            });
        }

        try {
            const check = await pool.query(
                `SELECT status FROM public.drivers WHERE id = $1`,
                [driverId],
            );

            if (check.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    error: 'Driver not found',
                });
            }

            const currentStatus = check.rows[0].status;

            if (['approved', 'rejected'].includes(currentStatus)) {
                return res.status(400).json({
                    success: false,
                    error: `Cannot approve driver with status '${currentStatus}'`,
                });
            }

            await pool.query(
                `
                UPDATE public.drivers
                SET
                    status = 'approved',
                    updated_at = CURRENT_TIMESTAMP,
                    verification_checked_at = CURRENT_TIMESTAMP,
                    verification_checked_by = $1
                WHERE id = $2
                `,
                [req.adminUser.id, driverId],
            );

            await pool.query(
                `
                INSERT INTO public.verification_audit_log
                (driver_id, admin_id, action, previous_status, new_status)
                VALUES ($1, $2, 'approve', $3, 'approved')
                `,
                [driverId, req.adminUser.id, currentStatus],
            );

            return res.status(200).json({
                success: true,
                message: 'Driver approved successfully',
            });
        } catch (error: unknown) {
            console.error('❌ Approve driver error:', error);

            return res.status(500).json({
                success: false,
                error: 'Failed to approve driver',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| Reject Driver
|--------------------------------------------------------------------------
*/

app.post(
    '/api/admin/drivers/:id/reject',
    async (req: AuthRequest, res: Response) => {
        const driverId = Number(req.params.id);

        const reason = String(req.body?.reason || '').trim();

        if (!Number.isInteger(driverId)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid driver ID',
            });
        }

        if (!reason) {
            return res.status(400).json({
                success: false,
                error: 'Rejection reason is required',
            });
        }

        if (!req.adminUser) {
            return res.status(403).json({
                success: false,
                error: 'Admin authentication required',
            });
        }

        try {
            const check = await pool.query(
                `SELECT status FROM public.drivers WHERE id = $1`,
                [driverId],
            );

            if (check.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    error: 'Driver not found',
                });
            }

            const currentStatus = check.rows[0].status;

            if (['approved', 'rejected'].includes(currentStatus)) {
                return res.status(400).json({
                    success: false,
                    error: `Cannot reject driver with status '${currentStatus}'`,
                });
            }

            await pool.query(
                `
                UPDATE public.drivers
                SET
                    status = 'rejected',
                    updated_at = CURRENT_TIMESTAMP,
                    verification_checked_at = CURRENT_TIMESTAMP,
                    verification_checked_by = $1,
                    reviewer_comment = $2
                WHERE id = $3
                `,
                [req.adminUser.id, reason, driverId],
            );

            await pool.query(
                `
                INSERT INTO public.verification_audit_log
                (driver_id, admin_id, action, previous_status, new_status, reason)
                VALUES ($1, $2, 'reject', $3, 'rejected', $4)
                `,
                [driverId, req.adminUser.id, currentStatus, reason],
            );

            return res.status(200).json({
                success: true,
                message: 'Driver rejected successfully',
            });
        } catch (error: unknown) {
            console.error('❌ Reject driver error:', error);

            return res.status(500).json({
                success: false,
                error: 'Failed to reject driver',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| Request Driver Correction
|--------------------------------------------------------------------------
*/

app.post(
    '/api/admin/drivers/:id/request-correction',
    async (req: AuthRequest, res: Response) => {
        const driverId = Number(req.params.id);

        const message = String(req.body?.message || '').trim();

        if (!Number.isInteger(driverId)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid driver ID',
            });
        }

        if (!message) {
            return res.status(400).json({
                success: false,
                error: 'Correction message is required',
            });
        }

        if (!req.adminUser) {
            return res.status(403).json({
                success: false,
                error: 'Admin authentication required',
            });
        }

        try {
            const check = await pool.query(
                `SELECT status FROM public.drivers WHERE id = $1`,
                [driverId],
            );

            if (check.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    error: 'Driver not found',
                });
            }

            const currentStatus = check.rows[0].status;

            if (['approved', 'rejected'].includes(currentStatus)) {
                return res.status(400).json({
                    success: false,
                    error: `Cannot request correction for driver with status '${currentStatus}'`,
                });
            }

            await pool.query(
                `
                UPDATE public.drivers
                SET
                    status = 'action_required',
                    updated_at = CURRENT_TIMESTAMP,
                    correction_message = $1,
                    correction_requested_at = CURRENT_TIMESTAMP,
                    reviewer_id = $2
                WHERE id = $3
                `,
                [message, req.adminUser.id, driverId],
            );

            await pool.query(
                `
                INSERT INTO public.verification_audit_log
                (driver_id, admin_id, action, previous_status, new_status, reason)
                VALUES ($1, $2, 'request_correction', $3, 'action_required', $4)
                `,
                [driverId, req.adminUser.id, currentStatus, message],
            );

            return res.status(200).json({
                success: true,
                message: 'Correction requested successfully',
            });
        } catch (error: unknown) {
            console.error('❌ Correction request error:', error);

            return res.status(500).json({
                success: false,
                error: 'Failed to request correction',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| Driver Audit Log
|--------------------------------------------------------------------------
*/

app.get(
    '/api/admin/drivers/:id/audit',
    async (req: AuthRequest, res: Response) => {
        const driverId = Number(req.params.id);

        if (!Number.isInteger(driverId)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid driver ID',
            });
        }

        try {
            const result = await pool.query(
                `
                SELECT
                    l.*,
                    a.full_name AS admin_name
                FROM public.verification_audit_log l
                JOIN public.admins a
                    ON l.admin_id = a.id
                WHERE l.driver_id = $1
                ORDER BY l.created_at DESC
                `,
                [driverId],
            );

            return res.status(200).json({
                success: true,
                audit: result.rows,
            });
        } catch (error: unknown) {
            console.error('❌ Audit log error:', error);

            return res.status(500).json({
                success: false,
                error: 'Failed to fetch audit log',
            });
        }
    },
);

/*
|--------------------------------------------------------------------------
| 404 (API only)
|--------------------------------------------------------------------------
| ⭐ CHANGED: non-API requests fall through to the SPA fallback below.
*/

app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/api')) {
        return res.status(404).json({
            success: false,
            error: 'Route not found',
        });
    }
    next();
});

/*
|--------------------------------------------------------------------------
| Serve Frontend (Vite build output → backend/public)
|--------------------------------------------------------------------------
| ⭐ NEW: serves the React SPA from the same Express server.
*/

const clientDist = path.resolve(__dirname, '../public');

if (fs.existsSync(clientDist)) {
    console.log(`📦 Serving frontend from ${clientDist}`);

    // 1) Static assets (Vite emits hashed filenames → safe to cache).
    app.use(
        express.static(clientDist, {
            index: false,
            maxAge: '1y',
            immutable: true,
            setHeaders(res, filePath) {
                if (filePath.endsWith('index.html')) {
                    res.setHeader('Cache-Control', 'no-cache');
                }
            },
        }),
    );

    // 2) SPA fallback — any GET/HEAD without an extension renders index.html
    app.use((req: Request, res: Response, next: NextFunction) => {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
            return next();
        }
        if (path.extname(req.path)) {
            // Missing asset → let it fall through to the JSON 404 below.
            return next();
        }
        return res.sendFile(path.join(clientDist, 'index.html'));
    });
} else {
    console.warn(`⚠️  Frontend build not found at ${clientDist}`);
    console.warn(
        '   Run `npm run build:all` to build both backend and frontend.',
    );
}

/*
|--------------------------------------------------------------------------
| Final 404 (non-API only: e.g. POST /, or missing assets)
|--------------------------------------------------------------------------
*/

app.use((req: Request, res: Response) => {
    if (req.path.startsWith('/api')) {
        return res.status(404).json({
            success: false,
            error: 'Route not found',
        });
    }
    return res.status(404).send('Not found');
});

/*
|--------------------------------------------------------------------------
| Global Error Handler
|--------------------------------------------------------------------------
*/

app.use(
    (
        error: unknown,
        _req: Request,
        res: Response,
        _next: NextFunction,
    ) => {
        console.error('❌ Unhandled server error:', error);

        const serverError = error as { message?: string };

        return res.status(500).json({
            success: false,
            error:
                serverError.message || 'Internal server error',
        });
    },
);

/*
|--------------------------------------------------------------------------
| Start Server
|--------------------------------------------------------------------------
*/

app.listen(PORT, '0.0.0.0', () => {
    console.log('======================================');
    console.log(`🚀 Tegaara Backend running on port ${PORT}`);
    console.log(`   http://localhost:${PORT}`);
    console.log('======================================');
});
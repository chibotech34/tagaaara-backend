import dotenv from 'dotenv';
dotenv.config();

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';

import pool from './config/database';

import {
    initializeApp,
    cert,
    getApps,
} from 'firebase-admin/app';

import { getAuth } from 'firebase-admin/auth';
import { getDatabase } from 'firebase-admin/database';

import adminAuth from './middleware/firebaseAdmin';

import passengerRoutes from './routes/passengerRoutes';
import driverRoutes from './routes/driverRoutes';

// Extend Express Request to include adminUser from middleware
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

const app = express();

/* Middleware */
app.use(
    cors({
        origin: true,
        credentials: true,
    })
);
app.use(
    express.json({
        limit: '10mb',
    })
);

/* Environment Variables */
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('Missing DATABASE_URL');

const serviceAccountPath = process.env.FIREBASE_ADMIN_SDK_PATH;
if (!serviceAccountPath) throw new Error('Missing FIREBASE_ADMIN_SDK_PATH');

const firebaseDatabaseUrl = process.env.FIREBASE_DATABASE_URL;
if (!firebaseDatabaseUrl) throw new Error('Missing FIREBASE_DATABASE_URL');

/* Firebase Service Account */
const resolvedPath = path.resolve(process.cwd(), serviceAccountPath);
if (!fs.existsSync(resolvedPath)) {
    throw new Error(
        `Service account file not found at: ${resolvedPath}\n` +
        `Please check your FIREBASE_ADMIN_SDK_PATH environment variable.\n` +
        `Current value: "${serviceAccountPath}"`
    );
}

/* PostgreSQL Connection Test */
pool
    .query('SELECT NOW()')
    .then((result) => {
        console.log('✅ PostgreSQL connected successfully');
        console.log('   Server time:', result.rows[0].now);
    })
    .catch((error) => {
        console.error('❌ PostgreSQL connection failed:', error);
    });

/* Firebase Admin Initialization */
const serviceAccount = require(resolvedPath);
if (getApps().length === 0) {
    initializeApp({
        credential: cert(serviceAccount),
        databaseURL: firebaseDatabaseUrl,
    });
    console.log('✅ Firebase Admin initialized');
} else {
    console.log('ℹ️ Firebase Admin already initialized');
}

/*
|--------------------------------------------------------------------------
| PUBLIC ROUTES (no authentication)
|--------------------------------------------------------------------------
*/
app.get('/api/health', async (_req: Request, res: Response) => {
    try {
        await pool.query('SELECT 1');
        return res.json({
            success: true,
            message: 'Tegaara backend is running',
            database: 'connected',
            firebase: 'configured',
        });
    } catch (error: any) {
        console.error('Health check error:', error);
        return res.status(500).json({
            success: false,
            message: 'Database connection failed',
            error: error.message,
        });
    }
});

app.get('/api/admin/exists', async (_req: Request, res: Response) => {
    try {
        const result = await pool.query('SELECT id FROM public.admins LIMIT 1');
        const exists = result.rows.length > 0;
        return res.json({ exists });
    } catch (error: any) {
        console.error('Error checking admin existence:', error);
        return res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/admin/create', async (req: Request, res: Response) => {
    const { email, password, fullName, phoneNumber, username, profilePhoto, accountStatus } = req.body;

    if (!email || !password || !fullName) {
        return res.status(400).json({
            error: 'Email, password and full name are required',
        });
    }

    try {
        const normalizedEmail = String(email).trim().toLowerCase();

        const existingAdmin = await pool.query(
            `SELECT id FROM public.admins WHERE LOWER(email) = $1 LIMIT 1`,
            [normalizedEmail]
        );
        if (existingAdmin.rows.length > 0) {
            return res.status(409).json({ error: 'An admin with this email already exists' });
        }

        const userRecord = await getAuth().createUser({
            email: normalizedEmail,
            password,
            displayName: fullName,
        });
        const firebaseUid = userRecord.uid;
        console.log('Created Firebase admin UID:', firebaseUid);

        const query = `
            INSERT INTO public.admins
            (firebase_uid, email, full_name, phone_number, username, profile_photo_url, account_status, role)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *;
        `;
        const values = [
            firebaseUid,
            normalizedEmail,
            fullName,
            phoneNumber || null,
            username || null,
            profilePhoto || null,
            accountStatus || 'active',
            'admin',
        ];
        const result = await pool.query(query, values);

        const db = getDatabase();
        await db.ref(`admins/${firebaseUid}`).set({
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

        return res.status(201).json({
            message: 'Admin created successfully',
            uid: firebaseUid,
            adminId: result.rows[0].id,
            admin: {
                id: result.rows[0].id,
                firebaseUid: result.rows[0].firebase_uid,
                email: result.rows[0].email,
                fullName: result.rows[0].full_name,
                phoneNumber: result.rows[0].phone_number,
                username: result.rows[0].username,
                profilePhoto: result.rows[0].profile_photo_url,
                accountStatus: result.rows[0].account_status,
                role: result.rows[0].role,
                createdAt: result.rows[0].created_at,
            },
        });
    } catch (error: any) {
        console.error('❌ Error creating admin:', error);
        return res.status(500).json({ error: error.message || 'Failed to create admin' });
    }
});

/*
|--------------------------------------------------------------------------
| ROUTES THAT REQUIRE A VALID FIREBASE TOKEN BUT NOT ADMIN
| (Passenger & Driver registration / other non-admin endpoints)
|--------------------------------------------------------------------------
*/
app.use('/api/passenger', passengerRoutes);
app.use('/api/drivers', driverRoutes);

/*
|--------------------------------------------------------------------------
| PROTECTED ADMIN ROUTES (require Firebase Auth + admin check)
|--------------------------------------------------------------------------
*/
app.use(adminAuth);

app.get('/api/admin/me', (req: AuthRequest, res: Response) => {
    if (!req.adminUser) {
        return res.status(404).json({ error: 'Admin not found' });
    }
    const admin = req.adminUser;
    return res.json({
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
});

/* Dashboard endpoints (admin only) */
app.get('/api/stats', async (req: AuthRequest, res: Response) => {
    res.json({
        totalPassengers: 150,
        activeDrivers: 12,
        activeRides: 8,
        todaysRevenue: 4500,
        averageDriverRating: 4.5,
        cancellationRate: 3.2,
    });
});

app.get('/api/passengers', async (req: AuthRequest, res: Response) => {
    res.json([
        { id: 1, name: 'Alice Johnson', phone: '055-123-4567', region: 'Upper West', status: 'active', totalRides: 12 },
        { id: 2, name: 'Bob Mensah', phone: '055-234-5678', region: 'Upper West', status: 'inactive', totalRides: 4 },
    ]);
});

app.get('/api/drivers', async (req: AuthRequest, res: Response) => {
    res.json([
        { id: 1, name: 'Kwame Boateng', status: 'active', rating: 4.8, rideCount: 45 },
        { id: 2, name: 'Ama Serwaa', status: 'busy', rating: 4.2, rideCount: 33 },
    ]);
});

app.get('/api/rickshaws', async (req: AuthRequest, res: Response) => {
    res.json([
        { id: 1, registrationNumber: 'GW-1234-24', driver: 'Kwame Boateng', status: 'available', verificationStatus: 'verified' },
        { id: 2, registrationNumber: 'UW-5678-24', driver: 'Ama Serwaa', status: 'in_transit', verificationStatus: 'pending' },
    ]);
});

app.get('/api/rides', async (req: AuthRequest, res: Response) => {
    res.json([
        { id: 1, passenger: 'Alice Johnson', driver: 'Kwame Boateng', fare: 25.5, status: 'completed' },
        { id: 2, passenger: 'Bob Mensah', driver: 'Ama Serwaa', fare: 18.0, status: 'ongoing' },
    ]);
});

app.get('/api/finance', async (req: AuthRequest, res: Response) => {
    res.json([
        { id: 1, rideId: 1, passenger: 'Alice Johnson', amount: 25.5, status: 'completed' },
        { id: 2, rideId: 2, passenger: 'Bob Mensah', amount: 18.0, status: 'pending' },
    ]);
});

app.get('/api/settings', async (req: AuthRequest, res: Response) => {
    res.json({
        name: 'Tegaara',
        supportEmail: 'support@tegaara.com',
        driverSearchRadius: '5 km',
        sessionTimeout: '30 min',
        notificationEnabled: true,
    });
});

/* ================================================================
   PENDING VERIFICATION ENDPOINTS
   ================================================================ */

/**
 * Helper to safely parse driver ID from request params
 */
function parseDriverId(req: Request): number | null {
    const idParam = req.params.id;
    if (!idParam) return null;
    // Ensure it's a string (in case of array, take first element)
    const idStr = Array.isArray(idParam) ? idParam[0] : idParam;
    const parsed = parseInt(idStr, 10);
    return isNaN(parsed) ? null : parsed;
}

/**
 * GET /api/admin/pending-drivers
 * Fetch pending drivers with pagination, search, filters
 */
app.get('/api/admin/pending-drivers', async (req: AuthRequest, res: Response) => {
    try {
        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 10;
        const offset = (page - 1) * limit;
        const search = (req.query.search as string) || '';
        const statusFilter = (req.query.status as string) || 'pending';
        const priorityFilter = (req.query.priority as string) || '';
        const dateFrom = req.query.dateFrom as string;
        const dateTo = req.query.dateTo as string;

        let whereClause = `WHERE d.status = $1`;
        const params: any[] = [statusFilter];
        let paramIndex = 2;

        if (search) {
            whereClause += ` AND (d.full_name ILIKE $${paramIndex} OR d.phone ILIKE $${paramIndex} OR d.email ILIKE $${paramIndex} OR d.registration_number ILIKE $${paramIndex})`;
            params.push(`%${search}%`);
            paramIndex++;
        }
        if (priorityFilter) {
            whereClause += ` AND d.priority = $${paramIndex}`;
            params.push(priorityFilter);
            paramIndex++;
        }
        if (dateFrom) {
            whereClause += ` AND d.created_at >= $${paramIndex}`;
            params.push(dateFrom);
            paramIndex++;
        }
        if (dateTo) {
            whereClause += ` AND d.created_at <= $${paramIndex}`;
            params.push(dateTo);
            paramIndex++;
        }

        const countQuery = `SELECT COUNT(*) FROM public.drivers d ${whereClause}`;
        const countResult = await pool.query(countQuery, params);
        const total = parseInt(countResult.rows[0].count);

        const dataQuery = `
            SELECT d.*,
                   a.full_name AS reviewer_name,
                   a.id AS reviewer_id
            FROM public.drivers d
            LEFT JOIN public.admins a ON d.reviewer_id = a.id
            ${whereClause}
            ORDER BY d.created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        params.push(limit, offset);
        const dataResult = await pool.query(dataQuery, params);

        res.json({
            drivers: dataResult.rows,
            pagination: {
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit)
            }
        });
    } catch (error: any) {
        console.error('Error fetching pending drivers:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/admin/drivers/:id
 * Get full driver details (including all documents)
 */
app.get('/api/admin/drivers/:id', async (req: AuthRequest, res: Response) => {
    const driverId = parseDriverId(req);
    if (driverId === null) {
        return res.status(400).json({ error: 'Invalid driver ID' });
    }

    try {
        const result = await pool.query(
            `SELECT d.*, a.full_name AS reviewer_name
             FROM public.drivers d
             LEFT JOIN public.admins a ON d.reviewer_id = a.id
             WHERE d.id = $1`,
            [driverId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Driver not found' });
        }
        res.json(result.rows[0]);
    } catch (error: any) {
        console.error('Error fetching driver details:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/admin/drivers/:id/approve
 * Approve a driver (status must be pending or under_review)
 */
app.post('/api/admin/drivers/:id/approve', async (req: AuthRequest, res: Response) => {
    const driverId = parseDriverId(req);
    if (driverId === null) {
        return res.status(400).json({ error: 'Invalid driver ID' });
    }
    const admin = req.adminUser!;

    try {
        // Check current status
        const checkResult = await pool.query(
            `SELECT status FROM public.drivers WHERE id = $1`,
            [driverId]
        );
        if (checkResult.rows.length === 0) {
            return res.status(404).json({ error: 'Driver not found' });
        }
        const currentStatus = checkResult.rows[0].status;
        if (currentStatus !== 'pending' && currentStatus !== 'under_review' && currentStatus !== 'action_required') {
            return res.status(400).json({ error: `Cannot approve a driver with status '${currentStatus}'` });
        }

        // Update status and record approval
        await pool.query(
            `UPDATE public.drivers
             SET status = 'approved',
                 updated_at = CURRENT_TIMESTAMP,
                 verification_checked_at = CURRENT_TIMESTAMP,
                 verification_checked_by = $1
             WHERE id = $2`,
            [admin.id, driverId]
        );

        // Audit log
        await pool.query(
            `INSERT INTO public.verification_audit_log (driver_id, admin_id, action, previous_status, new_status)
             VALUES ($1, $2, 'approve', $3, 'approved')`,
            [driverId, admin.id, currentStatus]
        );

        // TODO: Fire notification (e.g., via Firebase RTDB or email)
        // await notifyDriver(driverId, 'approved');

        res.json({ success: true, message: 'Driver approved successfully' });
    } catch (error: any) {
        console.error('Error approving driver:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/admin/drivers/:id/reject
 * Reject a driver with a reason
 */
app.post('/api/admin/drivers/:id/reject', async (req: AuthRequest, res: Response) => {
    const driverId = parseDriverId(req);
    if (driverId === null) {
        return res.status(400).json({ error: 'Invalid driver ID' });
    }
    const { reason } = req.body;
    if (!reason) {
        return res.status(400).json({ error: 'Rejection reason is required' });
    }
    const admin = req.adminUser!;

    try {
        const checkResult = await pool.query(
            `SELECT status FROM public.drivers WHERE id = $1`,
            [driverId]
        );
        if (checkResult.rows.length === 0) return res.status(404).json({ error: 'Driver not found' });
        const currentStatus = checkResult.rows[0].status;
        if (currentStatus === 'approved' || currentStatus === 'rejected') {
            return res.status(400).json({ error: `Cannot reject a driver with status '${currentStatus}'` });
        }

        await pool.query(
            `UPDATE public.drivers
             SET status = 'rejected',
                 updated_at = CURRENT_TIMESTAMP,
                 verification_checked_at = CURRENT_TIMESTAMP,
                 verification_checked_by = $1,
                 reviewer_comment = $2
             WHERE id = $3`,
            [admin.id, reason, driverId]
        );

        await pool.query(
            `INSERT INTO public.verification_audit_log (driver_id, admin_id, action, previous_status, new_status, reason)
             VALUES ($1, $2, 'reject', $3, 'rejected', $4)`,
            [driverId, admin.id, currentStatus, reason]
        );

        // TODO: notifyDriver(driverId, 'rejected', reason);

        res.json({ success: true, message: 'Driver rejected' });
    } catch (error: any) {
        console.error('Error rejecting driver:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * POST /api/admin/drivers/:id/request-correction
 * Request corrections for a driver application
 */
app.post('/api/admin/drivers/:id/request-correction', async (req: AuthRequest, res: Response) => {
    const driverId = parseDriverId(req);
    if (driverId === null) {
        return res.status(400).json({ error: 'Invalid driver ID' });
    }
    const { message } = req.body;
    if (!message) {
        return res.status(400).json({ error: 'Correction message is required' });
    }
    const admin = req.adminUser!;

    try {
        const checkResult = await pool.query(
            `SELECT status FROM public.drivers WHERE id = $1`,
            [driverId]
        );
        if (checkResult.rows.length === 0) return res.status(404).json({ error: 'Driver not found' });
        const currentStatus = checkResult.rows[0].status;
        if (currentStatus === 'approved' || currentStatus === 'rejected') {
            return res.status(400).json({ error: `Cannot request correction for a driver with status '${currentStatus}'` });
        }

        await pool.query(
            `UPDATE public.drivers
             SET status = 'action_required',
                 updated_at = CURRENT_TIMESTAMP,
                 correction_message = $1,
                 correction_requested_at = CURRENT_TIMESTAMP,
                 reviewer_id = $2
             WHERE id = $3`,
            [message, admin.id, driverId]
        );

        await pool.query(
            `INSERT INTO public.verification_audit_log (driver_id, admin_id, action, previous_status, new_status, reason)
             VALUES ($1, $2, 'request_correction', $3, 'action_required', $4)`,
            [driverId, admin.id, currentStatus, message]
        );

        // TODO: notifyDriver(driverId, 'correction_required', message);

        res.json({ success: true, message: 'Correction requested' });
    } catch (error: any) {
        console.error('Error requesting correction:', error);
        res.status(500).json({ error: error.message });
    }
});

/**
 * GET /api/admin/drivers/:id/audit
 * Retrieve verification audit log for a driver
 */
app.get('/api/admin/drivers/:id/audit', async (req: AuthRequest, res: Response) => {
    const driverId = parseDriverId(req);
    if (driverId === null) {
        return res.status(400).json({ error: 'Invalid driver ID' });
    }

    try {
        const result = await pool.query(
            `SELECT l.*, a.full_name AS admin_name
             FROM public.verification_audit_log l
             JOIN public.admins a ON l.admin_id = a.id
             WHERE l.driver_id = $1
             ORDER BY l.created_at DESC`,
            [driverId]
        );
        res.json(result.rows);
    } catch (error: any) {
        console.error('Error fetching audit log:', error);
        res.status(500).json({ error: error.message });
    }
});

/* 404 Handler */
app.use((_req: Request, res: Response) => {
    return res.status(404).json({ error: 'Route not found' });
});

/* Global Error Handler */
app.use((error: any, _req: Request, res: Response, _next: NextFunction) => {
    console.error('Unhandled server error:', error);
    return res.status(500).json({
        error: error.message || 'Internal server error',
    });
});

/* Start Server */
const PORT = Number(process.env.PORT) || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log('======================================');
    console.log(`🚀 Tegaara Backend running on port ${PORT}`);
    console.log(`   http://localhost:${PORT}`);
    console.log('======================================');
});
import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
    throw new Error('Missing DATABASE_URL');
}

const pool = new Pool({
    connectionString: databaseUrl,
});

// ✅ Only export the pool instance as default
export default pool;
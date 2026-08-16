
import cors from 'cors';
import './config/firebase'; // <-- must come first
import express from 'express';


import adminRoutes from './routes/adminRoutes';

const app = express();

app.use(cors());

app.use(
    express.json({
        limit: '10mb',
    })
);

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'Tegaara backend is running',
    });
});

// Admin API
app.use('/api/admin', adminRoutes);

export default app;
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const axios = require('axios');
const PDFDocument = require('pdfkit');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const app = express();
const PORT = process.env.PORT || 5000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

pool.connect((err, client, release) => {
    if (err) {
        console.error('Error connecting to database:', err.stack);
    } else {
        console.log('Connected to Railway PostgreSQL database');
        release();
    }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
    origin: 'https://airtimesolutionfrontend.onrender.com',
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.set('trust proxy', 1);

app.use(session({
    store: new pgSession({
        pool: pool,
        tableName: 'session'
    }),
    secret: process.env.SESSION_SECRET || 'airtime-solution-kenya-secret-2024',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'none'
    }
}));

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - Origin: ${req.headers.origin}`);
    next();
});

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { success: false, message: 'Too many login attempts. Please try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false
});

const PAYNECTA_API_KEY = process.env.PAYNECTA_API_KEY;
const PAYNECTA_EMAIL = process.env.PAYNECTA_EMAIL;
const PAYNECTA_CODE = process.env.PAYNECTA_CODE || 'PNT_609202';
const STATUM_CONSUMER_KEY = process.env.STATUM_CONSUMER_KEY;
const STATUM_CONSUMER_SECRET = process.env.STATUM_CONSUMER_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '3462Abel@#';
const CALLBACK_BASE_URL = process.env.CALLBACK_BASE_URL || 'https://airtimesolutionbackend2.onrender.com';
const PAYHERO_LINK = 'https://short.payhero.co.ke/s/oEvAxA8Xx6cDoBLxntShmF';

function calculateBonus(amount) {
    if (amount >= 50) {
        return 6;
    }
    return 0;
}

function calculateAirtimeCost(amount) {
    return Math.floor(amount * 0.9);
}

app.get('/api/users/check-email/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const result = await pool.query('SELECT id, balance, bonus_balance FROM users WHERE LOWER(email) = LOWER($1)', [email]);
        if (result.rows.length > 0) {
            res.json({ 
                exists: true, 
                balance: parseFloat(result.rows[0].balance) + parseFloat(result.rows[0].bonus_balance)
            });
        } else {
            res.json({ exists: false });
        }
    } catch (error) {
        console.error('Check email error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/users/register', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ success: false, message: 'Email is required' });
        }
        
        const emailCheck = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
        if (emailCheck.rows.length > 0) {
            return res.status(400).json({ success: false, message: 'Email already registered' });
        }
        
        const id = uuidv4();
        
        await pool.query(
            `INSERT INTO users (id, email, balance, bonus_balance, is_disabled, created_at)
             VALUES ($1, $2, 0, 0, false, NOW())`,
            [id, email]
        );
        
        await pool.query(
            `INSERT INTO notifications (id, user_id, scope, title, message, is_read, created_at)
             VALUES ($1, $2, 'user', 'Welcome to Airtime Solution Kenya! 🎉', 'Thank you for joining us. Start by depositing funds to buy airtime.', false, NOW())`,
            [uuidv4(), id]
        );
        
        res.json({ success: true, message: 'User registered successfully', userId: id });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ success: false, message: 'Registration failed' });
    }
});

app.post('/api/users/update-firebase-uid', async (req, res) => {
    try {
        const { email, firebase_uid } = req.body;
        
        await pool.query(
            'UPDATE users SET firebase_uid = $1 WHERE LOWER(email) = LOWER($2)',
            [firebase_uid, email]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Update firebase uid error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/users/by-email/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const result = await pool.query(
            'SELECT id, email, balance, bonus_balance, is_disabled FROM users WHERE LOWER(email) = LOWER($1)',
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        if (result.rows[0].is_disabled) {
            return res.status(403).json({ success: false, message: 'Account is disabled. Contact support.' });
        }
        
        await pool.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [result.rows[0].id]);
        
        res.json({ success: true, user: result.rows[0] });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/users/balance-by-email/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const result = await pool.query(
            'SELECT balance, bonus_balance FROM users WHERE LOWER(email) = LOWER($1)',
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        res.json({
            success: true,
            balance: parseFloat(result.rows[0].balance),
            bonus: parseFloat(result.rows[0].bonus_balance),
            total: parseFloat(result.rows[0].balance) + parseFloat(result.rows[0].bonus_balance)
        });
    } catch (error) {
        console.error('Get balance error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/users/profile/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const result = await pool.query(
            `SELECT id, email, balance, bonus_balance, created_at, last_login_at 
             FROM users WHERE LOWER(email) = LOWER($1)`,
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        res.json({ success: true, user: result.rows[0] });
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/payments/deposit', async (req, res) => {
    try {
        const { phone, amount, email } = req.body;
        
        console.log('=== DEPOSIT REQUEST STARTED ===');
        console.log('Request body:', { phone, amount, email });
        console.log('Environment check:');
        console.log('- PAYNECTA_API_KEY exists:', !!PAYNECTA_API_KEY);
        console.log('- PAYNECTA_API_KEY length:', PAYNECTA_API_KEY ? PAYNECTA_API_KEY.length : 0);
        console.log('- PAYNECTA_EMAIL exists:', !!PAYNECTA_EMAIL);
        console.log('- PAYNECTA_EMAIL value:', PAYNECTA_EMAIL);
        console.log('- CALLBACK_BASE_URL:', CALLBACK_BASE_URL);
        
        if (!phone || !amount || !email) {
            console.log('Validation failed: missing fields');
            return res.status(400).json({ success: false, message: 'Phone, amount, and email are required' });
        }
        
        if (parseFloat(amount) < 10) {
            console.log('Validation failed: amount too low');
            return res.status(400).json({ success: false, message: 'Minimum deposit is KES 10' });
        }
        
        const userResult = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
        console.log('User lookup result:', userResult.rows.length > 0 ? 'Found' : 'Not found');
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const userId = userResult.rows[0].id;
        const formattedPhone = phone.startsWith('254') ? phone : `254${phone.replace(/^0/, '')}`;
        const reference = `DEP-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        console.log('Formatted phone:', formattedPhone);
        console.log('Reference:', reference);
        
        const transactionId = uuidv4();
        await pool.query(
            `INSERT INTO transactions (id, user_id, type, amount, fee, bonus, status, external_provider, phone, reference, created_at)
             VALUES ($1, $2, 'deposit', $3, 0, $4, 'pending', 'paynecta', $5, $6, NOW())`,
            [transactionId, userId, amount, calculateBonus(parseFloat(amount)), formattedPhone, reference]
        );
        console.log('Transaction created:', transactionId);
        
const paynectaPayload = {
    code: PAYNECTA_CODE,
    mobile_number: formattedPhone,
    amount: Math.round(parseFloat(amount))
};
        
        console.log('=== CALLING PAYNECTA API ===');
        console.log('Paynecta URL: https://paynecta.co.ke/api/v1/payment/initialize');
        console.log('Paynecta payload:', JSON.stringify(paynectaPayload));
        console.log('Headers being sent:', {
            'X-API-Key': PAYNECTA_API_KEY ? `${PAYNECTA_API_KEY.substring(0, 5)}...` : 'NOT SET',
            'X-User-Email': PAYNECTA_EMAIL || 'NOT SET'
        });
        
        const paynectaResponse = await axios.post('https://paynecta.co.ke/api/v1/payment/initialize', paynectaPayload, {
            headers: {
                'X-API-Key': PAYNECTA_API_KEY,
                'X-User-Email': PAYNECTA_EMAIL,
                'Content-Type': 'application/json'
            }
        });
        
        console.log('=== PAYNECTA RESPONSE ===');
        console.log('Status:', paynectaResponse.status);
        console.log('Response data:', JSON.stringify(paynectaResponse.data));
        
if (paynectaResponse.data && paynectaResponse.data.success) {
    const paynectaReference = paynectaResponse.data.data?.transaction_reference || null;
    
    // FIX: Store paynecta reference in metadata, NOT overwrite DEP- reference
    // This ensures frontend polling works correctly with the original reference
    await pool.query(
        'UPDATE transactions SET metadata = $1 WHERE id = $2',
        [JSON.stringify({ paynecta_reference: paynectaReference }), transactionId]
    );
    
    console.log('Stored paynecta_reference in metadata:', paynectaReference);
    console.log('Keeping original reference for polling:', reference);
    
    res.json({
                success: true,
                message: 'STK Push sent. Please enter your M-Pesa PIN.',
                reference: reference,
                transactionId: transactionId,
                bonus: calculateBonus(parseFloat(amount))
            });
        } else {
            await pool.query('UPDATE transactions SET status = $1 WHERE id = $2', ['failed', transactionId]);
            console.log('Paynecta returned failure:', paynectaResponse.data.message);
            res.status(400).json({ success: false, message: paynectaResponse.data.message || 'Payment initiation failed' });
        }
    } catch (error) {
        console.log('=== DEPOSIT ERROR ===');
        console.log('Error name:', error.name);
        console.log('Error message:', error.message);
        console.log('Error code:', error.code);
        if (error.response) {
            console.log('API Error Status:', error.response.status);
            console.log('API Error Status Text:', error.response.statusText);
            console.log('API Error Data:', JSON.stringify(error.response.data));
        } else if (error.request) {
            console.log('Request was made but no response received');
        }
        console.log('Full error stack:', error.stack);
        res.status(500).json({ success: false, message: 'Payment service error. Please try again.' });
    }
});

app.post('/api/payments/paynecta/callback', async (req, res) => {
    try {
        console.log('=== PAYNECTA CALLBACK RECEIVED ===');
        console.log('Callback body:', JSON.stringify(req.body));
        
        const { reference, status, mpesa_code, amount, transaction_reference } = req.body;
        
        // Get the reference from either field Paynecta might send
        const callbackReference = reference || transaction_reference;
        
        if (!callbackReference) {
            console.log('No reference in callback');
            return res.status(400).json({ success: false, message: 'Reference required' });
        }
        
        console.log('Looking up transaction with reference:', callbackReference);
        
        // FIX: Search by either the DEP- reference OR the paynecta reference in metadata
        let transactionResult = await pool.query(
            'SELECT id, user_id, amount, bonus, status FROM transactions WHERE reference = $1',
            [callbackReference]
        );
        
        // If not found by reference, search in metadata for paynecta_reference
        if (transactionResult.rows.length === 0) {
            console.log('Not found by reference, searching in metadata...');
            transactionResult = await pool.query(
                `SELECT id, user_id, amount, bonus, status FROM transactions 
                 WHERE metadata->>'paynecta_reference' = $1`,
                [callbackReference]
            );
        }
        
        if (transactionResult.rows.length === 0) {
            console.warn('Transaction not found for reference:', callbackReference);
            return res.status(404).json({ success: false, message: 'Transaction not found' });
        }
        
        const transaction = transactionResult.rows[0];
        console.log('Found transaction:', transaction.id, 'Current status:', transaction.status);
        
        if (transaction.status !== 'pending') {
            console.log('Transaction already processed:', callbackReference, transaction.status);
            return res.json({ success: true, message: 'Transaction already processed' });
        }
        
        // Normalize status check to handle different formats
        const normalizedStatus = (status || '').toLowerCase();
        if (normalizedStatus === 'success' || normalizedStatus === 'completed' || normalizedStatus === 'successful') {
            console.log('Payment successful, updating transaction and balance...');
            
            await pool.query(
                `UPDATE transactions SET status = 'completed', metadata = $1 WHERE id = $2`,
                [JSON.stringify({ mpesa_code, paynecta_reference: callbackReference }), transaction.id]
            );
            
            const totalAmount = parseFloat(transaction.amount);
            const bonus = parseFloat(transaction.bonus);
            
            await pool.query(
                'UPDATE users SET balance = balance + $1, bonus_balance = bonus_balance + $2 WHERE id = $3',
                [totalAmount, bonus, transaction.user_id]
            );
            
            // Add notification for successful deposit
            await pool.query(
                `INSERT INTO notifications (id, user_id, scope, title, message, is_read, created_at)
                 VALUES ($1, $2, 'user', 'Deposit Successful! 💰', $3, false, NOW())`,
                [uuidv4(), transaction.user_id, `KES ${totalAmount} has been added to your account${bonus > 0 ? ` plus KES ${bonus} bonus!` : '.'}`]
            );
            
            const pendingPurchase = await pool.query(
                `SELECT id, target_phone, amount FROM pending_purchases 
                 WHERE user_id = $1 AND status = 'awaiting_funds' 
                 ORDER BY initiated_at ASC LIMIT 1`,
                [transaction.user_id]
            );
            
            if (pendingPurchase.rows.length > 0) {
                const purchase = pendingPurchase.rows[0];
                await processPendingAirtimePurchase(purchase.id, transaction.user_id);
            }
            
            console.log(`Deposit successful for user ${transaction.user_id}: KES ${totalAmount} + ${bonus} bonus`);
        } else {
            console.log('Payment failed/cancelled, status:', status);
            await pool.query('UPDATE transactions SET status = $1 WHERE id = $2', ['failed', transaction.id]);
        }
        
        res.json({ success: true, message: 'Callback processed' });
    } catch (error) {
        console.error('Callback error:', error);
        res.status(500).json({ success: false, message: 'Callback processing error' });
    }
});

app.get('/api/payments/status/:reference', async (req, res) => {
    try {
        const { reference } = req.params;
        const result = await pool.query(
            'SELECT status, amount, bonus, created_at FROM transactions WHERE reference = $1',
            [reference]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Transaction not found' });
        }
        
        res.json({ success: true, transaction: result.rows[0] });
    } catch (error) {
        console.error('Status query error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/payments/verify-deposit', async (req, res) => {
    try {
        const { mpesa_code, email, amount } = req.body;
        
        if (!mpesa_code || !email) {
            return res.status(400).json({ success: false, message: 'M-Pesa code and email are required' });
        }
        
        const userResult = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        const userId = userResult.rows[0].id;
        
        const existingVerification = await pool.query(
            'SELECT id, status FROM deposit_verifications WHERE UPPER(mpesa_code) = UPPER($1)',
            [mpesa_code]
        );
        
        if (existingVerification.rows.length > 0) {
            const verification = existingVerification.rows[0];
            if (verification.status === 'validated') {
                return res.status(400).json({ success: false, message: 'This M-Pesa code has already been used' });
            }
            return res.json({ success: true, message: 'Verification already submitted, awaiting review' });
        }
        
        const existingTransaction = await pool.query(
            `SELECT id FROM transactions WHERE metadata->>'mpesa_code' = $1 AND status = 'completed'`,
            [mpesa_code.toUpperCase()]
        );
        
        if (existingTransaction.rows.length > 0) {
            return res.status(400).json({ success: false, message: 'This deposit has already been credited to your account' });
        }
        
        await pool.query(
            `INSERT INTO deposit_verifications (id, user_id, mpesa_code, amount_claimed, status, submitted_at)
             VALUES ($1, $2, $3, $4, 'pending', NOW())`,
            [uuidv4(), userId, mpesa_code.toUpperCase(), amount || 0]
        );
        
        res.json({ success: true, message: 'Verification submitted. Admin will review shortly.' });
    } catch (error) {
        console.error('Verify deposit error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/payments/payhero-link', async (req, res) => {
    try {
        const { phone, amount, email } = req.body;
        
        const formattedPhone = phone.startsWith('254') ? phone : `254${phone.replace(/^0/, '')}`;
        
        // Use customer_name for email so PayHero callback can identify user
        const payHeroUrl = `${PAYHERO_LINK}?phone=${formattedPhone}&amount=${amount}&customer_name=${encodeURIComponent(email)}&reference=${encodeURIComponent('#airtime deposit')}`;
        
        res.json({ success: true, paymentLink: payHeroUrl });
    } catch (error) {
        console.error('PayHero link error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// PayHero webhook endpoint for deposits via payment link
app.post('/api/payments/payhero/callback', async (req, res) => {
    try {
        console.log('=== PAYHERO CALLBACK RECEIVED ===');
        console.log('Callback body:', JSON.stringify(req.body));
        
        const { 
            status, 
            amount, 
            phone, 
            customer_name, 
            reference,
            mpesa_reference,
            checkout_request_id 
        } = req.body;
        
        // customer_name contains the email
        const email = customer_name;
        
        if (!email) {
            console.log('No email in PayHero callback');
            return res.status(400).json({ success: false, message: 'Customer email required' });
        }
        
        const normalizedStatus = (status || '').toLowerCase();
        
        if (normalizedStatus === 'success' || normalizedStatus === 'completed' || normalizedStatus === 'successful') {
            console.log('PayHero payment successful for:', email, 'Amount:', amount);
            
            // Find the user
            const userResult = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
            
            if (userResult.rows.length === 0) {
                console.log('User not found for email:', email);
                return res.status(404).json({ success: false, message: 'User not found' });
            }
            
            const userId = userResult.rows[0].id;
            const depositAmount = parseFloat(amount);
            const bonus = calculateBonus(depositAmount);
            const transactionRef = `PHERO-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            
            // Check if this payment was already processed (by mpesa_reference)
            if (mpesa_reference) {
                const existingTx = await pool.query(
                    `SELECT id FROM transactions WHERE metadata->>'mpesa_code' = $1 AND status = 'completed'`,
                    [mpesa_reference]
                );
                
                if (existingTx.rows.length > 0) {
                    console.log('PayHero payment already processed:', mpesa_reference);
                    return res.json({ success: true, message: 'Payment already processed' });
                }
            }
            
            // Create completed transaction
            await pool.query(
                `INSERT INTO transactions (id, user_id, type, amount, fee, bonus, status, external_provider, phone, reference, metadata, created_at)
                 VALUES ($1, $2, 'deposit', $3, 0, $4, 'completed', 'payhero', $5, $6, $7, NOW())`,
                [uuidv4(), userId, depositAmount, bonus, phone, transactionRef, JSON.stringify({ 
                    mpesa_code: mpesa_reference,
                    checkout_request_id,
                    original_reference: reference
                })]
            );
            
            // Update user balance immediately
            await pool.query(
                'UPDATE users SET balance = balance + $1, bonus_balance = bonus_balance + $2 WHERE id = $3',
                [depositAmount, bonus, userId]
            );
            
            console.log(`PayHero deposit successful for user ${userId}: KES ${depositAmount} + ${bonus} bonus`);
            
            // Add notification
            await pool.query(
                `INSERT INTO notifications (id, user_id, scope, title, message, is_read, created_at)
                 VALUES ($1, $2, 'user', 'Deposit Successful! 💰', $3, false, NOW())`,
                [uuidv4(), userId, `KES ${depositAmount} has been added to your account via PayHero${bonus > 0 ? ` plus KES ${bonus} bonus!` : '.'}`]
            );
        }
        
        res.json({ success: true, message: 'PayHero callback processed' });
    } catch (error) {
        console.error('PayHero callback error:', error);
        res.status(500).json({ success: false, message: 'Callback processing error' });
    }
});

app.get('/api/airtime/float-status', async (req, res) => {
    try {
        const result = await pool.query("SELECT value FROM settings WHERE key = 'float_low'");
        const isLow = result.rows.length > 0 && result.rows[0].value === 'true';
        res.json({ success: true, floatLow: isLow });
    } catch (error) {
        console.error('Float status error:', error);
        res.json({ success: true, floatLow: false });
    }
});

app.post('/api/airtime/buy', async (req, res) => {
    try {
        const { phone, amount, email } = req.body;
        
        if (!phone || !amount || !email) {
            return res.status(400).json({ success: false, message: 'Phone, amount, and email are required' });
        }
        
        if (parseFloat(amount) < 5) {
            return res.status(400).json({ success: false, message: 'Minimum airtime is KES 5' });
        }
        
        const floatResult = await pool.query("SELECT value FROM settings WHERE key = 'float_low'");
        if (floatResult.rows.length > 0 && floatResult.rows[0].value === 'true') {
            return res.status(503).json({ success: false, message: 'Airtime service temporarily unavailable. Please try again later.' });
        }
        
        const userResult = await pool.query(
            'SELECT id, balance, bonus_balance FROM users WHERE LOWER(email) = LOWER($1)',
            [email]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const user = userResult.rows[0];
        const totalBalance = parseFloat(user.balance) + parseFloat(user.bonus_balance);
        const airtimeAmount = parseFloat(amount);
        
        if (totalBalance < airtimeAmount) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance',
                balance: totalBalance,
                required: airtimeAmount,
                shortfall: airtimeAmount - totalBalance
            });
        }
        
        const formattedPhone = phone.startsWith('254') ? phone : `254${phone.replace(/^0/, '')}`;
        const reference = `AIR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        const actualAirtime = calculateAirtimeCost(airtimeAmount);
        
        let remainingAmount = airtimeAmount;
        let bonusUsed = 0;
        let balanceUsed = 0;
        
        if (parseFloat(user.bonus_balance) > 0) {
            bonusUsed = Math.min(parseFloat(user.bonus_balance), remainingAmount);
            remainingAmount -= bonusUsed;
        }
        balanceUsed = remainingAmount;
        
        const transactionId = uuidv4();
        await pool.query(
            `INSERT INTO transactions (id, user_id, type, amount, fee, bonus, status, external_provider, phone, reference, metadata, created_at)
             VALUES ($1, $2, 'airtime', $3, $4, 0, 'pending', 'statum', $5, $6, $7, NOW())`,
            [transactionId, user.id, airtimeAmount, airtimeAmount - actualAirtime, formattedPhone, reference, JSON.stringify({ actual_airtime: actualAirtime })]
        );
        
        const statumAuth = Buffer.from(`${STATUM_CONSUMER_KEY}:${STATUM_CONSUMER_SECRET}`).toString('base64');
        
        const statumResponse = await axios.post('https://api.statum.co.ke/api/v2/airtime', {
            phone_number: formattedPhone,
            amount: actualAirtime.toString()
        }, {
            headers: {
                'Authorization': `Basic ${statumAuth}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (statumResponse.data.status_code === 200) {
            await pool.query(
                'UPDATE users SET balance = balance - $1, bonus_balance = bonus_balance - $2 WHERE id = $3',
                [balanceUsed, bonusUsed, user.id]
            );
            
            await pool.query(
                `UPDATE transactions SET status = 'completed', metadata = $1 WHERE id = $2`,
                [JSON.stringify({ actual_airtime: actualAirtime, statum_request_id: statumResponse.data.request_id }), transactionId]
            );
            
            res.json({
                success: true,
                message: `Airtime sent! KES ${actualAirtime} to ${formattedPhone}`,
                airtimeSent: actualAirtime,
                reference: reference
            });
        } else {
            await pool.query('UPDATE transactions SET status = $1 WHERE id = $2', ['failed', transactionId]);
            res.status(400).json({ success: false, message: 'Airtime purchase failed. Please try again.' });
        }
    } catch (error) {
        console.error('Buy airtime error:', error.response?.data || error);
        res.status(500).json({ success: false, message: 'Airtime service error. Please try again.' });
    }
});

app.post('/api/airtime/direct', async (req, res) => {
    try {
        const { phone_to_receive, phone_to_pay, amount } = req.body;
        
        if (!phone_to_receive || !phone_to_pay || !amount) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }
        
        if (parseFloat(amount) < 5) {
            return res.status(400).json({ success: false, message: 'Minimum airtime is KES 5' });
        }
        
        const floatResult = await pool.query("SELECT value FROM settings WHERE key = 'float_low'");
        if (floatResult.rows.length > 0 && floatResult.rows[0].value === 'true') {
            return res.status(503).json({ success: false, message: 'Airtime service temporarily unavailable.' });
        }
        
        const formattedPayPhone = phone_to_pay.startsWith('254') ? phone_to_pay : `254${phone_to_pay.replace(/^0/, '')}`;
        const formattedReceivePhone = phone_to_receive.startsWith('254') ? phone_to_receive : `254${phone_to_receive.replace(/^0/, '')}`;
        const reference = `DAIR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const actualAirtime = calculateAirtimeCost(parseFloat(amount));
        
        const paynectaResponse = await axios.post('https://paynecta.co.ke/api/v1/payments/initiate', {
            phone: formattedPayPhone,
            amount: parseFloat(amount),
            reference: paynectaReference,
            callback_url: `${CALLBACK_BASE_URL}/api/payments/direct-airtime/callback`
        }, {
            headers: {
                'X-API-Key': PAYNECTA_API_KEY,
                'X-User-Email': PAYNECTA_EMAIL,
                'Content-Type': 'application/json'
            }
        });
        
        if (paynectaResponse.data.success) {
            await pool.query(
                `INSERT INTO pending_purchases (id, target_phone, amount, status, deposit_reference, initiated_at)
                 VALUES ($1, $2, $3, 'awaiting_payment', $4, NOW())`,
                [uuidv4(), formattedReceivePhone, actualAirtime, reference]
            );
            
            res.json({
                success: true,
                message: 'STK Push sent! Complete payment to receive airtime.',
                reference: reference,
                airtime_to_receive: actualAirtime
            });
        } else {
            res.status(400).json({ success: false, message: 'Payment initiation failed' });
        }
    } catch (error) {
        console.error('Direct airtime error:', error.response?.data || error);
        res.status(500).json({ success: false, message: 'Service error. Please try again.' });
    }
});

async function processPendingAirtimePurchase(purchaseId, userId) {
    try {
        const purchaseResult = await pool.query(
            'SELECT target_phone, amount FROM pending_purchases WHERE id = $1',
            [purchaseId]
        );
        
        if (purchaseResult.rows.length === 0) return;
        
        const purchase = purchaseResult.rows[0];
        const statumAuth = Buffer.from(`${STATUM_CONSUMER_KEY}:${STATUM_CONSUMER_SECRET}`).toString('base64');
        
        const statumResponse = await axios.post('https://api.statum.co.ke/api/v2/airtime', {
            phone_number: purchase.target_phone,
            amount: purchase.amount.toString()
        }, {
            headers: {
                'Authorization': `Basic ${statumAuth}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (statumResponse.data.status_code === 200) {
            await pool.query('UPDATE pending_purchases SET status = $1 WHERE id = $2', ['completed', purchaseId]);
            
            await pool.query(
                `INSERT INTO notifications (id, user_id, scope, title, message, is_read, created_at)
                 VALUES ($1, $2, 'user', 'Airtime Sent! 📱', $3, false, NOW())`,
                [uuidv4(), userId, `KES ${purchase.amount} airtime has been sent to ${purchase.target_phone}`]
            );
        } else {
            await pool.query(
                'UPDATE pending_purchases SET status = $1, retry_count = retry_count + 1 WHERE id = $2',
                ['failed', purchaseId]
            );
        }
    } catch (error) {
        console.error('Process pending purchase error:', error);
    }
}

app.get('/api/transactions/:email', async (req, res) => {
    try {
        const { email } = req.params;
        
        const userResult = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const result = await pool.query(
            `SELECT id, type, amount, fee, bonus, status, phone, reference, created_at
             FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100`,
            [userResult.rows[0].id]
        );
        
        res.json({ success: true, transactions: result.rows });
    } catch (error) {
        console.error('Get transactions error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/transactions/:email/pdf', async (req, res) => {
    try {
        const { email } = req.params;
        
        const userResult = await pool.query('SELECT id, email FROM users WHERE LOWER(email) = LOWER($1)', [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const transResult = await pool.query(
            `SELECT type, amount, status, phone, created_at
             FROM transactions WHERE user_id = $1 ORDER BY created_at DESC`,
            [userResult.rows[0].id]
        );
        
        const doc = new PDFDocument();
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=transactions-${email}.pdf`);
        
        doc.pipe(res);
        
        doc.fontSize(20).text('Airtime Solution Kenya', { align: 'center' });
        doc.fontSize(12).text('Transaction History', { align: 'center' });
        doc.moveDown();
        doc.fontSize(10).text(`Email: ${email}`);
        doc.text(`Generated: ${new Date().toLocaleString()}`);
        doc.moveDown();
        
        doc.fontSize(10);
        transResult.rows.forEach((tx, index) => {
            doc.text(`${index + 1}. ${tx.type.toUpperCase()} - KES ${tx.amount} - ${tx.status} - ${new Date(tx.created_at).toLocaleDateString()}`);
        });
        
        doc.end();
    } catch (error) {
        console.error('PDF generation error:', error);
        res.status(500).json({ success: false, message: 'PDF generation failed' });
    }
});

app.get('/api/notifications/:email', async (req, res) => {
    try {
        const { email } = req.params;
        
        const userResult = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const result = await pool.query(
            `SELECT id, title, message, is_read, created_at FROM notifications 
             WHERE user_id = $1 OR scope = 'system'
             ORDER BY created_at DESC LIMIT 50`,
            [userResult.rows[0].id]
        );
        
        res.json({ success: true, notifications: result.rows });
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.put('/api/notifications/:id/read', async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('UPDATE notifications SET is_read = true WHERE id = $1', [id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Mark notification read error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/admin/login', adminLoginLimiter, (req, res) => {
    const { password } = req.body;
    
    if (!password) {
        return res.status(400).json({ success: false, message: 'Password required' });
    }
    
    if (password === ADMIN_PASSWORD) {
        req.session.isAdmin = true;
        console.log(`Admin login from IP: ${req.ip}`);
        res.json({ success: true, message: 'Admin logged in' });
    } else {
        res.status(401).json({ success: false, message: 'Invalid password' });
    }
});

function adminAuth(req, res, next) {
    if (req.session && req.session.isAdmin) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized' });
    }
}

app.get('/api/admin/users', adminAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, email, balance, bonus_balance, is_disabled, created_at, last_login_at 
             FROM users ORDER BY created_at DESC`
        );
        res.json({ success: true, users: result.rows });
    } catch (error) {
        console.error('Admin get users error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.put('/api/admin/users/:id/toggle', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('UPDATE users SET is_disabled = NOT is_disabled WHERE id = $1', [id]);
        
        await pool.query(
            `INSERT INTO admin_audit_logs (id, admin_identifier, action, target_user, created_at)
             VALUES ($1, 'admin', 'toggle_user_status', $2, NOW())`,
            [uuidv4(), id]
        );
        
        res.json({ success: true, message: 'User status updated' });
    } catch (error) {
        console.error('Toggle user error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.put('/api/admin/users/:id/balance', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { amount, type } = req.body;
        
        if (type === 'add') {
            await pool.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [Math.abs(amount), id]);
        } else {
            await pool.query('UPDATE users SET balance = GREATEST(0, balance - $1) WHERE id = $2', [Math.abs(amount), id]);
        }
        
        await pool.query(
            `INSERT INTO transactions (id, user_id, type, amount, status, external_provider, reference, created_at)
             VALUES ($1, $2, 'adjustment', $3, 'completed', 'manual', $4, NOW())`,
            [uuidv4(), id, type === 'add' ? amount : -amount, `ADJ-${Date.now()}`]
        );
        
        await pool.query(
            `INSERT INTO admin_audit_logs (id, admin_identifier, action, target_user, metadata, created_at)
             VALUES ($1, 'admin', 'balance_adjustment', $2, $3, NOW())`,
            [uuidv4(), id, JSON.stringify({ amount, type })]
        );
        
        res.json({ success: true, message: 'Balance updated' });
    } catch (error) {
        console.error('Adjust balance error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/admin/transactions', adminAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT t.id, t.type, t.amount, t.fee, t.status, t.phone, t.reference, t.created_at, u.email
             FROM transactions t 
             LEFT JOIN users u ON t.user_id = u.id 
             ORDER BY t.created_at DESC LIMIT 500`
        );
        res.json({ success: true, transactions: result.rows });
    } catch (error) {
        console.error('Admin get transactions error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/admin/verifications', adminAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT dv.id, dv.mpesa_code, dv.amount_claimed, dv.status, dv.submitted_at, u.email
             FROM deposit_verifications dv
             LEFT JOIN users u ON dv.user_id = u.id
             ORDER BY dv.submitted_at DESC`
        );
        res.json({ success: true, verifications: result.rows });
    } catch (error) {
        console.error('Admin get verifications error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.put('/api/admin/verifications/:id', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, amount } = req.body;
        
        const verificationResult = await pool.query(
            'SELECT user_id, amount_claimed FROM deposit_verifications WHERE id = $1',
            [id]
        );
        
        if (verificationResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Verification not found' });
        }
        
        const verification = verificationResult.rows[0];
        
        await pool.query(
            'UPDATE deposit_verifications SET status = $1, reviewed_by = $2 WHERE id = $3',
            [status, 'admin', id]
        );
        
        if (status === 'validated' && amount > 0) {
            await pool.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [amount, verification.user_id]);
            
            await pool.query(
                `INSERT INTO transactions (id, user_id, type, amount, status, external_provider, reference, created_at)
                 VALUES ($1, $2, 'deposit', $3, 'completed', 'manual', $4, NOW())`,
                [uuidv4(), verification.user_id, amount, `VERIFY-${Date.now()}`]
            );
        }
        
        res.json({ success: true, message: 'Verification processed' });
    } catch (error) {
        console.error('Process verification error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.put('/api/admin/float-status', adminAuth, async (req, res) => {
    try {
        const { isLow } = req.body;
        
        await pool.query(
            `INSERT INTO settings (key, value) VALUES ('float_low', $1)
             ON CONFLICT (key) DO UPDATE SET value = $1`,
            [isLow.toString()]
        );
        
        res.json({ success: true, message: 'Float status updated' });
    } catch (error) {
        console.error('Set float status error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/admin/notifications', adminAuth, async (req, res) => {
    try {
        const { title, message, userId } = req.body;
        
        await pool.query(
            `INSERT INTO notifications (id, user_id, scope, title, message, is_read, created_at)
             VALUES ($1, $2, $3, $4, $5, false, NOW())`,
            [uuidv4(), userId || null, userId ? 'user' : 'system', title, message]
        );
        
        res.json({ success: true, message: 'Notification sent' });
    } catch (error) {
        console.error('Send notification error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const users = await pool.query('SELECT COUNT(*) FROM users');
        const totalDeposits = await pool.query("SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE type = 'deposit' AND status = 'completed'");
        const totalAirtime = await pool.query("SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE type = 'airtime' AND status = 'completed'");
        const pendingVerifications = await pool.query("SELECT COUNT(*) FROM deposit_verifications WHERE status = 'pending'");
        
        res.json({
            success: true,
            stats: {
                totalUsers: parseInt(users.rows[0].count),
                totalDeposits: parseFloat(totalDeposits.rows[0].total),
                totalAirtime: parseFloat(totalAirtime.rows[0].total),
                pendingVerifications: parseInt(pendingVerifications.rows[0].count)
            }
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/admin/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true, message: 'Logged out' });
});

app.post('/api/airtime-to-cash/initiate', async (req, res) => {
    res.status(503).json({ 
        success: false, 
        message: 'Airtime to Cash feature coming soon!',
        comingSoon: true
    });
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
    res.json({ 
        message: 'Airtime Solution Kenya API', 
        status: 'running',
        frontend: process.env.FRONTEND_ORIGIN || 'https://airtimesolutionfrontend.onrender.com'
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Frontend origin: ${process.env.FRONTEND_ORIGIN || 'https://airtimesolutionfrontend.onrender.com'}`);
    console.log(`Callback URL: ${CALLBACK_BASE_URL}`);
});

process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    pool.end(() => {
        console.log('Database pool closed');
        process.exit(0);
    });
});

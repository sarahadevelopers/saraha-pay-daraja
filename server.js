require('dotenv').config();

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', 1);

/* -------------------------------
   0. Security headers
-------------------------------- */
try {
    const helmet = require('helmet');
    app.use(helmet({ contentSecurityPolicy: false }));
    console.log('📍 Security headers: ENABLED (helmet)');
} catch (e) {
    console.log('📍 Security headers: DISABLED (run: npm install helmet)');
}

/* -------------------------------
   1. MongoDB Connection
-------------------------------- */
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => console.error("❌ MongoDB Error:", err));

/* -------------------------------
   2. Transaction Schema
-------------------------------- */
const transactionSchema = new mongoose.Schema({
    name: String,
    phone: String,            // Payer's number
    recipient_phone: String,  // Recipient's number (for gifting)
    amount: String,
    bundle_sku: String,
    source: String,
    status: { type: String, default: "PENDING" },
    checkout_id: String,
    merchant_request_id: String,
    mpesa_receipt: String,
    result_code: Number,
    result_desc: String,
    retryCount: { type: Number, default: 0 },
    lastRetryAt: { type: Date, default: null },

    // ── Delivery worker fields ──
    delivered:         { type: Boolean, default: false },
    delivery_status:   { type: String, default: null },
    delivery_attempts: { type: Number, default: 0 },
    delivered_at:      { type: Date, default: null },
    delivery_error:    { type: String, default: null },

    createdAt: { type: Date, default: Date.now }
});

transactionSchema.index({ createdAt: -1 });
transactionSchema.index({ phone: 1, createdAt: -1 });
transactionSchema.index({ status: 1, createdAt: -1 });
transactionSchema.index({ checkout_id: 1 });
transactionSchema.index({ merchant_request_id: 1 });
transactionSchema.index({ delivery_status: 1, delivered: 1, createdAt: 1 });

const Transaction = mongoose.model("Transaction", transactionSchema);

/* -------------------------------
   3. CORS + BODY PARSING
-------------------------------- */
const allowedOrigins = [
    'https://bingwasoko.co.ke',
    'https://www.bingwasoko.co.ke',
    'https://datasokoni.com',
    'https://www.datasokoni.com',
    'https://fineescorts.co.ke',
    'https://www.fineescorts.co.ke',
    'https://sarahadevelopers.github.io',
    'http://localhost:3000',
    'http://localhost:5505',
    'http://127.0.0.1:5505',
    'https://fine-2zxp.onrender.com',
    'https://rentspace.co.ke',
    'https://www.rentspace.co.ke',
    'https://saraha-pay-daraja.onrender.com'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
        callback(new Error('Not allowed by CORS'));
    },
    credentials: true
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

/* -------------------------------
   3b. Basic Auth for Admin
-------------------------------- */
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS;

const adminAuth = (req, res, next) => {
    if (!ADMIN_PASS) {
        console.warn('⚠️  ADMIN_PASS not set — admin routes are UNPROTECTED');
        return next();
    }
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Basic ')) {
        res.set('WWW-Authenticate', 'Basic realm="Sarahapay Admin"');
        return res.status(401).send('Authentication required');
    }
    const [user, pass] = Buffer.from(auth.slice(6), 'base64').toString().split(':');
    if (user === ADMIN_USER && pass === ADMIN_PASS) return next();
    res.set('WWW-Authenticate', 'Basic realm="Sarahapay Admin"');
    return res.status(401).send('Invalid credentials');
};

app.use('/admin.html', adminAuth);
app.use('/api/transactions', adminAuth);
app.use('/api/transaction', adminAuth);
app.use(express.static(path.join(__dirname, 'docs')));

/* -------------------------------
   4. Shared Secret Check
-------------------------------- */
const VALID_SECRETS = [
    process.env.API_SECRET,
    process.env.API_SECRET_BINGWA,
    process.env.API_SECRET_FINEESCORTS,
].filter(Boolean);

const checkSecret = (req, res, next) => {
    const origin = req.headers.origin || '';
    if (origin && allowedOrigins.includes(origin)) return next();

    const secret = req.headers['x-api-secret'];
    if (!secret) {
        console.warn(`❌ Missing API secret (origin: ${origin || '(none)'})`);
        return res.status(403).json({ error: "Missing API secret" });
    }
    if (!VALID_SECRETS.includes(secret)) {
        console.warn(`❌ Invalid API secret: ${secret.substring(0, 10)}...`);
        return res.status(403).json({ error: "Unauthorized" });
    }
    next();
};

/* -------------------------------
   5. reCAPTCHA Verification
-------------------------------- */
const verifyRecaptcha = async (req, res, next) => {
    if (process.env.RECAPTCHA_DISABLED === 'true') {
        return next();
    }

    const token = req.headers['x-recaptcha-token'] || req.body.recaptchaToken;
    if (!token) {
        return res.status(403).json({ error: "reCAPTCHA verification required" });
    }

    try {
        const verification = await axios.post(
            'https://www.google.com/recaptcha/api/siteverify',
            null,
            {
                params: {
                    secret: process.env.RECAPTCHA_SECRET,
                    response: token
                },
                timeout: 5000
            }
        );

        const { success, score } = verification.data;
        const errorCodes = verification.data['error-codes'] || [];

        if (errorCodes.length > 0) {
            if (errorCodes.includes('invalid-input-secret')) {
                console.error('❌ reCAPTCHA secret is INVALID');
                return res.status(500).json({ error: "Server misconfiguration" });
            }
            return next(); // Allow through on config error
        }

        if (!success || (typeof score === 'number' && score < 0.5)) {
            return res.status(403).json({ error: "Bot detected. Please try again." });
        }

        next();
    } catch (error) {
        console.error("reCAPTCHA network error (allowing through):", error.message);
        next();
    }
};

/* -------------------------------
   6. Global Rate Limit
-------------------------------- */
let globalRequestCount = 0;
let globalWindowStart = Date.now();
const GLOBAL_MAX = 500;
const GLOBAL_WINDOW = 60 * 1000;

const globalRateLimit = (req, res, next) => {
    const now = Date.now();
    if (now - globalWindowStart > GLOBAL_WINDOW) {
        globalRequestCount = 0;
        globalWindowStart = now;
    }
    globalRequestCount++;
    if (globalRequestCount > GLOBAL_MAX) {
        console.warn(`⚠️  GLOBAL RATE LIMIT TRIPPED`);
        return res.status(429).json({ error: "Service temporarily busy. Please try again shortly." });
    }
    next();
};

/* -------------------------------
   6b. getClientIp helper
-------------------------------- */
function getClientIp(req) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) {
        const first = xff.split(',')[0].trim();
        if (first) return first;
    }
    const cf = req.headers['cf-connecting-ip'];
    if (cf) return cf.trim();
    const realIp = req.headers['x-real-ip'];
    if (realIp) return realIp.trim();
    return req.ip || '';
}

/* -------------------------------
   6c. Per-phone rate limiter
-------------------------------- */
const phoneAttempts = new Map();
const PHONE_WINDOW_MS = 60 * 1000;
const PHONE_MAX = 1;

const phoneLimiter = (req, res, next) => {
    const rawPhone = req.body?.phone;
    if (!rawPhone || typeof rawPhone !== 'string') return next();

    const phone = rawPhone.replace(/\s+/g, '').replace(/^\+/, '').replace(/^0/, '254');
    if (!/^254\d{9}$/.test(phone)) return next();

    const now = Date.now();
    const attempts = (phoneAttempts.get(phone) || []).filter(t => now - t < PHONE_WINDOW_MS);

    if (attempts.length >= PHONE_MAX) {
        const oldest = attempts[0];
        const waitSec = Math.ceil((PHONE_WINDOW_MS - (now - oldest)) / 1000);
        console.warn(`🚫 Phone rate limit: ${phone} (wait ${waitSec}s)`);
        return res.status(429).json({
            error: `A payment was already requested for this number. Please wait ${waitSec} seconds.`
        });
    }

    attempts.push(now);
    phoneAttempts.set(phone, attempts);
    next();
};

// Cleanup every 5 minutes
setInterval(() => {
    const now = Date.now();
    for (const [phone, attempts] of phoneAttempts.entries()) {
        const fresh = attempts.filter(t => now - t < PHONE_WINDOW_MS);
        if (fresh.length === 0) phoneAttempts.delete(phone);
        else phoneAttempts.set(phone, fresh);
    }
}, 5 * 60 * 1000);

/* -------------------------------
   6d. Middleware stack
-------------------------------- */
app.use('/api/pay', checkSecret);
app.use('/api/retry-payment', checkSecret);
app.use('/api/query-stk', checkSecret);

app.use('/api/pay', verifyRecaptcha);
app.use('/api/retry-payment', verifyRecaptcha);

app.use('/api/pay', globalRateLimit);
app.use('/api/retry-payment', globalRateLimit);
app.use('/api/query-stk', globalRateLimit);

app.use('/api/pay', phoneLimiter);
app.use('/api/retry-payment', phoneLimiter);

/* -------------------------------
   7. IP Blocking (CGNAT-safe limits)
-------------------------------- */
const violationStore = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of violationStore.entries()) {
        if (data.blockUntil && data.blockUntil < now) {
            violationStore.delete(ip);
        } else if (!data.blockUntil && (now - data.firstViolationTime) > 3600000) {
            violationStore.delete(ip);
        }
    }
}, 60000);

const checkBlocked = (req, res, next) => {
    const ip = getClientIp(req);
    const now = Date.now();
    const data = violationStore.get(ip);
    if (data && data.blockUntil && data.blockUntil > now) {
        return res.status(403).json({
            error: `Your IP is temporarily blocked due to excessive failed attempts. Try again after ${Math.ceil((data.blockUntil - now) / 60000)} minutes.`
        });
    }
    next();
};

const paymentLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 20,
    keyGenerator: (req) => getClientIp(req) || 'unknown',
    message: { error: "Too many payment requests from this IP. Please wait 5 minutes." },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        const ip = getClientIp(req);
        const now = Date.now();
        const data = violationStore.get(ip) || { count: 0, firstViolationTime: now, blockUntil: null };
        data.count += 1;
        if (data.count >= 10) {
            data.blockUntil = now + 900000;
            violationStore.set(ip, data);
            res.status(429).json({
                error: "Too many failed payment attempts. Your IP has been blocked for 15 minutes."
            });
        } else {
            violationStore.set(ip, data);
            res.status(429).json({
                error: "Too many payment requests from this IP. Please wait 5 minutes."
            });
        }
    }
});

app.use('/api/pay', checkBlocked, paymentLimiter);
app.use('/api/retry-payment', checkBlocked, paymentLimiter);

/* -------------------------------
   8. Root Route
-------------------------------- */
app.get("/", (req, res) => {
    res.send("sarahapay API Running – Daraja Express");
});

/* -------------------------------
   8b. Callback IP Whitelist
-------------------------------- */
const SAFARICOM_IPS = (process.env.SAFARICOM_CALLBACK_IPS || '')
    .split(',').map(s => s.trim()).filter(Boolean);

const callbackIpCheck = (req, res, next) => {
    const realIp = getClientIp(req);
    if (SAFARICOM_IPS.length === 0) return next();
    if (SAFARICOM_IPS.some(prefix => realIp.startsWith(prefix))) return next();
    console.warn(`🚫 Blocked callback from non-Safarcom IP: ${realIp}`);
    return res.status(403).send('Forbidden');
};

/* -------------------------------
   9. Daraja Configuration
-------------------------------- */
const DARAJA_ENV = process.env.DARAJA_ENVIRONMENT || 'production';
const DARAJA_BASE_URL = DARAJA_ENV === 'sandbox'
    ? 'https://sandbox.safaricom.co.ke'
    : 'https://api.safaricom.co.ke';

/* -------------------------------
   10. Helper: Initiate STK Push
-------------------------------- */
async function initiateStkPush(name, phone, amount, retryCount = 0, bundleSku = null, source = null, recipient = null) {
    let formattedPhone = phone.replace(/\s+/g, '').replace(/^\+/, '').replace(/^0/, '254');
    if (!formattedPhone.startsWith('254')) formattedPhone = '254' + formattedPhone;

    let formattedRecipient = recipient ? String(recipient).replace(/\s+/g, '').replace(/^\+/, '').replace(/^0/, '254') : formattedPhone;
    if (!formattedRecipient.startsWith('254')) formattedRecipient = '254' + formattedRecipient;

    const auth = Buffer.from(
        `${process.env.DARAJA_CONSUMER_KEY}:${process.env.DARAJA_CONSUMER_SECRET}`
    ).toString('base64');

    let accessToken;
    try {
        const tokenRes = await axios.get(
            `${DARAJA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials`,
            { headers: { Authorization: `Basic ${auth}` } }
        );
        accessToken = tokenRes.data.access_token;
    } catch (err) {
        throw new Error('Could not authenticate with Safaricom.');
    }

    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
    const password = Buffer.from(
        `${process.env.DARAJA_SHORTCODE}${process.env.DARAJA_PASSKEY}${timestamp}`
    ).toString('base64');

    const accountRef = `PAY-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;

    const stkPayload = {
        BusinessShortCode: process.env.DARAJA_SHORTCODE,
        Password: password,
        Timestamp: timestamp,
        TransactionType: "CustomerBuyGoodsOnline",
        Amount: Math.round(parseFloat(amount)),
        PartyA: formattedPhone,
        PartyB: process.env.DARAJA_TILL_NUMBER,
        PhoneNumber: formattedPhone,
        CallBackURL: process.env.DARAJA_CALLBACK_URL,
        AccountReference: accountRef,
        TransactionDesc: `Bundle for ${formattedRecipient}`
    };

    let response;
    try {
        const stkRes = await axios.post(
            `${DARAJA_BASE_URL}/mpesa/stkpush/v1/processrequest`,
            stkPayload,
            { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' } }
        );
        response = stkRes.data;
    } catch (err) {
        const errorMsg = err.response?.data?.errorMessage || err.response?.data?.ResponseDescription || 'Daraja STK push failed';
        throw new Error(errorMsg);
    }

    if (response.ResponseCode !== '0') {
        throw new Error(response.ResponseDescription || 'Daraja STK push failed');
    }

    const tx = new Transaction({
        name: name || 'Daraja Payment',
        phone: formattedPhone,
        recipient_phone: formattedRecipient, // <-- SAVES THE FRIEND'S NUMBER
        amount: parseFloat(amount).toFixed(2),
        bundle_sku: bundleSku || undefined,
        source: source || undefined,
        checkout_id: response.CheckoutRequestID,
        merchant_request_id: response.MerchantRequestID,
        retryCount: retryCount,
        lastRetryAt: new Date()
    });
    await tx.save();
    return tx;
}

/* -------------------------------
   10b. Input Validation
-------------------------------- */
function validatePaymentInput(body) {
    const { name, phone, amount } = body || {};

    if (typeof name !== 'string' || name.trim().length === 0 || name.length > 100) {
        return { ok: false, error: 'Invalid name' };
    }
    if (typeof phone !== 'string') {
        return { ok: false, error: 'Phone must be a string' };
    }
    const cleanPhone = phone.replace(/\s+/g, '').replace(/^\+/, '').replace(/^0/, '254');
    if (!/^254\d{9}$/.test(cleanPhone)) {
        return { ok: false, error: 'Invalid phone number (expected 254XXXXXXXXX)' };
    }
    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0 || amt > 100000) {
        return { ok: false, error: 'Invalid amount (must be 1–100,000)' };
    }
    return { ok: true, cleanPhone, amt };
}

/* -------------------------------
   11. Initiate Payment (/api/pay)
-------------------------------- */
app.post("/api/pay", async (req, res) => {
    try {
        const v = validatePaymentInput(req.body);
        if (!v.ok) return res.status(400).json({ error: v.error });

        const { name, bundle_sku, source, recipient } = req.body; // Extracts recipient from frontend

        const lastTx = await Transaction.findOne({ phone: v.cleanPhone }).sort({ createdAt: -1 });

        if (lastTx && lastTx.status === "PENDING") {
            const secondsSince = (Date.now() - new Date(lastTx.createdAt).getTime()) / 1000;
            if (secondsSince > 30) {
                await Transaction.updateOne({ _id: lastTx._id }, { status: "FAILED" });
            } else {
                return res.status(409).json({ error: "You already have a pending payment. Please wait." });
            }
        }

        const tx = await initiateStkPush(
            name,
            v.cleanPhone,
            String(v.amt),
            lastTx?.retryCount || 0,
            bundle_sku,
            source,
            recipient // <-- PASSES RECIPIENT TO DB
        );

        res.status(201).json({
            message: "STK Push Sent",
            transactionId: tx._id
        });

    } catch (error) {
        res.status(500).json({ error: "Failed to initiate payment", details: error.message });
    }
});

/* -------------------------------
   12. Retry Payment Endpoint
-------------------------------- */
app.post("/api/retry-payment", async (req, res) => {
    try {
        const { phone } = req.body;
        if (!phone) return res.status(400).json({ error: "Phone number required" });

        const cleanPhone = phone.replace(/\s+/g, '').replace(/^\+/, '').replace(/^0/, '254');

        const lastTx = await Transaction.findOne({
            phone: cleanPhone,
            status: { $in: ["PENDING", "FAILED", "CANCELLED"] }
        }).sort({ createdAt: -1 });

        if (!lastTx) return res.status(404).json({ error: "No failed transaction found to retry" });

        const newTx = await initiateStkPush(
            lastTx.name,
            cleanPhone,
            lastTx.amount,
            (lastTx.retryCount || 0) + 1,
            lastTx.bundle_sku,
            lastTx.source,
            lastTx.recipient_phone // <-- KEEPS THE RECIPIENT ON RETRY
        );

        res.status(201).json({ message: "Retry initiated", transactionId: newTx._id });
    } catch (error) {
        res.status(500).json({ error: "Failed to retry payment" });
    }
});

/* -------------------------------
   13. Query STK & Transactions (Admin)
-------------------------------- */
app.post("/api/query-stk", async (req, res) => { /* unchanged */ });
app.get("/api/transactions", async (req, res) => { /* unchanged */ });
app.get("/api/transaction/:id", async (req, res) => { /* unchanged */ });

/* -------------------------------
   14. Daraja Payment Callback
-------------------------------- */
app.post("/callback", callbackIpCheck, async (req, res) => {
    const cb = req.body?.Body?.stkCallback;
    res.sendStatus(200);

    (async () => {
        try {
            if (!cb) return;

            const checkoutId = cb.CheckoutRequestID;
            const items = cb.CallbackMetadata?.Item || [];
            const getItem = (name) => items.find(i => i.Name === name)?.Value;

            const status = Number(cb.ResultCode) === 0 ? 'SUCCESS' : 'FAILED';

            let transaction = await Transaction.findOne({ checkout_id: checkoutId });
            if (!transaction) return;

            transaction.status = status;
            transaction.result_code = cb.ResultCode;
            transaction.result_desc = cb.ResultDesc;
            
            if (status === 'SUCCESS') {
                transaction.mpesa_receipt = getItem('MpesaReceiptNumber');
                transaction.delivery_status = 'PENDING';
                await transaction.save();
                
                console.log(`\n✅ SUCCESS! Payment received for ${transaction.recipient_phone}`);
                console.log(`📦 Delivery queued for ${transaction._id}\n`);
            } else {
                await transaction.save();
                console.log(`❌ Payment failed [${checkoutId}]: ${cb.ResultDesc}`);
            }
        } catch (err) {
            console.error("Callback error:", err);
        }
    })();
});

/* -------------------------------
   15. Delivery worker endpoints
-------------------------------- */
const requireDeliverySecret = (req, res, next) => {
    const secret = req.headers['x-api-secret'];
    if (!secret || secret !== process.env.API_SECRET) {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    next();
};

app.get('/api/delivery/pending', requireDeliverySecret, async (req, res) => {
    try {
        const tx = await Transaction.findOne({
            status: 'SUCCESS',
            delivered: false,
            delivery_status: 'PENDING',
            delivery_attempts: { $lt: 3 }
        }).sort({ createdAt: 1 }).lean();

        if (!tx) return res.status(204).send();

        res.json({
            orderId: tx._id.toString(),
            phone: tx.recipient_phone || tx.phone, // <-- RETURNS RECIPIENT NUMBER
            bundleSku: tx.bundle_sku,
            amount: tx.amount,
            attempt: (tx.delivery_attempts || 0) + 1
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/delivery/complete', requireDeliverySecret, async (req, res) => {
    try {
        const { orderId, status, error } = req.body || {};
        if (!orderId || !['DELIVERED', 'FAILED'].includes(status)) {
            return res.status(400).json({ error: 'orderId and status=DELIVERED|FAILED required' });
        }

        const tx = await Transaction.findById(orderId);
        if (!tx) return res.status(404).json({ error: 'Order not found' });

        if (status === 'DELIVERED') {
            tx.delivered = true;
            tx.delivery_status = 'DELIVERED';
            tx.delivered_at = new Date();
            tx.delivery_error = null;
        } else {
            tx.delivery_attempts = (tx.delivery_attempts || 0) + 1;
            if (tx.delivery_attempts >= 3) {
                tx.delivery_status = 'FAILED';
                tx.delivery_error = error || 'Max attempts reached';
            } else {
                tx.delivery_status = 'PENDING';
                tx.delivery_error = error || 'Retry pending';
            }
        }
        await tx.save();
        res.json({ ok: true, delivery_status: tx.delivery_status });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* -------------------------------
   16. Start Server
-------------------------------- */
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌍 Environment: ${DARAJA_ENV}`);
});
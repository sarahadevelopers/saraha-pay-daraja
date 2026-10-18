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
   0. Security headers (optional helmet)
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
    phone: String,
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
    createdAt: { type: Date, default: Date.now }
});

transactionSchema.index({ createdAt: -1 });
transactionSchema.index({ phone: 1, createdAt: -1 });
transactionSchema.index({ status: 1, createdAt: -1 });
transactionSchema.index({ checkout_id: 1 });
transactionSchema.index({ merchant_request_id: 1 });

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
   3b. Basic Auth for Admin (BEFORE static — see below)
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

// Admin auth MUST run before express.static — otherwise the file
// at docs/admin.html gets served directly, bypassing auth entirely.
app.use('/admin.html', adminAuth);
app.use('/api/transactions', adminAuth);
app.use('/api/transaction', adminAuth);

// Static files last so admin.html can't be reached without auth above.
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
    const secret = req.headers['x-api-secret'];

    if (!secret) {
        const origin = req.headers.origin || req.headers.referer || '(none)';
        console.warn(`❌ Missing API secret header (origin: ${origin})`);
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
        console.warn('⚠️  reCAPTCHA disabled via RECAPTCHA_DISABLED=true');
        return next();
    }

    const token = req.headers['x-recaptcha-token'] || req.body.recaptchaToken;

    // Reject when token is missing — no silent fallback
    if (!token) {
        console.warn('❌ Missing reCAPTCHA token — rejecting request');
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

        console.log('reCAPTCHA full response:', JSON.stringify(verification.data));

        const { success, score } = verification.data;
        const errorCodes = verification.data['error-codes'] || [];

        // Google config errors (bad secret) are OUR problem, not the user's
        if (errorCodes.length > 0) {
            if (errorCodes.includes('invalid-input-secret')) {
                console.error('❌ reCAPTCHA secret is INVALID — check RECAPTCHA_SECRET env var');
                return res.status(500).json({ error: "Server misconfiguration" });
            }
            console.warn(`⚠️  reCAPTCHA config error (allowing through): ${errorCodes.join(', ')}`);
            return next();
        }

        if (!success) {
            console.log(`🚫 reCAPTCHA failed: success=false, score=${score}`);
            return res.status(403).json({ error: "Bot detected. Please try again." });
        }

        if (typeof score === 'number' && score < 0.5) {
            console.log(`🚫 reCAPTCHA low score: ${score}`);
            return res.status(403).json({ error: "Bot detected. Please try again." });
        }

        console.log(`✅ reCAPTCHA passed (score: ${score})`);
        next();
    } catch (error) {
        // Network error — allow through so Google outages don't kill payments
        console.error("reCAPTCHA network error (allowing through):", error.message);
        next();
    }
};

/* -------------------------------
   6. Global Rate Limit
-------------------------------- */
let globalRequestCount = 0;
let globalWindowStart = Date.now();
const GLOBAL_MAX = 50;
const GLOBAL_WINDOW = 60 * 1000;

const globalRateLimit = (req, res, next) => {
    const now = Date.now();
    if (now - globalWindowStart > GLOBAL_WINDOW) {
        globalRequestCount = 0;
        globalWindowStart = now;
    }
    globalRequestCount++;
    if (globalRequestCount > GLOBAL_MAX) {
        return res.status(429).json({ error: "Global request limit reached. Please try again later." });
    }
    next();
};

/* -------------------------------
   6b. getClientIp helper (moved up — used by IP blocking and callback check)
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
   6c. Middleware stack — now covers /api/query-stk too
-------------------------------- */
app.use('/api/pay', checkSecret);
app.use('/api/retry-payment', checkSecret);
app.use('/api/query-stk', checkSecret);

app.use('/api/pay', verifyRecaptcha);
app.use('/api/retry-payment', verifyRecaptcha);
// NOTE: /api/query-stk doesn't get reCAPTCHA — internal tool, protected by secret + rate limit

app.use('/api/pay', globalRateLimit);
app.use('/api/retry-payment', globalRateLimit);
app.use('/api/query-stk', globalRateLimit);

/* -------------------------------
   7. IP Blocking (now uses real client IP)
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
    max: 3,
    keyGenerator: (req) => getClientIp(req) || 'unknown',
    message: { error: "Too many payment requests from this IP. Please wait 5 minutes." },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        const ip = getClientIp(req);
        const now = Date.now();
        const data = violationStore.get(ip) || { count: 0, firstViolationTime: now, blockUntil: null };
        data.count += 1;
        if (data.count >= 3) {
            data.blockUntil = now + 3600000;
            violationStore.set(ip, data);
            res.status(429).json({
                error: "Too many failed payment attempts. Your IP has been blocked for 1 hour."
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
    const proxyIp = req.ip || '';
    const xff = req.headers['x-forwarded-for'] || '(none)';

    console.log(`🔍 Callback IP check → real=${realIp} | proxy=${proxyIp} | xff=${xff}`);

    if (SAFARICOM_IPS.length === 0) {
        console.warn(`⚠️  IP whitelist DISABLED — allowing callback from ${realIp}`);
        return next();
    }
    if (SAFARICOM_IPS.some(prefix => realIp.startsWith(prefix))) {
        return next();
    }
    console.warn(`🚫 Blocked callback from non-Safaricom IP: ${realIp} (xff=${xff})`);
    return res.status(403).send('Forbidden');
};

/* -------------------------------
   9. Daraja Configuration
-------------------------------- */
const DARAJA_ENV = process.env.DARAJA_ENVIRONMENT || 'production';
const DARAJA_BASE_URL = DARAJA_ENV === 'sandbox'
    ? 'https://sandbox.safaricom.co.ke'
    : 'https://api.safaricom.co.ke';

console.log(`📍 Daraja Environment: ${DARAJA_ENV}`);
console.log(`📍 Daraja Base URL: ${DARAJA_BASE_URL}`);
console.log(`📍 Daraja Shortcode: ${process.env.DARAJA_SHORTCODE}`);
console.log(`📍 Daraja Till: ${process.env.DARAJA_TILL_NUMBER}`);
console.log(`📍 Daraja Callback: ${process.env.DARAJA_CALLBACK_URL}`);
console.log(`📍 Forward Webhooks: ${process.env.FORWARD_WEBHOOK_URLS || '(none configured)'}`);
console.log(`📍 Admin Auth: ${ADMIN_PASS ? 'ENABLED' : 'DISABLED (set ADMIN_PASS!)'}`);
console.log(`📍 Callback IP Whitelist: ${SAFARICOM_IPS.length ? SAFARICOM_IPS.join(',') : 'DISABLED (set SAFARICOM_CALLBACK_IPS)'}`);
console.log(`📍 reCAPTCHA: ${process.env.RECAPTCHA_DISABLED === 'true' ? 'DISABLED' : 'ENABLED'}`);

/* -------------------------------
   10. Helper: Initiate STK Push
-------------------------------- */
async function initiateStkPush(name, phone, amount, retryCount = 0, bundleSku = null, source = null) {
    let formattedPhone = phone
        .replace(/\s+/g, '')
        .replace(/^\+/, '')
        .replace(/^0/, '254');
    if (!formattedPhone.startsWith('254')) {
        formattedPhone = '254' + formattedPhone;
    }

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
        console.error('❌ Failed to get Daraja access token:', err.response?.data || err.message);
        throw new Error('Could not authenticate with Safaricom. Check your Consumer Key and Secret.');
    }

    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
    const password = Buffer.from(
        `${process.env.DARAJA_SHORTCODE}${process.env.DARAJA_PASSKEY}${timestamp}`
    ).toString('base64');

    const accountRef = `PAY-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;

    console.log("📤 Daraja STK Request:", {
        phone: formattedPhone,
        amount: Math.round(parseFloat(amount)),
        accountRef,
        callbackUrl: process.env.DARAJA_CALLBACK_URL,
        bundleSku,
        source
    });

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
        TransactionDesc: (name || 'Sarahapay').substring(0, 13)
    };

    let response;
    try {
        const stkRes = await axios.post(
            `${DARAJA_BASE_URL}/mpesa/stkpush/v1/processrequest`,
            stkPayload,
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );
        response = stkRes.data;
        console.log("📥 Daraja Response:", response);
    } catch (err) {
        console.error('❌ Daraja STK Push failed:', err.response?.data || err.message);
        const errorMsg = err.response?.data?.errorMessage || err.response?.data?.ResponseDescription || 'Daraja STK push failed';
        throw new Error(errorMsg);
    }

    if (response.ResponseCode !== '0') {
        const errorMsg = response.ResponseDescription || 'Daraja STK push failed';
        throw new Error(errorMsg);
    }

    const checkoutId = response.CheckoutRequestID;
    const merchantRequestId = response.MerchantRequestID;

    const tx = new Transaction({
        name: name || 'Daraja Payment',
        phone: formattedPhone,
        amount: parseFloat(amount).toFixed(2),
        bundle_sku: bundleSku || undefined,
        source: source || undefined,
        checkout_id: checkoutId,
        merchant_request_id: merchantRequestId,
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
   11. Initiate Payment
-------------------------------- */
app.post("/api/pay", async (req, res) => {
    try {
        const v = validatePaymentInput(req.body);
        if (!v.ok) return res.status(400).json({ error: v.error });

        const { name, bundle_sku, source } = req.body;

        const lastTx = await Transaction.findOne({ phone: v.cleanPhone })
            .sort({ createdAt: -1 });

        if (lastTx && lastTx.status === "PENDING") {
            const secondsSince = (Date.now() - new Date(lastTx.createdAt).getTime()) / 1000;
            if (secondsSince > 30) {
                await Transaction.updateOne({ _id: lastTx._id }, { status: "FAILED" });
                console.log(`Auto-cleaned stale pending transaction ${lastTx._id} after 30s`);
            } else {
                return res.status(409).json({
                    error: "You already have a pending payment. Please wait or check your phone."
                });
            }
        }

        if (lastTx && (lastTx.status === "FAILED" || lastTx.status === "CANCELLED")) {
            const retryCount = lastTx.retryCount || 0;
            const secondsSinceLast = (Date.now() - new Date(lastTx.lastRetryAt || lastTx.createdAt).getTime()) / 1000;

            if (retryCount >= 5) {
                if (secondsSinceLast < 30) {
                    return res.status(429).json({
                        error: `Too many failed attempts (${retryCount}). Please wait ${Math.ceil(30 - secondsSinceLast)} seconds before trying again.`
                    });
                } else {
                    await Transaction.updateOne({ _id: lastTx._id }, { retryCount: 0 });
                }
            }
        }

        const tx = await initiateStkPush(
            name,
            v.cleanPhone,
            String(v.amt),
            lastTx?.retryCount || 0,
            bundle_sku,
            source
        );

        res.status(201).json({
            message: "STK Push Sent",
            transactionId: tx._id
        });

    } catch (error) {
        console.error("STK Push Error:", error.response?.data || error.message);
        res.status(500).json({
            error: "Failed to initiate payment",
            details: error.response?.data || error.message
        });
    }
});

/* -------------------------------
   12. Retry Payment Endpoint
-------------------------------- */
app.post("/api/retry-payment", async (req, res) => {
    try {
        const { phone } = req.body;
        if (!phone || typeof phone !== 'string') {
            return res.status(400).json({ error: "Phone number required" });
        }

        const cleanPhone = phone.replace(/\s+/g, '').replace(/^\+/, '').replace(/^0/, '254');

        const lastTx = await Transaction.findOne({
            phone: cleanPhone,
            status: { $in: ["PENDING", "FAILED", "CANCELLED"] }
        }).sort({ createdAt: -1 });

        if (!lastTx) {
            return res.status(404).json({ error: "No failed or pending transaction found to retry" });
        }

        const retryCount = lastTx.retryCount || 0;
        const secondsSinceLast = (Date.now() - new Date(lastTx.lastRetryAt || lastTx.createdAt).getTime()) / 1000;

        if (retryCount >= 5) {
            if (secondsSinceLast < 30) {
                return res.status(429).json({
                    error: `Retry limit reached (${retryCount}). Please wait ${Math.ceil(30 - secondsSinceLast)} seconds before trying again.`
                });
            } else {
                await Transaction.updateOne({ _id: lastTx._id }, { retryCount: 0 });
            }
        }

        await Transaction.updateOne(
            { _id: lastTx._id },
            { status: "FAILED", lastRetryAt: new Date() }
        );

        const newTx = await initiateStkPush(
            lastTx.name,
            cleanPhone,
            lastTx.amount,
            retryCount + 1,
            lastTx.bundle_sku,
            lastTx.source
        );

        res.status(201).json({
            message: "Retry initiated. Check your phone for the M-PESA prompt.",
            transactionId: newTx._id,
            retryCount: retryCount + 1
        });

    } catch (error) {
        console.error("Retry payment error:", error);
        res.status(500).json({ error: "Failed to retry payment", details: error.message });
    }
});

/* -------------------------------
   12b. Query STK Push Status
-------------------------------- */
app.post("/api/query-stk", async (req, res) => {
    try {
        const { checkoutRequestId } = req.body;
        if (!checkoutRequestId) {
            return res.status(400).json({ error: "checkoutRequestId required" });
        }

        const auth = Buffer.from(
            `${process.env.DARAJA_CONSUMER_KEY}:${process.env.DARAJA_CONSUMER_SECRET}`
        ).toString('base64');

        const tokenRes = await axios.get(
            `${DARAJA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials`,
            { headers: { Authorization: `Basic ${auth}` } }
        );
        const accessToken = tokenRes.data.access_token;

        const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
        const password = Buffer.from(
            `${process.env.DARAJA_SHORTCODE}${process.env.DARAJA_PASSKEY}${timestamp}`
        ).toString('base64');

        const queryPayload = {
            BusinessShortCode: process.env.DARAJA_SHORTCODE,
            Password: password,
            Timestamp: timestamp,
            CheckoutRequestID: checkoutRequestId
        };

        const queryRes = await axios.post(
            `${DARAJA_BASE_URL}/mpesa/stkpushquery/v1/query`,
            queryPayload,
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        console.log("📥 STK Query Response:", queryRes.data);
        res.json(queryRes.data);

    } catch (error) {
        console.error("STK Query Error:", error.response?.data || error.message);
        res.status(500).json({
            error: "Failed to query STK status",
            details: error.response?.data || error.message
        });
    }
});

/* -------------------------------
   13. Fetch Transactions (paginated)
-------------------------------- */
app.get("/api/transactions", async (req, res) => {
    try {
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
        const status = (req.query.status || '').toUpperCase();
        const phone = (req.query.phone || '').trim();

        const rawSearch = (req.query.search || '').trim();
        const search = rawSearch.length > 100 ? rawSearch.slice(0, 100) : rawSearch;
        const escapedSearch = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

        const filter = {};
        if (status && ['PENDING', 'SUCCESS', 'FAILED', 'CANCELLED'].includes(status)) {
            filter.status = status;
        }
        if (phone) {
            filter.phone = phone.replace(/\s+/g, '');
        }
        if (escapedSearch) {
            filter.$or = [
                { name: { $regex: escapedSearch, $options: 'i' } },
                { phone: { $regex: escapedSearch, $options: 'i' } },
                { mpesa_receipt: { $regex: escapedSearch, $options: 'i' } },
                { checkout_id: { $regex: escapedSearch, $options: 'i' } }
            ];
        }

        const skip = (page - 1) * limit;

        const [total, transactions] = await Promise.all([
            Transaction.countDocuments(filter),
            Transaction.find(filter)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean()
        ]);

        const totalPages = Math.ceil(total / limit);

        res.json({
            data: transactions,
            pagination: {
                page, limit, total, totalPages,
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        });
    } catch (error) {
        console.error("Fetch transactions error:", error);
        res.status(500).json({ error: "Failed to fetch transactions" });
    }
});

/* -------------------------------
   14. Get Single Transaction by ID
-------------------------------- */
app.get("/api/transaction/:id", async (req, res) => {
    try {
        const transaction = await Transaction.findById(req.params.id);
        if (!transaction) {
            return res.status(404).json({ error: "Transaction not found" });
        }
        res.json(transaction);
    } catch (error) {
        res.status(500).json({ error: "Failed to fetch transaction" });
    }
});

/* -------------------------------
   15. Daraja Payment Callback
-------------------------------- */
app.post("/callback", callbackIpCheck, async (req, res) => {
    const cb = req.body?.Body?.stkCallback;
    console.log(`🔔 Callback: ${cb?.CheckoutRequestID || 'unknown'} → ResultCode ${cb?.ResultCode}`);

    res.sendStatus(200);

    (async () => {
        try {
            if (!cb) {
                console.error("❌ Invalid callback structure");
                return;
            }

            const checkoutId = cb.CheckoutRequestID;
            const merchantRequestId = cb.MerchantRequestID;
            const resultCode = cb.ResultCode;
            const resultDesc = cb.ResultDesc;

            const items = cb.CallbackMetadata?.Item || [];
            const getItem = (name) => items.find(i => i.Name === name)?.Value;
            const receipt = getItem('MpesaReceiptNumber');
            const phone = getItem('PhoneNumber');
            const amount = getItem('Amount');

            const status = Number(resultCode) === 0 ? 'SUCCESS' : 'FAILED';

            let transaction = null;
            if (checkoutId) {
                transaction = await Transaction.findOne({ checkout_id: checkoutId });
            }
            if (!transaction && merchantRequestId) {
                transaction = await Transaction.findOne({ merchant_request_id: merchantRequestId });
            }
            if (!transaction && phone && amount) {
                transaction = await Transaction.findOne({
                    phone: String(phone),
                    amount: String(amount)
                }).sort({ createdAt: -1 });
            }
            if (!transaction) {
                console.error(`❌ No transaction found for CheckoutRequestID: ${checkoutId}`);
                return;
            }

            transaction.status = status;
            transaction.result_code = resultCode;
            transaction.result_desc = resultDesc;
            if (receipt) transaction.mpesa_receipt = receipt;
            if (checkoutId) transaction.checkout_id = checkoutId;
            if (merchantRequestId) transaction.merchant_request_id = merchantRequestId;
            await transaction.save();
            console.log(`✅ Transaction ${transaction._id} → ${status}${receipt ? ` (${receipt})` : ''}`);

            if (status === 'SUCCESS') {
                const callbackPayload = {
                    transactionId: transaction._id,
                    checkoutId: transaction.checkout_id,
                    checkout_id: transaction.checkout_id,
                    merchantRequestId: transaction.merchant_request_id,
                    status: 'SUCCESS',
                    paid: true,
                    mpesa_receipt: receipt || transaction.mpesa_receipt,
                    receipt: receipt || transaction.mpesa_receipt,
                    amount: transaction.amount,
                    phone: transaction.phone,
                    name: transaction.name,
                    bundle_sku: transaction.bundle_sku,
                    source: transaction.source,
                    reference: checkoutId,
                    createdAt: transaction.createdAt
                };

                const rawUrls = [
                    process.env.FORWARD_WEBHOOK_URLS,
                    process.env.RENTSPACE_WEBHOOK_URL,
                    process.env.FINEESCORTS_WEBHOOK_URL
                ].filter(Boolean).join(',');

                const webhookUrls = [...new Set(
                    rawUrls.split(',').map(u => u.trim()).filter(Boolean)
                )];

                if (!webhookUrls.length) {
                    console.log('ℹ️  No forwarding webhooks configured');
                }

                const forwardHeaders = process.env.FORWARD_WEBHOOK_SECRET
                    ? { 'x-api-secret': process.env.FORWARD_WEBHOOK_SECRET }
                    : {};

                for (const webhookUrl of webhookUrls) {
                    try {
                        await axios.post(webhookUrl, callbackPayload, {
                            timeout: 5000,
                            headers: forwardHeaders
                        });
                        console.log(`✅ Forwarded to ${webhookUrl}`);
                    } catch (err) {
                        console.error(`❌ Failed to forward to ${webhookUrl}:`, err.message);
                    }
                }
            }
        } catch (err) {
            console.error("❌ Error processing callback:", err);
        }
    })();
});

/* -------------------------------
   16. Start Server
-------------------------------- */
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌍 Environment: ${DARAJA_ENV}`);
});
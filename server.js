require('dotenv').config();

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 10000;

// Trust Render's reverse proxy so req.ip returns the real client IP
app.set('trust proxy', 1);

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
    status: { type: String, default: "PENDING" },
    checkout_id: String,          // Daraja CheckoutRequestID
    merchant_request_id: String,  // Daraja MerchantRequestID
    mpesa_receipt: String,
    result_code: Number,
    result_desc: String,
    retryCount: { type: Number, default: 0 },
    lastRetryAt: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now }
});

// Indexes for fast lookups and pagination
transactionSchema.index({ createdAt: -1 });
transactionSchema.index({ phone: 1, createdAt: -1 });
transactionSchema.index({ status: 1, createdAt: -1 });
transactionSchema.index({ checkout_id: 1 });
transactionSchema.index({ merchant_request_id: 1 });

const Transaction = mongoose.model("Transaction", transactionSchema);

/* -------------------------------
   3. Middleware – CORS + BODY PARSING
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
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static("docs"));

/* -------------------------------
   4. Shared Secret Check
-------------------------------- */
const SKIP_SECRET_DOMAINS = [
    'https://bingwasoko.co.ke',
    'https://www.bingwasoko.co.ke',
    'https://datasokoni.com',
    'https://www.datasokoni.com'
];

const VALID_SECRETS = [
    process.env.API_SECRET,
    process.env.API_SECRET_BINGWA,
    process.env.API_SECRET_FINEESCORTS,
].filter(Boolean);

const checkSecret = (req, res, next) => {
    const origin = req.headers.origin || req.headers.referer || '';
    const secret = req.headers['x-api-secret'];

    const isTrustedDomain = SKIP_SECRET_DOMAINS.some(domain => origin.startsWith(domain));
    if (isTrustedDomain) {
        console.log(`✅ Skipping secret check for trusted domain: ${origin}`);
        return next();
    }

    if (!secret) {
        console.warn('❌ Missing API secret header');
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
    const token = req.headers['x-recaptcha-token'] || req.body.recaptchaToken;
    if (!token) {
        return res.status(400).json({ error: "Missing reCAPTCHA token" });
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
        if (!success || score < 0.5) {
            console.log(`reCAPTCHA failed: success=${success}, score=${score}`);
            return res.status(403).json({ error: "Bot detected. Please try again." });
        }

        next();
    } catch (error) {
        console.error("reCAPTCHA verification error:", error);
        return res.status(500).json({ error: "CAPTCHA verification failed" });
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

app.use('/api/pay', checkSecret);
app.use('/api/retry-payment', checkSecret);
// app.use('/api/pay', verifyRecaptcha); // Uncomment for production
// app.use('/api/retry-payment', verifyRecaptcha);
app.use('/api/pay', globalRateLimit);
app.use('/api/retry-payment', globalRateLimit);

/* -------------------------------
   7. IP Blocking
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
    const ip = req.ip || req.connection.remoteAddress;
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
    message: { error: "Too many payment requests from this IP. Please wait 5 minutes." },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        const ip = req.ip || req.connection.remoteAddress;
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
   9. Daraja Configuration
-------------------------------- */
const DARAJA_ENV = process.env.DARAJA_ENVIRONMENT || 'production';
const DARAJA_BASE_URL = DARAJA_ENV === 'sandbox'
    ? 'https://sandbox.safaricom.co.ke'
    : 'https://api.safaricom.co.ke';

console.log(`📍 Daraja Environment: ${DARAJA_ENV}`);
console.log(`📍 Daraja Base URL: ${DARAJA_BASE_URL}`);
console.log(`📍 Daraja Shortcode: ${process.env.DARAJA_SHORTCODE}`);
console.log(`📍 Daraja Callback: ${process.env.DARAJA_CALLBACK_URL}`);

/* -------------------------------
   10. Helper: Initiate STK Push (Direct API)
-------------------------------- */
async function initiateStkPush(name, phone, amount, retryCount = 0) {
    // 1. Normalize phone to 254XXXXXXXXX
    let formattedPhone = phone
        .replace(/\s+/g, '')
        .replace(/^\+/, '')
        .replace(/^0/, '254');
    if (!formattedPhone.startsWith('254')) {
        formattedPhone = '254' + formattedPhone;
    }

    // 2. Get OAuth Access Token
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

    // 3. Generate Timestamp and Password
    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
    const password = Buffer.from(
        `${process.env.DARAJA_SHORTCODE}${process.env.DARAJA_PASSKEY}${timestamp}`
    ).toString('base64');

    // 4. Build the STK Push Request
    const accountRef = `PAY-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;

    console.log("📤 Daraja STK Request (Direct API):", {
        phone: formattedPhone,
        amount: Math.round(parseFloat(amount)),
        accountRef,
        callbackUrl: process.env.DARAJA_CALLBACK_URL
    });

    const stkPayload = {
        BusinessShortCode: process.env.DARAJA_SHORTCODE,
        Password: password,
        Timestamp: timestamp,
        TransactionType: "CustomerPayBillOnline",
        Amount: Math.round(parseFloat(amount)),
        PartyA: formattedPhone,
        PartyB: process.env.DARAJA_SHORTCODE,
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
        console.log("📥 Daraja Response (Direct API):", response);
    } catch (err) {
        console.error('❌ Daraja STK Push failed:', err.response?.data || err.message);
        const errorMsg = err.response?.data?.errorMessage || err.response?.data?.ResponseDescription || 'Daraja STK push failed';
        throw new Error(errorMsg);
    }

    // 5. Check for Success and Save Transaction
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
        checkout_id: checkoutId,
        merchant_request_id: merchantRequestId,
        retryCount: retryCount,
        lastRetryAt: new Date()
    });
    await tx.save();
    return tx;
}

/* -------------------------------
   11. Initiate Payment
-------------------------------- */
app.post("/api/pay", async (req, res) => {
    try {
        const { name, phone, amount } = req.body;
        if (!name || !phone || !amount) {
            return res.status(400).json({ error: "Name, phone and amount required" });
        }

        let formattedPhone = phone
            .replace(/\s+/g, '')
            .replace(/^\+/, '')
            .replace(/^0/, '254');

        const lastTx = await Transaction.findOne({ phone: formattedPhone })
            .sort({ createdAt: -1 });

        // 30-second timeout for pending transactions
        if (lastTx && lastTx.status === "PENDING") {
            const secondsSince = (Date.now() - new Date(lastTx.createdAt).getTime()) / 1000;
            if (secondsSince > 30) {
                await Transaction.updateOne(
                    { _id: lastTx._id },
                    { status: "FAILED" }
                );
                console.log(`Auto-cleaned stale pending transaction ${lastTx._id} after 30s`);
            } else {
                return res.status(409).json({
                    error: "You already have a pending payment. Please wait or check your phone."
                });
            }
        }

        // Retry limit handling (max 5 attempts)
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

        const tx = await initiateStkPush(name, formattedPhone, amount, lastTx?.retryCount || 0);
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
        if (!phone) {
            return res.status(400).json({ error: "Phone number required" });
        }

        let formattedPhone = phone
            .replace(/\s+/g, '')
            .replace(/^\+/, '')
            .replace(/^0/, '254');

        const lastTx = await Transaction.findOne({
            phone: formattedPhone,
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
            formattedPhone,
            lastTx.amount,
            retryCount + 1
        );

        res.status(201).json({
            message: "Retry initiated. Check your phone for the M-PESA prompt.",
            transactionId: newTx._id,
            retryCount: retryCount + 1
        });

    } catch (error) {
        console.error("Retry payment error:", error);
        res.status(500).json({
            error: "Failed to retry payment",
            details: error.message
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
        const search = (req.query.search || '').trim();

        const filter = {};
        if (status && ['PENDING', 'SUCCESS', 'FAILED', 'CANCELLED'].includes(status)) {
            filter.status = status;
        }
        if (phone) {
            filter.phone = phone.replace(/\s+/g, '');
        }
        if (search) {
            filter.$or = [
                { name: { $regex: search, $options: 'i' } },
                { phone: { $regex: search, $options: 'i' } },
                { mpesa_receipt: { $regex: search, $options: 'i' } },
                { checkout_id: { $regex: search, $options: 'i' } }
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
                page,
                limit,
                total,
                totalPages,
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
   15. Daraja Payment Callback (Webhook)
-------------------------------- */
app.post("/callback", async (req, res) => {
    console.log("========================================");
    console.log("🔔 DARAJA CALLBACK RECEIVED");
    console.log("📌 Content-Type:", req.headers["content-type"]);
    console.log("📌 Body:", JSON.stringify(req.body, null, 2));
    console.log("========================================");

    // Always respond with 200 immediately — Daraja retries aggressively on non-200
    res.sendStatus(200);

    // Process asynchronously
    (async () => {
        try {
            const callback = req.body?.Body?.stkCallback;
            if (!callback) {
                console.error("❌ Invalid Daraja callback structure (missing Body.stkCallback)");
                return;
            }

            const checkoutId = callback.CheckoutRequestID;
            const merchantRequestId = callback.MerchantRequestID;
            const resultCode = callback.ResultCode;
            const resultDesc = callback.ResultDesc;

            console.log(`📊 ResultCode: ${resultCode}, Desc: ${resultDesc}`);
            console.log(`📊 CheckoutRequestID: ${checkoutId}`);

            const items = callback.CallbackMetadata?.Item || [];
            const getItem = (name) => items.find(i => i.Name === name)?.Value;
            const receipt = getItem('MpesaReceiptNumber');
            const phone = getItem('PhoneNumber');
            const amount = getItem('Amount');

            const status = Number(resultCode) === 0 ? 'SUCCESS' : 'FAILED';

            let transaction = null;

            if (checkoutId) {
                transaction = await Transaction.findOne({ checkout_id: checkoutId });
                if (transaction) console.log(`✅ Found by CheckoutRequestID: ${checkoutId}`);
            }

            if (!transaction && merchantRequestId) {
                transaction = await Transaction.findOne({ merchant_request_id: merchantRequestId });
                if (transaction) console.log(`✅ Found by MerchantRequestID: ${merchantRequestId}`);
            }

            if (!transaction && phone && amount) {
                transaction = await Transaction.findOne({
                    phone: String(phone),
                    amount: String(amount)
                }).sort({ createdAt: -1 });
                if (transaction) console.log(`✅ Found by phone + amount: ${phone} / ${amount}`);
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
            console.log(`✅ Transaction ${transaction._id} updated to ${status}`);

            if (status === 'SUCCESS') {
                const callbackPayload = {
                    checkout_id: transaction.checkout_id,
                    status: 'paid',
                    mpesa_receipt: receipt || transaction.mpesa_receipt,
                    amount: transaction.amount,
                    phone: transaction.phone,
                    name: transaction.name,
                    reference: checkoutId
                };

                // Forward to FineEscorts
                const fineEscortsUrl = process.env.FINEESCORTS_WEBHOOK_URL
                    || 'https://fineescorts.co.ke/payment-callback';

                try {
                    await axios.post(
                        fineEscortsUrl,
                        {
                            transactionId: transaction._id,
                            checkoutId: transaction.checkout_id,
                            status: status,
                            receipt: receipt,
                            phone: transaction.phone,
                            amount: transaction.amount,
                            name: transaction.name
                        },
                        { timeout: 5000 }
                    );
                    console.log(`✅ Forwarded callback to FineEscorts (${fineEscortsUrl})`);
                } catch (err) {
                    console.error('❌ Failed to forward callback to FineEscorts:', err.message);
                }

                // Forward to RentSpace (supports comma-separated URLs)
                const webhookUrls = (process.env.RENTSPACE_WEBHOOK_URL
                    || 'https://rentspace-marketplace.onrender.com/api/subscriptions/saraha-webhook')
                    .split(',')
                    .map(u => u.trim())
                    .filter(Boolean);

                for (const webhookUrl of webhookUrls) {
                    try {
                        await axios.post(webhookUrl, callbackPayload, { timeout: 5000 });
                        console.log(`✅ Forwarded callback to ${webhookUrl}`);
                    } catch (err) {
                        console.error(`❌ Failed to forward callback to ${webhookUrl}:`, err.message);
                    }
                }
            }
        } catch (err) {
            console.error("❌ Error processing Daraja callback:", err);
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
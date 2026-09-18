// Helper: display status message
function showStatus(message, type) {
    const status = document.getElementById("status");
    if (!status) return;
    status.style.color = type === "success" ? "green" : type === "error" ? "red" : "blue";
    status.innerText = message;
}

// Helper: enable/disable pay button
function setPayButton(disabled, text = null) {
    const btn = document.getElementById("payBtn");
    if (!btn) return;
    btn.disabled = disabled;
    if (text !== null) btn.innerText = text;
}

// ---------- API Base URLs (Daraja) ----------
// ← CHANGED: fixed hostname (sarahapay → saraha-pay). Must match Render's URL exactly.
const API_BASE = "https://saraha-pay-daraja.onrender.com";
const API_PAY_URL = `${API_BASE}/api/pay`;
const API_RETRY_URL = `${API_BASE}/api/retry-payment`;

// ---------- Shared secret (must match API_SECRET in Render) ----------
const API_SECRET = "103e07b75c0b3d874cd4376dd0e095729f66d4f268033061aa087df169acc4ac4";

// ---------- reCAPTCHA site key (from Google) ----------
const RECAPTCHA_SITE_KEY = "6LcKDGEtAAAAAJKAWjXB7j5bSIPvzz94wBWapTD5";

// Retry payment using /api/retry-payment endpoint
async function retryPayment(phone) {
    const retryBtn = document.getElementById("retryBtn");
    if (retryBtn) {
        retryBtn.disabled = true;
        retryBtn.innerText = "Retrying...";
    }
    showStatus("Retrying payment...", "blue");

    try {
        const response = await fetch(API_RETRY_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-Secret": API_SECRET
            },
            body: JSON.stringify({ phone: phone })
        });
        const data = await response.json();

        if (response.ok) {
            showStatus(data.message || "Retry initiated. Check your phone for M-PESA prompt.", "success");
            const rb = document.getElementById("retryBtn");
            if (rb) rb.remove();
            setPayButton(false, "Pay Now");
        } else if (response.status === 429) {
            const errorMsg = data.error || "Too many failed attempts. Please wait.";
            showStatus(errorMsg, "error");
            const match = errorMsg.match(/(\d+)\s*second/);
            const waitSeconds = match ? parseInt(match[1]) : 30;
            startCooldownTimer(waitSeconds, phone);
        } else {
            showStatus(data.error || "Retry failed. Try again later.", "error");
            if (retryBtn) {
                retryBtn.disabled = false;
                retryBtn.innerText = "Retry Payment";
            }
        }
    } catch (err) {
        console.error("Retry error:", err);
        showStatus("Network error. Please refresh and try again.", "error");
        if (retryBtn) {
            retryBtn.disabled = false;
            retryBtn.innerText = "Retry Payment";
        }
    }
}

// Countdown timer for cooldown period (in seconds)
function startCooldownTimer(seconds, phone) {
    let remaining = seconds;
    const timerInterval = setInterval(() => {
        if (remaining <= 0) {
            clearInterval(timerInterval);
            showStatus("You can now retry again.", "blue");
            offerRetryButton(phone);
        } else {
            showStatus(`Too many failed attempts. Please wait ${remaining} seconds before retrying.`, "error");
            remaining--;
        }
    }, 1000);
}

// Create or show retry button
function offerRetryButton(phone) {
    let retryBtn = document.getElementById("retryBtn");
    if (!retryBtn) {
        retryBtn = document.createElement("button");
        retryBtn.id = "retryBtn";
        retryBtn.innerText = "Retry Payment";
        retryBtn.style.marginTop = "10px";
        retryBtn.style.padding = "10px 20px";
        retryBtn.style.backgroundColor = "#ff9800";
        retryBtn.style.border = "none";
        retryBtn.style.borderRadius = "5px";
        retryBtn.style.cursor = "pointer";
        retryBtn.onclick = () => retryPayment(phone);
        const payBtn = document.getElementById("payBtn");
        if (payBtn && payBtn.parentNode) {
            payBtn.parentNode.insertBefore(retryBtn, payBtn.nextSibling);
        } else {
            document.getElementById("paymentForm").appendChild(retryBtn);
        }
    } else {
        retryBtn.style.display = "block";
        retryBtn.disabled = false;
        retryBtn.innerText = "Retry Payment";
        retryBtn.onclick = () => retryPayment(phone);
    }
}

// Main payment function (with reCAPTCHA)
async function handlePayment() {
    const name = document.getElementById("name").value;
    const phone = document.getElementById("phone").value;
    const amount = document.getElementById("amount").value;

    if (!name || !phone || !amount) {
        alert("Please fill in name, phone and amount");
        return;
    }

    setPayButton(true, "Processing...");
    showStatus("Requesting M-Pesa prompt...", "blue");

    try {
        // ---------- Get reCAPTCHA token (invisible) ----------
        let recaptchaToken = '';
        try {
            recaptchaToken = await grecaptcha.execute(RECAPTCHA_SITE_KEY, { action: 'payment' });
        } catch (captchaErr) {
            console.error("reCAPTCHA error:", captchaErr);
            // Continue anyway — backend may not require it
        }

        const response = await fetch(API_PAY_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-Secret": API_SECRET,
                "X-Recaptcha-Token": recaptchaToken
            },
            body: JSON.stringify({ name, phone, amount })
        });
        const data = await response.json();

        if (response.ok) {
            showStatus("STK Push sent. Check your phone.", "success");
            const rb = document.getElementById("retryBtn");
            if (rb) rb.remove();
        } else {
            const errorMsg = data.error || data.details || "Payment failed";
            showStatus(errorMsg, "error");

            if (response.status === 409) {
                showStatus("You already have a pending payment. Check your phone or wait a few minutes.", "error");
                startCooldownTimer(30, phone);
            } else if (response.status === 429) {
                const waitMatch = errorMsg.match(/(\d+)\s*second/);
                const waitSeconds = waitMatch ? parseInt(waitMatch[1]) : 30;
                startCooldownTimer(waitSeconds, phone);
            } else {
                offerRetryButton(phone);
            }
        }
    } catch (err) {
        console.error("Payment error:", err);
        showStatus("Server error. Please try again.", "error");
        offerRetryButton(phone);
    } finally {
        setPayButton(false, "Pay Now");
    }
}
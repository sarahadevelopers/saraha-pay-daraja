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

// ---------- API Base URLs ----------
const API_BASE = "https://saraha-pay-daraja.onrender.com";
const API_PAY_URL = `${API_BASE}/api/pay`;
const API_RETRY_URL = `${API_BASE}/api/retry-payment`;

// NOTE: No API_SECRET in this file anymore.
// Browser calls are authenticated by reCAPTCHA (enforced server-side).
// The shared secret is only used by server-to-server callers.

// ---------- reCAPTCHA site key ----------
const RECAPTCHA_SITE_KEY = "6LeRv_QtAAAAAJA7B6yizaa4gL6z-MK6XkGPkcdA";

// Helper: get a fresh reCAPTCHA token
async function getRecaptchaToken(action) {
    try {
        return await grecaptcha.execute(RECAPTCHA_SITE_KEY, { action });
    } catch (err) {
        console.error("reCAPTCHA execute error:", err);
        return '';
    }
}

// Retry payment using /api/retry-payment endpoint
async function retryPayment(phone) {
    const retryBtn = document.getElementById("retryBtn");
    if (retryBtn) {
        retryBtn.disabled = true;
        retryBtn.innerText = "Retrying...";
    }
    showStatus("Retrying payment...", "blue");

    try {
        const recaptchaToken = await getRecaptchaToken('retry_payment');

        const response = await fetch(API_RETRY_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Recaptcha-Token": recaptchaToken
            },
            body: JSON.stringify({ phone })
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
        const recaptchaToken = await getRecaptchaToken('payment');

        if (!recaptchaToken) {
            showStatus("Security verification failed. Please refresh and try again.", "error");
            setPayButton(false, "Pay Now");
            return;
        }

        const response = await fetch(API_PAY_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
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
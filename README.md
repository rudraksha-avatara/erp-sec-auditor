# 🔐 ERP Sec Auditor

**ERP Sec Auditor** is a safe, professional security testing tool built for administrators like **Jaydatt Khodave** to audit ERP login systems without performing brute‑force attacks.

It helps you test authentication flow, lockout policy, error leakage, and logging behavior using controlled password lists.

---

# 🚀 Features

✅ Spring Security login support (`/login.htm` → `/j_spring_security_check`)
✅ Cookie & session handling
✅ CSRF hidden field auto-detection
✅ JSON + NDJSON live logging
✅ Success / failure detection using redirect URL
✅ Password hashing in logs (no plaintext leak)
✅ Suspicious response detection (SQL errors / 5xx)
✅ Safe caps to prevent brute‑force misuse

---

# 📁 Folder Structure

```
erp-sec-auditor/
 ├── main.js   # main tool
 ├── passwords.txt        # test passwords list
 ├── erp-attempts.json    # final report
 ├── erp-attempts.ndjson  # live attempt logs
```

---

# ⚙️ Requirements

* Node.js 18+
* ERP admin test account
* Written permission to test system

Check Node version:

```
node -v
```

---

# 📥 Installation

No dependencies needed.

Just download the script and run.

```
mkdir erp-sec-auditor
cd erp-sec-auditor
```

Add file:

```
erp-sec-auditor.js
```

---

# 📝 passwords.txt Format

One password per line:

```
Password123
Test@1234
Demo@431401
Admin@2026
```

No spaces or blank lines.

---

# ▶️ Run Command (One Line)

```
node main.js run --base https://erp.itisuniqueofficial.com --login-path /login.htm --auth-path /j_spring_security_check --user-field j_username --pass-field j_password --username test@itisuniqueofficial.com --password-file passwords.txt --out erp-attempts.json --ndjson erp-attempts.ndjson --max-tries 1000 --timeout-ms 1000 --retries 1 --stop-on-success 1 --show-body 0
```

---

# 📊 Output Files

### 1️⃣ erp-attempts.ndjson

Live stream log:

```
{"index":0,"status":302,"location":"/login.htm?failure=true"}
```

### 2️⃣ erp-attempts.json

Full structured report:

```
{
  "summary": {
    "successFound": true,
    "successAtIndex": 3
  }
}
```

---

# 🔐 Security Testing Use Cases

* Login success detection
* Wrong password handling
* Lockout policy test
* SQL error leakage check
* Response timing analysis
* Redirect validation

---

# ☁️ Recommended ERP Security Improvements

### 1️⃣ Lockout Policy

```
5 failed attempts → 10 minute lockout
```

### 2️⃣ Cloudflare Rate Limit

```
Path: /j_spring_security_check
Limit: 5 requests/min per IP
```

### 3️⃣ Enable MFA / OTP

### 4️⃣ Generic Error Message

```
"Invalid username or password"
```

---

# 📧 Alerts Automation Ideas

* Telegram bot alert on login spikes
* Email alert if 20 failures/min
* Cloudflare Worker auto‑block

---

# 📌 Important Rules

* Only test systems you own or have permission for
* Do not remove safety caps
* Do not use for password guessing
* Change real passwords after testing

---

# 👨‍💻 Author

Created for **Jaydatt Khodave**

Full‑Stack Developer • Automation Engineer • Security Researcher

Website: [https://www.itisuniqueofficial.com](https://www.itisuniqueofficial.com)

---

# ⭐ Future Features

* HTML dashboard report
* Telegram alert bot
* NVIDIA AI log analyzer
* Cloudflare WAF auto‑rule generator
* Firebase security audit module

---

# ❤️ Support

If this tool helps you, star your GitHub repo and keep building secure platforms 🚀

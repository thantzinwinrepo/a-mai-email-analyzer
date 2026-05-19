# 🐱 A Mai — Email Threat Analyzer

A local SOC dashboard for analyzing `.eml` files. Parse emails, extract IOCs, query VirusTotal, perform WHOIS lookup on the sender domain, and export reports — all from a clean web UI that runs on your machine.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)

---

## 📸 Features

- **EML Parsing** — headers, routing chain, SPF/DKIM/DMARC auth results, body, attachments
- **IOC Extraction** — IPs, domains, URLs, email addresses, MD5/SHA1/SHA256 hashes
- **Threat Intelligence** — VirusTotal lookups for IPs, domains, URLs, and file hashes
- **Sender WHOIS** — RDAP lookup (over HTTPS) for the sender domain: creation date, age, registrar
- **Threat Score** — automatic risk scoring based on auth failures, URL count, attachments
- **Visualizations** — IOC distribution chart, VT detection bar chart, threat gauge, domain age chart
- **Paste Support** — paste raw EML text directly into the dashboard (no file needed)
- **Export** — download full reports as CSV or JSON
- **Light / Dark mode** — persists across sessions
- **Auto-opens browser** — just run the script, the page opens automatically

---

## 🚀 Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/a-mai-email-analyzer.git
cd a-mai-email-analyzer
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run

```bash
python3 server.py
```

The browser opens automatically at `http://localhost:8000`.

---

## 📁 Project Structure

```
a-mai-email-analyzer/
├── server.py          # Backend — EML parser, IOC extractor, API integrations
├── static/
│   └── index.html     # Frontend dashboard (single file, no build step)
├── requirements.txt
└── README.md
```

> **Note:** If you place `index.html` in the same folder as `server.py` (flat layout), the server will automatically move it into `static/` on first run.

---

## 🔑 API Keys (Optional)

The tool works without any API keys — IOCs are extracted from the EML regardless. API keys unlock threat intelligence enrichment.

| Key | Where to get | What it unlocks |
|-----|-------------|-----------------|
| VirusTotal | [virustotal.com](https://www.virustotal.com) → Sign up → API Key | VT detection scores for IPs, domains, URLs, hashes |

Enter your key in the dashboard's **API Keys** bar and click **Save** — it's stored in your browser's localStorage.

> **Free tier limits:** VirusTotal free allows 4 requests/minute and 500/day. For heavy use, consider a premium key.

---

## 🛡️ What Gets Analyzed

### Email Headers
`From`, `To`, `CC`, `Subject`, `Date`, `Reply-To`, `Message-ID`, `X-Originating-IP`, `X-Mailer`

### Authentication
- **SPF** — Sender Policy Framework
- **DKIM** — DomainKeys Identified Mail
- **DMARC** — Domain-based Message Authentication

### IOCs Extracted
- Public IP addresses (private ranges filtered automatically)
- Domains and URLs (from headers, body, HTML)
- Email addresses
- File hashes from attachments (MD5, SHA256) and body text

### Sender Domain WHOIS
Uses RDAP (HTTPS) to look up:
- Creation date
- Domain age
- Registrar
- Expiry date
- Status flags

---

## 📊 Threat Score

The dashboard automatically calculates a 0–100 risk score:

| Indicator | Points |
|-----------|--------|
| SPF Fail | +25 |
| DKIM Fail | +20 |
| DMARC Fail | +20 |
| More than 3 URLs | +15 |
| Attachments present | +10 |
| More than 2 external IPs | +10 |

| Score | Level |
|-------|-------|
| 0–39 | ✅ Low Risk |
| 40–69 | ⚡ Suspicious |
| 70–100 | ⚠️ High Risk |

---

## 🖥️ Requirements

- Python 3.8+
- No external web framework — uses Python's built-in `http.server`
- Internet access for VirusTotal and RDAP (WHOIS) lookups

---

## 📦 Dependencies

```
requests
python-whois
dnspython
```

All other modules (`email`, `re`, `json`, `csv`, `hashlib`, `http.server`, `webbrowser`, `threading`) are Python standard library.

---

## ⚠️ Disclaimer

This tool is intended for **defensive security analysis** of emails you are authorized to inspect. Do not use it to analyze emails you do not have permission to review. IOC data is sent to third-party APIs (VirusTotal) only when you explicitly click **Run Threat Intel**.

---

## 📄 License

MIT License — free to use, modify, and distribute.

# 🛡️ VAPT Phase 3 – Phishing Domain Analysis Report

**🎯 Target Domain:** [https://todayspecialoffers.io](https://todayspecialoffers.io)  
**🔍 Analyst:** Indrajeet Palled  
**🏢 Organization:** Turtleneck Systems and Solutions Pvt Ltd  
**📅 Report Date:** July 3, 2025  
**📌 Assignment Phase:** Phase 3 – Phishing Analysis

---

## 🧾 Executive Summary

This report presents a phishing and vulnerability assessment of the domain `todayspecialoffers.io`, suspected to impersonate a legitimate e-commerce platform (Flipkart). The analysis confirms malicious activity, including deceptive UI, phishing traps, and multiple web vulnerabilities. The domain is built to lure users with fake discounts and steal credentials via spoofed interfaces.

---

## 🔧 Methodology & Tools Used

| Tool / Technique         | Purpose                                      |
|--------------------------|----------------------------------------------|
| `whois`                  | Domain registration metadata                 |
| `dig`, `nslookup`        | DNS lookup and IP address tracing            |
| `VirusTotal`             | Threat reputation scoring and vendor flags   |
| `nmap`                   | Full port scan and service enumeration       |
| `nikto`                  | Web vulnerability scanning                   |
| Browser DevTools         | HTML/JavaScript inspection of UI             |
| `Gobuster` (optional)    | Directory brute-forcing                      |
| Manual login testing     | Tested `/admin` login access manually        |

---

## ✅ Key Findings

| #  | Finding                    | Description                                                       | Status     |
|----|----------------------------|-------------------------------------------------------------------|------------|
| 1  | Fake Flipkart Branding     | Copied logo/UI using local assets like `SwOvZ3r.png`             | ✅ Confirmed |
| 2  | Price Manipulation         | Static "90% OFF" values hardcoded in JavaScript                  | ✅ Confirmed |
| 3  | Fake Product Display       | Products loaded via JS, no real validation                       | ✅ Confirmed |
| 4  | Obfuscated Product URLs    | MD5 hashes used in product links                                 | ✅ Confirmed |
| 5  | Exposed Admin Panel        | Accessible login via `/admin` path                               | ✅ Confirmed |
| 6  | Fake Delivery Promises     | Every product claims "Free Delivery in 2 Days"                   | ✅ Confirmed |
| 7  | Web Vulnerabilities (Nikto)| LFI, insecure headers, outdated components                       | ✅ Confirmed |
| 8  | VirusTotal Detection       | 12 vendors flagged it as phishing/malware                        | ✅ Confirmed |
| 9  | Service Enumeration (nmap) | FTP, MySQL, RPC, cPanel ports open                               | ✅ Confirmed |

---

## 🛠️ OWASP Risk Mapping

| OWASP Category               | Evidence/Tool                                |
|-----------------------------|----------------------------------------------|
| A1 – Broken Access Control  | Public `/admin` login page                   |
| A2 – Cryptographic Failures | Insecure cookies, no HSTS                    |
| A3 – Injection              | Potential LFI via `sitebuilder.cgi`          |
| A4 – Insecure Design        | Static UI with JS-only logic                 |
| A5 – Security Misconfig     | Missing headers, exposed services            |
| A6 – Vulnerable Components  | Outdated `SITEBUILDER v1.4`, `IlohaMail 0.8.10` |
| A7 – AuthN/Session Issues   | No CAPTCHA or login lockout on `/admin`     |
| A8 – Integrity Failures     | Fake product prices and discounts            |
| A9 – Logging/Monitoring     | No rate-limit or brute-force detection       |
| A10 – SSRF                  | ❌ Not Observed                               |

---

## 🧪 Technical Evidence Summary

- **WHOIS Info:** Recently registered, privacy-protected, shady registrar.
- **DNS/IP:** `212.81.47.13`, hosted by Datacamp Ltd, Sydney.
- **nmap:** Over 30 open ports; FTP, cPanel, MySQL exposed.
- **nikto:** Local File Inclusion (LFI), missing HTTP security headers.
- **VirusTotal:** 12/94 vendors marked as phishing/malware.
- **Screenshots Included:**
  - Fake Flipkart UI with logo
  - Admin login page
  - Static discount UI
  - VirusTotal detection summary

---

## 📬 Recommendations

| Action Type     | Suggestion                                                                 |
|----------------|------------------------------------------------------------------------------|
| Takedown Report | Report to CERT-In, domain registrar (NICENIC), and hosting provider (Datacamp) |
| Brand Abuse     | Notify Flipkart Security/Abuse team with evidence                          |
| Technical Fixes | If legitimate: secure headers, patch vulnerabilities, verify product logic |
| Prevention Tips | Monitor WHOIS and DNS records to detect phishing clones                    |

---

## 👤 Author Information

**Indrajeet Palled**  
Cybersecurity Intern – Turtleneck Systems and Solutions Pvt Ltd  
📧 Email: indrajeetmp11@gmail.com  
🔐 Focus Areas: VAPT, Ethical Hacking, Cyber Threat Intelligence

---

## ⚠️ Disclaimer

This report is part of an authorized academic VAPT assignment under supervised conditions. No unauthorized access or exploitation was performed. All actions were purely investigative and non-intrusive in nature.

---


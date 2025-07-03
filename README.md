# 🛡️ VAPT Phase 3 – Phishing Domain Analysis Report

**Target Domain:** https://todayspecialoffers.io  
**Analyst:** Indrajeet Palled  
**Organization:** Turtleneck Systems and Solutions Pvt Ltd  
**Assignment Phase:** Phase 3 – Phishing Analysis  
**Report Date:** July 3, 2025

---

## 🧾 Executive Summary

The domain `todayspecialoffers.io` was analyzed as part of a Vulnerability Assessment and Penetration Testing (VAPT) exercise to identify indicators of phishing activity, spoofed branding, backend exposures, and OWASP-aligned vulnerabilities.

Using OSINT tools, vulnerability scanners, and manual inspection techniques, the site was confirmed to be a **malicious phishing site** mimicking Flipkart, likely built to deceive users with fake discounts and login capture mechanisms.

---

VAPT_Phishing_Report_Indrajeet/
├── Final_Report.pdf                # Full technical report with screenshots
├── README.md                       # This documentation file
├── Output_Logs/                    # Raw output logs of scanning tools
│   ├── whois_todayspecialoffers.txt
│   ├── dig_todayspecialoffers.txt
│   ├── nslookup_todayspecialoffers.txt
│   ├── nmap_todayspecialoffers.txt
│   └── nikto_todayspecialoffers.txt
├── Screenshots/                    # Visual evidence from HTML/UI inspection
│   ├── html_inspect_todayspecialoffers.png
│   ├── fake_logo.png
│   ├── fake_discount.png
│   ├── admin_panel_login.png
│   └── virustotal_detection.png



---

## 🔧 Methodology & Tools Used

| Tool / Technique       | Purpose                                               |
|------------------------|--------------------------------------------------------|
| `whois`                | Domain registration metadata                          |
| `dig`, `nslookup`      | DNS lookup and IP address tracing                     |
| `VirusTotal`           | Threat reputation scoring and vendor flags            |
| `nmap`                 | Full port scan and service version enumeration        |
| `nikto`                | Web vulnerability scanning                            |
| `Browser DevTools`     | HTML/JavaScript inspection of UI                      |
| `Gobuster` (optional)  | Directory brute-force to find hidden admin paths      |
| Manual login testing   | Accessing exposed /admin panel                        |

---

## ✅ Key Findings

| # | Finding                          | Description                                                         | Status       |
|---|----------------------------------|---------------------------------------------------------------------|--------------|
| 1 | Fake Flipkart Branding           | Logo and UI copied using local assets (e.g., SwOvZ3r.png)          | ✅ Confirmed |
| 2 | Hardcoded Price Manipulation     | Static “90% OFF” values injected directly in JavaScript            | ✅ Confirmed |
| 3 | Fake Product Display             | DOM elements rendered via JS without real product validation       | ✅ Confirmed |
| 4 | Obfuscated Product URLs          | Usage of MD5 hashes in URLs (e.g., product-details/${md5_id})      | ✅ Confirmed |
| 5 | Exposed Admin Panel              | Login page found under /admin or /admin_panel path                 | ✅ Confirmed |
| 6 | Fake Delivery Promises           | Every product claims “Free Delivery in 2 Days”                     | ✅ Confirmed |
| 7 | Web Vulnerabilities (Nikto)      | Missing headers, LFI, insecure cookies, outdated components        | ✅ Confirmed |
| 8 | VirusTotal Detection             | 12 out of 94 vendors marked it as phishing/malware                 | ✅ Confirmed |
| 9 | Service Enumeration (Nmap)       | Multiple exposed services including FTP, MySQL, RPC, cPanel        | ✅ Confirmed |

---

## 🛠️ OWASP Risk Mapping

| OWASP Category                       | Evidence Source                                    |
|-------------------------------------|----------------------------------------------------|
| A1 – Broken Access Control          | Public /admin login interface                      |
| A2 – Cryptographic Failures         | No HSTS, insecure PHPSESSID cookie                 |
| A3 – Injection                      | Potential LFI via forum/view.php & sitebuilder.cgi |
| A4 – Insecure Design                | JS-built UI with no backend validation             |
| A5 – Security Misconfiguration      | Missing headers, exposed services                  |
| A6 – Vulnerable Components          | SITEBUILDER v1.4, IlohaMail 0.8.10                 |
| A7 – AuthN/Session Issues           | No CAPTCHA or lockout on admin login               |
| A8 – Integrity Failures             | Unverified product data injection in UI            |
| A9 – Logging & Monitoring Failures  | No alerting/rate-limit on brute-force attempts     |
| A10 – SSRF                          | ❌ Not observed                                     |

---

## 🧪 Output Logs

- `whois_todayspecialoffers.txt`: WHOIS lookup showing new domain, privacy protection, shady registrar
- `dig/nslookup`: IP: 212.81.47.13 → Hosted in Sydney (Datacamp Ltd), TTL 3600s
- `nmap_todayspecialoffers.txt`: Over 30 open ports; vulnerable exposed services found
- `nikto_todayspecialoffers.txt`: LFI in `sitebuilder.cgi`, insecure headers, vulnerable mail/web interfaces

---

## 🖼️ Screenshots (Evidence)

- 🖼️ `html_inspect_todayspecialoffers.png`: Fake Flipkart logo via `<img src="img/SwOvZ3r.png">`
- 🖼️ `fake_discount.png`: Static “90% Off” offer element rendered by JS
- 🖼️ `admin_panel_login.png`: Screenshot of accessible /admin login before server went down
- 🖼️ `virustotal_detection.png`: 12 vendors marked the domain as phishing/malicious

---

## 🧩 Final Status

As of **July 3, 2025**, the site `https://todayspecialoffers.io` is **offline/unresponsive**. This indicates:
- It may have been **taken down** after analysis.
- It may be implementing **anti-scan evasion** techniques.
- **Login panel** and fake UI are no longer accessible.

---

## 📬 Recommendations

| Action Type      | Suggestion                                                             |
|------------------|------------------------------------------------------------------------|
| Takedown Report  | Notify CERT-In, NICENIC Registrar, Datacamp Ltd. (Hosting provider)    |
| Domain Abuse     | Forward phishing report to Flipkart’s abuse email                      |
| Technical Fixes  | If legit: Add HTTP headers, patch vulns, remove fake branding          |
| Prevention Tips  | Monitor WHOIS/DNS changes for phishing detection                       |

---

## 👤 Author Info

**Indrajeet Palled**  
Cybersecurity Intern – Turtleneck Systems and Solutions Pvt Ltd  
📧 Email: indrajeetmp11@gmail.com  
🔐 Specialization: VAPT, Ethical Hacking, Cyber Threat Hunting

---

## ⚠️ Disclaimer

This report was created for **academic and authorized cybersecurity testing** under internship supervision. No exploitation or damage was caused to any system.

---


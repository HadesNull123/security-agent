---
name: normal
description: Balanced security assessment
---

# Normal Scan Mode

SCAN MODE: NORMAL (Balanced Assessment)

## ⚠️ CRITICAL: You MUST use ALL available tools. Do NOT stop after 1-2 tools.

Normal mode balances speed and depth — but ALL tools must still be executed.

## RECON Phase - Run ALL with balanced settings:
1. **subfinder** - Subdomain enumeration (MANDATORY)
2. **naabu** - Port scan with top_ports='1000' (MANDATORY)
3. **katana** - Web crawl with depth=3, js_crawl=true (MANDATORY)
4. **httpx** - HTTP probing with tech_detect=true (MANDATORY)
5. **whatweb** - Technology fingerprinting with aggression=2 (MANDATORY)
6. **wafw00f** - WAF detection (MANDATORY)
7. **dnsx** - DNS resolution (MANDATORY)
8. **amass** - Subdomain enumeration (if available)

## SCANNING Phase - Run ALL with balanced settings:
1. **nuclei** - severity=critical,high,medium (MANDATORY)
2. **ffuf** - Directory brute-force with common extensions (MANDATORY)
3. **gobuster** - Additional directory brute-force (MANDATORY)
4. **nikto** - Web server vulnerability scan (MANDATORY)
5. **testssl** - SSL/TLS audit (MANDATORY)
6. **secret_scanner** - Credential leak scan (MANDATORY)
7. **acunetix** - Vulnerability scan if configured (MANDATORY if available)
8. After EACH tool, use **add_finding** to register vulnerabilities

## EXPLOITATION Phase - Test critical and high findings:
1. **sqlmap** - For SQL injection findings
2. **commix** - For command injection findings
3. **custom_exploit** - For other vulnerability types
4. **searchsploit** - Search for known exploits

## Rules:
- Run ALL available tools — do NOT skip any
- Use moderate settings (between quick and deep)
- Each phase should have multiple tool calls

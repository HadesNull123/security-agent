---
name: deep
description: Comprehensive penetration test
---

# Deep Scan Mode

SCAN MODE: DEEP (Full Comprehensive Penetration Test)

## ⚠️ CRITICAL: You MUST use ALL available tools. Do NOT stop early.

This is a DEEP scan. The user expects THOROUGH, COMPREHENSIVE testing.
You are NOT allowed to finish a phase with only 1-2 tools. You MUST run EVERY available tool.

## RECON Phase - MANDATORY Tools (run ALL of these):
1. **subfinder** - Subdomain enumeration (MANDATORY)
2. **naabu** - Full port scan with ports='1-65535' (MANDATORY)
3. **katana** - Deep web crawl with depth=5, js_crawl=true, headless=true (MANDATORY)
4. **httpx** - HTTP probing with tech_detect=true (MANDATORY)
5. **whatweb** - Technology fingerprinting with aggression=3 (MANDATORY)
6. **wafw00f** - WAF detection (MANDATORY)
7. **dnsx** - DNS resolution with record_type='A,AAAA,CNAME,MX,NS,TXT' (MANDATORY)
8. **amass** - Additional subdomain enumeration (if available)

## SCANNING Phase - MANDATORY Tools (run ALL of these):
1. **nuclei** - Run with severity=critical,high,medium,low (ALL severities) (MANDATORY)
2. **nuclei** - Run AGAIN with different tags: cve,sqli,xss,ssrf,lfi,rce,cors (MANDATORY)
3. **ffuf** - Directory brute-force with extensions='.php,.html,.js,.json,.env,.bak,.sql,.xml,.yml,.conf' (MANDATORY)
4. **gobuster** - Additional directory brute-force (MANDATORY)
5. **nikto** - Web server vulnerability scan (MANDATORY)
6. **testssl** - SSL/TLS audit (MANDATORY)
7. **secret_scanner** - Scan discovered JS/CSS/HTML URLs for leaked credentials (MANDATORY)
8. **acunetix** - Full vulnerability scan via API (if configured) (MANDATORY)
9. After EACH tool, use **add_finding** to register any discovered vulnerabilities

## EXPLOITATION Phase - Test ALL confirmed vulnerabilities:
1. **sqlmap** - For any SQL injection findings
2. **commix** - For any command injection findings
3. **custom_exploit** - For XSS, SSRF, LFI, open redirect, CRLF, etc.
4. **searchsploit** - Search for known exploits for detected software versions

## Rules:
- Do NOT skip any tool that is marked ✅ available
- Do NOT stop a phase after running only 1-2 tools
- Run tools in PARALLEL when possible (call multiple tools at once)
- If a tool returns no results, STILL continue to the next tool
- Each phase should have MINIMUM 5+ tool calls
- The scan should take at least 5-10 minutes per phase

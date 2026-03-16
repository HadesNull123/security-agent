---
name: quick
description: Fast surface-level scan
---

# Quick Scan Mode

SCAN MODE: QUICK (Fast Surface Scan)

## ⚠️ CRITICAL: You MUST use ALL available tools. Do NOT stop after 1-2 tools.

Even in QUICK mode, you must run every available tool — but with FAST settings.
The difference from DEEP is speed, NOT coverage.

## RECON Phase - Run ALL with fast settings:
1. **subfinder** - Subdomain enumeration (MANDATORY)
2. **httpx** - HTTP probing (MANDATORY)
3. **wafw00f** - WAF detection (MANDATORY)
4. **whatweb** - Tech fingerprinting, aggression=1 (MANDATORY)
5. **dnsx** - DNS resolution (MANDATORY)
6. **naabu** - Port scan, top_ports='100' (MANDATORY, but fast)
7. **katana** - Web crawl, depth=2 (MANDATORY, but shallow)

## SCANNING Phase - Run ALL with fast settings:
1. **nuclei** - severity=critical,high only (MANDATORY)
2. **ffuf** - Basic directory brute-force (MANDATORY)
3. **nikto** - Web server scan (MANDATORY)
4. **testssl** - SSL/TLS audit (MANDATORY)
5. **secret_scanner** - Credential leak scan (MANDATORY)
6. **acunetix** - Scan if configured (MANDATORY if available)
7. After EACH tool, use **add_finding** to register vulnerabilities

## EXPLOITATION Phase:
- Test ONLY critical/high findings
- Prefer custom_exploit over heavy tools

## Key Difference from DEEP:
- Use smaller wordlists
- Scan fewer ports (top 100 vs all)
- Shallow crawl (depth 2 vs 5)
- Focus on critical/high severity only
- BUT still run ALL tools

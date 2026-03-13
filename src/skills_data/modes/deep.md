---
name: deep
description: Comprehensive penetration test
---

# Deep Scan Mode

SCAN MODE: DEEP (Comprehensive Scan)
Strategy: Thorough assessment. Leave no stone unturned.

## Tool Selection
- Recon: ALL recon tools (subfinder, naabu full port scan, katana deep crawl, httpx, theHarvester, amass)
- Scanning: nuclei with ALL severities, ffuf with large wordlist, multiple scan passes
- Exploitation: Test ALL confirmed vulnerabilities

## Guidance
- naabu: scan ALL ports (ports='1-65535')
- katana: depth=5 with js_crawl and headless
- nuclei: severity=critical,high,medium,low
- ffuf: use comprehensive wordlists with extensions
- Run as many tool calls as needed for thorough coverage

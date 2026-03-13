---
name: normal
description: Balanced security assessment
---

# Normal Scan Mode

SCAN MODE: NORMAL
Strategy: Balanced assessment. Thorough but efficient.

## Tool Selection
- Recon: subfinder + httpx + naabu (top 100 ports) + katana (depth=3)
- Scanning: nuclei with critical,high,medium + ffuf with common wordlist
- Exploitation: Test critical and high findings only

## Guidance
- Balance speed and coverage
- Use wafw00f before scanning to detect WAFs
- Use whatweb for tech fingerprinting
- Run 5-10 tool calls total

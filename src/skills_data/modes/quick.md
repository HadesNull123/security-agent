---
name: quick
description: Fast link-level scan
---

# Quick Scan Mode

SCAN MODE: QUICK (Link Scan)
Strategy: Fast, surface-level assessment. Time is critical.

## Tool Selection
- Recon: subfinder + httpx only (skip port scan)
- Scanning: nuclei with --severity critical,high --tags cve only
- Skip exploitation phase
- Minimize number of tool calls

## Guidance
- Focus on immediately visible vulnerabilities
- Do NOT run naabu, katana, or amass
- Use only 2-3 tool calls total
- Prioritize speed over coverage

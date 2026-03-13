---
name: auth_bruteforce
category: scanner
binary_name: ffuf
virtual: true
---

# Authentication Brute-Force & Rate Limit Testing

## When to Use
Test login forms and authentication endpoints for:
- Missing rate limiting (unlimited login attempts)
- Default credentials
- Weak password policies
Run when katana/crawling discovers /login, /admin, or /auth endpoints.

## How to Use
This is a **virtual skill** — uses ffuf with credential wordlists.
1. Use ffuf to brute-force login endpoints
2. Check for rate limiting by monitoring response times and status codes
3. Test common default credentials

## Parameters
- Use ffuf with credential-based payloads
- `target`: Login endpoint URL
- `wordlist`: Use `/usr/share/wordlists/common.txt` for usernames
- Monitor for: response code changes, response size differences

## Output Interpretation
- No rate limiting after 100 attempts = MEDIUM
- Default credentials work (admin:admin, admin:password) = CRITICAL
- Account lockout not implemented after 10 failed attempts = MEDIUM
- Different response sizes indicate valid username enumeration = MEDIUM

## Best Practices
- NEVER try more than 100 combinations without permission
- Start with top 10 default credentials only
- Check if brute-force protection exists BEFORE attempting
- Look for username enumeration via different error messages
- Monitor for account lockout (429 status code)

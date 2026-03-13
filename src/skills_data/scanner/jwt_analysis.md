---
name: jwt_analysis
category: scanner
binary_name: nuclei
virtual: true
---

# JWT Token Analysis

## When to Use
Test JWT implementation when the target uses JWT tokens for authentication.
Detect weak signing algorithms, missing expiration, algorithm confusion attacks.
Run when httpx/recon reveals JWT in cookies or Authorization headers.

## How to Use
This is a **virtual skill** — uses nuclei with JWT-specific tags.
Run nuclei with `--tags jwt,token` to detect JWT issues.

## Parameters
- Use nuclei with `tags: "jwt,token"`
- `target`: URL that uses JWT authentication

## Output Interpretation
- Algorithm: none accepted = CRITICAL (bypass authentication entirely)
- Algorithm confusion (RS256→HS256) = CRITICAL
- Weak secret (easily brute-forced) = HIGH
- Missing expiration = MEDIUM
- No key rotation = LOW

## Best Practices
- Check Authorization: Bearer headers for JWT format
- Test algorithm substitution (alg: none, alg: HS256 with RS256 public key)
- If JWT secret is weak, try common passwords: secret, password, 123456
- Check if expired tokens are still accepted

---
name: cors_check
category: scanner
binary_name: nuclei
virtual: true
---

# CORS Misconfiguration Testing

## When to Use
Test for Cross-Origin Resource Sharing (CORS) misconfigurations on ALL web targets.
Overly permissive CORS headers can allow cross-site data theft.
Run this during the scanning phase alongside regular nuclei scans.

## How to Use
This is a **virtual skill** — it uses nuclei with specific tags.
Run nuclei with `--tags cors` to check for CORS issues.

## Parameters
- Use nuclei with `tags: "cors"`
- `target`: URL to test

## Output Interpretation
- `Access-Control-Allow-Origin: *` = permissive (medium severity)
- `Access-Control-Allow-Origin: attacker.com` (reflected) = critical
- `Access-Control-Allow-Credentials: true` with wildcard = critical
- No CORS headers = not vulnerable (but may break functionality)

## Best Practices
- Always test CORS on API endpoints
- Check if credentials flag is set with wildcard origin
- Test with custom Origin header to check for reflection

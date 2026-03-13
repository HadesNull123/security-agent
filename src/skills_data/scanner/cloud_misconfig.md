---
name: cloud_misconfig
category: scanner
binary_name: nuclei
virtual: true
---

# Cloud Misconfiguration Detection

## When to Use
Detect misconfigured cloud storage and services:
- Public S3 buckets
- Exposed Google Cloud Storage
- Azure Blob storage misconfiguration
- Cloud metadata endpoints accessible via SSRF
Run during normal/deep scans for all web targets.

## How to Use
This is a **virtual skill** — uses nuclei with cloud-specific tags.
Run nuclei with `--tags cloud,aws,s3,gcloud,azure` to detect cloud issues.

## Parameters
- Use nuclei with `tags: "cloud,aws,s3,gcloud,azure,misconfig"`
- `target`: URL to test

## Output Interpretation
- Public S3 bucket with listing = HIGH (data exposure)
- Public S3 bucket with write access = CRITICAL
- Cloud metadata accessible (169.254.169.254) = CRITICAL
- Exposed .env or config files with cloud credentials = CRITICAL
- Firebase/Firestore rules misconfigured = HIGH

## Best Practices
- Check for S3 bucket names in JavaScript files and HTML source
- Test bucket URLs: https://s3.amazonaws.com/[company-name]
- Check for exposed cloud credentials in /env, /config, /debug endpoints
- Test cloud metadata endpoint via any SSRF vulnerabilities found

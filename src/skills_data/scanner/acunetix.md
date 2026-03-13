---
name: acunetix
category: scanner
binary_name: acunetix
api_tool: true
---

# Acunetix — Enterprise Web Vulnerability Scanner

## When to Use
Run when Acunetix API is configured. Enterprise-grade web vulnerability scanner with DAST capabilities.

## How to Use
Acunetix is controlled via REST API. Requires API key in config.

## API Endpoints
```
BASE URL: https://<acunetix-host>:3443/api/v1

TARGETS:
   POST   /targets                    add new target
   GET    /targets                    list all targets
   GET    /targets/{id}               get target details
   PATCH  /targets/{id}               update target
   DELETE /targets/{id}               delete target

SCANS:
   POST   /scans                      start new scan
   GET    /scans                      list all scans
   GET    /scans/{id}                 get scan status
   DELETE /scans/{id}                 stop/delete scan
   POST   /scans/{id}/abort           abort scan

SCAN PROFILES (profile_id for POST /scans):
   11111111-1111-1111-1111-111111111111  Full Scan
   11111111-1111-1111-1111-111111111112  High Risk Vulnerabilities
   11111111-1111-1111-1111-111111111116  Cross-site Scripting
   11111111-1111-1111-1111-111111111113  SQL Injection
   11111111-1111-1111-1111-111111111115  Weak Passwords
   11111111-1111-1111-1111-111111111117  Crawl Only
   11111111-1111-1111-1111-111111111120  Malware Scan

VULNERABILITIES:
   GET    /vulnerabilities             list all vulnerabilities
   GET    /vulnerabilities/{id}        get vulnerability details

REPORTS:
   POST   /reports                     generate report
   GET    /reports                     list reports
   GET    /reports/{id}                get report
   GET    /reports/download/{id}       download report

REPORT TEMPLATES (for POST /reports):
   11111111-1111-1111-1111-111111111111  Developer Report
   11111111-1111-1111-1111-111111111112  Executive Summary
   11111111-1111-1111-1111-111111111113  Quick Report
   11111111-1111-1111-1111-111111111119  OWASP Top 10

API AUTH:
   Header: X-Auth: <api_key>
```

## Example API Calls
```bash
# Add target
curl -k -H "X-Auth: API_KEY" -H "Content-Type: application/json" \
  -d '{"address":"https://example.com","description":"test"}' \
  https://acunetix:3443/api/v1/targets

# Start full scan
curl -k -H "X-Auth: API_KEY" -H "Content-Type: application/json" \
  -d '{"target_id":"TARGET_ID","profile_id":"11111111-1111-1111-1111-111111111111"}' \
  https://acunetix:3443/api/v1/scans

# Check scan status
curl -k -H "X-Auth: API_KEY" \
  https://acunetix:3443/api/v1/scans/SCAN_ID

# Get vulnerabilities
curl -k -H "X-Auth: API_KEY" \
  "https://acunetix:3443/api/v1/vulnerabilities?q=severity:3"

# Generate report
curl -k -H "X-Auth: API_KEY" -H "Content-Type: application/json" \
  -d '{"template_id":"11111111-1111-1111-1111-111111111111","source":{"list_type":"scans","id_list":["SCAN_ID"]}}' \
  https://acunetix:3443/api/v1/reports
```

## Output Interpretation
- Severity 3 = High, 2 = Medium, 1 = Low, 0 = Informational
- Confidence field indicates detection accuracy
- CWE/CVE references link to specific weaknesses

## Best Practices
- Use Full Scan profile for comprehensive testing
- Use High Risk profile for quick assessment
- Check scan status periodically (polling)
- Download report after scan completes

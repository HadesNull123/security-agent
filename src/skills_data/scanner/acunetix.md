---
name: acunetix
category: scanner
binary_name: acunetix
api_tool: true
requires_config: true
---

# Acunetix — Enterprise Web Vulnerability Scanner

## When to Use
Run when Acunetix API is configured. Enterprise-grade web vulnerability scanner with DAST capabilities.
Best for comprehensive web app scanning with JavaScript rendering support.

## How to Use
Acunetix is controlled via REST API. Requires `api_url` and `api_key` in config.

Call with: `acunetix(target="https://example.com", profile="full")`

Profiles: `full`, `high_risk`, `xss`, `sqli`, `weak_passwords`, `crawl_only`, `malware`

## API Endpoints
```
BASE URL: https://<acunetix-host>:3443/api/v1
AUTH: Header X-Auth: <api_key>

TARGETS:
   POST   /targets                                add target  {address, description, criticality}
   GET    /targets                                list targets
   GET    /targets/{id}                           get target
   PATCH  /targets/{id}                           update target
   DELETE /targets/{id}                           delete target
   GET    /targets/{id}/configuration              get target config (auth, exclusions)
   PATCH  /targets/{id}/configuration              update config (set login, crawl scope)

SCANS:
   POST   /scans                                  schedule scan {target_id, profile_id, schedule}
   GET    /scans                                  list scans
   GET    /scans/{id}                             get scan detail + current_session.status
   DELETE /scans/{id}                             delete scan
   POST   /scans/{id}/abort                       abort running scan
   POST   /scans/{id}/resume                      resume paused scan
   GET    /scans/{id}/results                     list scan result sessions

SCAN RESULTS:
   GET    /results/{result_id}                     get scan result properties
   GET    /scans/{scan_id}/results/{result_id}/vulnerabilities   list vulns in result
   GET    /scans/{scan_id}/results/{result_id}/vulnerabilities/{vuln_id}   vuln detail

VULNERABILITIES:
   GET    /vulnerabilities                         list ALL vulnerabilities (across scans)
   GET    /vulnerabilities/{vuln_id}               get single vuln detail
   GET    /scan_vulnerabilities/{vuln_id}          get vuln detail (without scan_id/result_id)
   GET    /targets/{id}/technologies               list technologies found
   GET    /targets/{id}/technologies/{tech_id}/vulnerabilities   vulns per technology

REPORTS:
   GET    /report_templates                        list report templates
   POST   /reports                                 generate report {template_id, source}
   GET    /reports                                 list reports
   GET    /reports/{id}                            get report status
   GET    /reports/download/{descriptor}            download report file

SCAN PROFILE UUIDs:
   11111111-1111-1111-1111-111111111111  Full Scan
   11111111-1111-1111-1111-111111111112  High Risk Vulnerabilities
   11111111-1111-1111-1111-111111111113  SQL Injection
   11111111-1111-1111-1111-111111111115  Weak Passwords
   11111111-1111-1111-1111-111111111116  Cross-site Scripting (XSS)
   11111111-1111-1111-1111-111111111117  Crawl Only
   11111111-1111-1111-1111-111111111120  Malware Scan

REPORT TEMPLATE UUIDs:
   11111111-1111-1111-1111-111111111111  Developer Report
   11111111-1111-1111-1111-111111111112  Executive Summary
   11111111-1111-1111-1111-111111111113  Quick Report
   11111111-1111-1111-1111-111111111119  OWASP Top 10
```

## Detailed API Workflow

### Step 1: Add Target
```bash
POST /api/v1/targets
Body: {"address": "https://example.com", "description": "Security scan", "criticality": 10}
Response: {"target_id": "uuid-here", ...}
```

### Step 2: Configure Target (Optional)
```bash
PATCH /api/v1/targets/{target_id}/configuration
Body: {
  "login": {"kind": "automatic", "credentials": {"enabled": true, "username": "user", "password": "pass"}},
  "authentication": {"enabled": true, "username": "user", "password": "pass"},
  "proxy": {"enabled": false},
  "scan_speed": "fast"
}
```

### Step 3: Schedule Scan
```bash
POST /api/v1/scans
Body: {
  "target_id": "uuid",
  "profile_id": "11111111-1111-1111-1111-111111111111",
  "schedule": {"disable": false, "start_date": null, "time_sensitive": false}
}
Response Header: Location: /api/v1/scans/{scan_id}
```

### Step 4: Poll Scan Status
```bash
GET /api/v1/scans/{scan_id}
Response: {
  "current_session": {
    "status": "completed|scanning|queued|failed|aborted",
    "progress": 85,
    "scan_session_id": "result_id",
    "severity_counts": {"high": 2, "medium": 5, "low": 3, "info": 10}
  }
}
```
Status values: `queued`, `starting`, `scanning`, `processing`, `completed`, `failed`, `aborted`

### Step 5: Get Vulnerabilities
```bash
GET /api/v1/scans/{scan_id}/results/{result_id}/vulnerabilities?l=100
Response: {
  "vulnerabilities": [
    {
      "vuln_id": "uuid",
      "severity": 3,           // 0=info, 1=low, 2=medium, 3=high, 4=critical (if applicable)
      "vt_name": "SQL Injection",
      "affects_url": "/login",
      "affects_detail": "parameter: username",
      "confidence": 100,
      "status": "open"
    }
  ]
}
```

### Step 6: Get Vulnerability Detail
```bash
GET /api/v1/vulnerabilities/{vuln_id}
Response: {
  "vuln_id": "uuid",
  "severity": 3,
  "vt_name": "SQL Injection",
  "description": "Detailed description...",
  "impact": "An attacker can...",
  "recommendation": "Use parameterized queries...",
  "affects_url": "/login",
  "request": "GET /login?user=...",
  "response_info": "HTTP/1.1 200 OK...",
  "references": [{"href": "https://cwe.mitre.org/data/definitions/89.html", "rel": "CWE-89"}],
  "tags": ["sqli", "owasp-top-10"],
  "cvss_score": 9.8,
  "cvss3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}
```

### Step 7: Generate Report (Optional)
```bash
POST /api/v1/reports
Body: {
  "template_id": "11111111-1111-1111-1111-111111111111",
  "source": {"list_type": "scans", "id_list": ["{scan_id}"]}
}
Response: {"report_id": "uuid", "status": "generating", "download": ["/api/v1/reports/download/descriptor"]}
```

## Output Interpretation
- Severity: 4=Critical, 3=High, 2=Medium, 1=Low, 0=Informational
- Confidence: 0-100 (100 = certain)
- Each vulnerability detail includes description, impact, recommendation, CVSS, and references
- CWE/CVE references link to specific weaknesses

## Best Practices
- Use `high_risk` profile for quick assessment first, then `full` for comprehensive results
- Check scan status periodically (tool polls every 5s, max 30min timeout)
- After scan, tool auto-fetches vulnerability details (description, impact, recommendation, CVSS)
- Use `crawl_only` to map the attack surface without testing vulnerabilities
- Download Acunetix report for additional detail after scan completes
- Always ensure target is in authorized scope before scanning

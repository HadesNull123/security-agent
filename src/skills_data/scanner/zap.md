---
name: zap
category: scanner
binary_name: zap-cli
api_tool: true
---

# OWASP ZAP — Web Application Security Scanner

## When to Use
Run for automated web application scanning. ZAP combines spidering, active scanning, and passive analysis. Requires ZAP daemon running or API access.

## How to Use
```
# ZAP can be controlled via:
# 1. zap-cli (Python CLI wrapper)
# 2. ZAP API (REST)
# 3. zap.sh (direct)
```

## CLI Flags (zap-cli)
```
COMMANDS:
   quick-scan URL          quick scan URL
   active-scan URL         active scan URL
   spider URL              spider URL
   ajax-spider URL         AJAX spider URL
   open-url URL            open URL in ZAP
   alerts                  list all alerts
   report                  generate report
   start                   start ZAP daemon
   shutdown                shutdown ZAP daemon
   status                  show ZAP status
   exclude URL_REGEX       exclude URLs from scope
   policies                list scan policies
   scanners                list scanners

OPTIONS:
   -p, --port PORT        ZAP proxy port (default 8080)
   --zap-url URL          ZAP API URL
   --api-key KEY          API key for ZAP
   -l, --log-level LEVEL  log level (DEBUG,INFO,WARNING,ERROR)
   -o, --output FORMAT    output format (json, html, xml, md)

ZAP.SH FLAGS:
   -daemon                run as daemon (headless)
   -host HOST             listen host
   -port PORT             listen port
   -config KEY=VALUE      override config (can be repeated)
   -addoninstall NAME     install add-on
   -addonupdate           update all add-ons
   -quickurl URL          URL to scan
   -quickprogress         show progress during quick scan
   -quickout FILE         output file for quick scan

ZAP API ENDPOINTS:
   /JSON/core/action/accessUrl/  open URL
   /JSON/spider/action/scan/     start spider
   /JSON/ascan/action/scan/      start active scan
   /JSON/core/view/alerts/       get alerts
   /JSON/reports/action/generate/ generate report
```

## Example Commands
```bash
# Start ZAP daemon
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.key=your-api-key

# Quick scan via CLI
zap-cli --api-key YOUR_KEY quick-scan -s all http://example.com

# Spider then active scan
zap-cli --api-key YOUR_KEY spider http://example.com
zap-cli --api-key YOUR_KEY active-scan http://example.com

# Get alerts
zap-cli --api-key YOUR_KEY alerts -l Medium

# Generate report
zap-cli --api-key YOUR_KEY report -o report.html -f html

# Via API (curl)
curl "http://localhost:8080/JSON/spider/action/scan/?apikey=KEY&url=http://target.com"
```

## Output Interpretation
- Alert risk: High/Medium/Low/Informational
- Confidence: User Confirmed/High/Medium/Low/False Positive
- CWE IDs reference specific weakness types

## Best Practices
- Start ZAP in daemon mode for automated scanning
- Use API key for authentication
- Spider before active scanning for better coverage
- Use `-config api.disablekey=true` in Docker only

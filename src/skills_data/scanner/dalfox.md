---
name: dalfox
category: scanner
binary_name: dalfox
---

# Dalfox — XSS Vulnerability Scanner

Dalfox is a powerful open-source tool focused on automation for quickly scanning XSS flaws and analyzing parameters. Supports reflected, stored, and DOM-based XSS with optimization and DOM/headless verification.

## When to Use
Run during scanning phase to detect XSS vulnerabilities. Especially effective when target has URL parameters or form inputs. More thorough than nuclei for XSS-specific testing.

Key features:
- **Modes**: URL, SXSS, Pipe, File, Server, Payload
- **Discovery**: Parameter analysis, static analysis, BAV testing, parameter mining
- **XSS Scanning**: Reflected, Stored, DOM-based, with optimization and DOM/headless verification
- **HTTP Options**: Custom headers, cookies, methods, proxy, and more
- **Output**: JSON/Plain formats, silence mode, detailed reports
- **Extensibility**: REST API, custom payloads, remote wordlists

## How to Use
```
dalfox [mode] [target] [flags]
```

### Modes
- `url` — Scan a single URL
- `sxss` — Scan for stored XSS (requires callback URL)
- `pipe` — Read URLs from stdin (pipeline mode)
- `file` — Read URLs from a file
- `server` — Start REST API server
- `payload` — Generate/test payloads

## CLI Flags
```
TARGET:
  -u, --url             Target URL to scan
  -b, --blind           Blind XSS callback URL (e.g. your BurpCollaborator)
  -p, --param           Specific parameter to test
  --custom-payload      Custom payload file path
  --remote-payloads     Remote payload sources (portswigger, payloadbox)

SCANNING:
  --mining-dom          Enable DOM-based parameter mining (default: true)
  --mining-dict         Enable dictionary-based parameter mining
  --deep-domxss         Deep DOM XSS scanning
  -w, --worker          Number of concurrent workers (default: 10)
  --follow-redirects    Follow HTTP redirects
  --skip-bav            Skip BAV (Basic Another Vulnerability) testing
  --only-discovery      Only perform parameter discovery, no XSS scanning

HTTP OPTIONS:
  -H, --header          Custom headers (repeatable)
  --cookie              Cookie string
  -X, --method          HTTP method (default: GET)
  --data                POST request body data
  -x, --proxy           Proxy URL
  --timeout             Request timeout in seconds (default: 10)
  --delay               Delay between requests in ms

OUTPUT:
  --format              Output format: json, plain (default: plain)
  -o, --output          Output file path
  --silence             Silence mode (only show results)
  --no-color            Disable color output
  --report              Generate report (HTML format)
```

## Example Commands
```bash
# Single URL scan
dalfox url "http://example.com/search?q=test"

# Scan with blind XSS callback
dalfox url "http://example.com" -b "https://your-callback-server"

# Scan with custom headers + cookie
dalfox url "http://example.com" -H "Authorization: Bearer xxx" --cookie "session=abc"

# File mode — scan multiple URLs
dalfox file urls.txt --custom-payload mypayloads.txt

# Pipeline mode — chain with other tools
cat urls.txt | dalfox pipe -H "AuthToken: xxx"
katana -u https://example.com | dalfox pipe

# JSON output for parsing
dalfox url "http://example.com/page?id=1" --format json -o results.json

# Specific parameter testing
dalfox url "http://example.com/page?id=1&name=test" -p id

# Stored XSS mode
dalfox sxss "http://example.com/comment" -b "https://callback"
```

## Parameters
- `target` (required): URL to scan, ideally with query parameters (e.g. http://example.com/search?q=test)
- `param`: Specific parameter to test (e.g. "q")
- `blind_url`: Blind XSS callback URL for out-of-band detection
- `headers`: Custom headers separated by semicolons (e.g. "Authorization: Bearer xxx; Cookie: session=abc")
- `cookie`: Cookie string for authenticated scanning
- `workers`: Number of concurrent workers (default: 10)
- `timeout`: Request timeout in seconds (default: 10)
- `delay`: Delay between requests in ms (optional, for rate limiting)

## Output Interpretation
- `type: reflected` = reflected XSS (high severity)
- `type: stored` = stored XSS (critical severity)
- `type: dom` = DOM-based XSS (high severity)
- `poc` = proof-of-concept URL demonstrating the XSS
- `payload` = the XSS payload that triggered the vulnerability

## Best Practices
- Feed URLs with parameters from katana/httpx crawl results
- Use with authenticated sessions for deeper coverage
- For blind XSS, provide a callback URL (`blind_url`)
- Focus on endpoints that accept user input (search, comment, profile fields)
- Run after nuclei to catch XSS that nuclei templates miss
- Use `--mining-dom` for automatic DOM parameter discovery
- Pipeline mode works great: `katana -u target | dalfox pipe`

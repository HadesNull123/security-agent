---
name: crlfuzz
category: scanner
binary_name: crlfuzz
---

# CRLFuzz — CRLF Injection Scanner

A fast tool to scan CRLF vulnerability written in Go. Tests for HTTP response splitting via header injection.

## When to Use
Run during scanning phase to detect CRLF injection (HTTP response splitting) vulnerabilities. CRLF allows attackers to inject headers, enabling cache poisoning, XSS via injected headers, and session fixation.

## How to Use
```
crlfuzz [flags]
```

## CLI Flags
```
Flag              Description
-u, --url         Define single URL to fuzz
-l, --list        Fuzz URLs within file
-X, --method      Specify request method to use (default: GET)
-o, --output      File to save results
-d, --data        Define request data
-H, --header      Pass custom header to target (repeatable)
-x, --proxy       Use specified proxy to fuzz
-c, --concurrent  Set the concurrency level (default: 25)
-s, --silent      Silent mode (only show vulnerable URLs)
-v, --verbose     Verbose mode (show error details)
-V, --version     Show current CRLFuzz version
-h, --help        Display help
```

### Target Input
3 ways to provide targets:

**Single URL:**
```bash
crlfuzz -u "http://target"
```

**URLs from file:**
```bash
crlfuzz -l /path/to/urls.txt
```

**From stdin (pipeline):**
```bash
subfinder -d target -silent | httpx -silent | crlfuzz
```

## Example Commands
```bash
# Basic single URL scan
crlfuzz -u "http://example.com"

# Silent mode — only show vulnerable URLs
crlfuzz -u "http://example.com" -s

# POST method with data
crlfuzz -u "http://example.com" -X "POST" -d "data=body"

# Custom headers (cookies, auth)
crlfuzz -u "http://example.com" -H "Cookie: session=abc" -H "User-Agent: Mozilla/5.0"

# Scan from file with output
crlfuzz -l /path/to/urls.txt -o /path/to/results.txt

# Pipeline mode — chain with recon tools
subfinder -d example.com -silent | httpx -silent | crlfuzz -s

# High concurrency scan
crlfuzz -l /path/to/urls.txt -c 50

# Silent + save only vulnerable URLs
crlfuzz -l /path/to/urls.txt -s | tee vuln-urls.txt

# Using proxy
crlfuzz -u "http://example.com" -x http://127.0.0.1:8080

# Verbose mode (debug errors)
crlfuzz -l /path/to/urls.txt -v
```

## Parameters
- `target` (required): URL to test for CRLF injection
- `method`: HTTP method to use (default: GET). Use POST for form targets
- `data`: POST body data (use with method=POST)
- `headers`: Custom headers separated by semicolons (e.g. "Cookie: session=abc")
- `concurrency`: Number of concurrent tests (default: 25)

## Output Interpretation
- Any URL in output = confirmed CRLF injection vulnerability
- Silent mode (`-s`): only vulnerable URLs are shown
- CRLF injection severity is typically "medium" but can escalate to "high" if combined with cache poisoning or XSS

## Best Practices
- Test all discovered endpoints from recon phase
- Focus on redirect endpoints and URLs with query parameters
- Test both GET and POST methods
- CRLF is often found in redirect parameters (?url=, ?redirect=, ?next=)
- Combine findings with cache poisoning analysis for higher impact
- Pipeline mode is very effective: pipe URLs from katana/httpx directly
- Use `-s` (silent) for clean output of only vulnerable URLs

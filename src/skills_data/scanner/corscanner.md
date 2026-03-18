---
name: corscanner
category: scanner
binary_name: cors
---

# CORScanner — CORS Misconfiguration Scanner

Fast CORS misconfiguration vulnerabilities scanner. Can be used via `cors` or `corscanner` command after `pip install corscanner`.

## When to Use
Run during scanning phase to detect CORS misconfigurations. More thorough than nuclei CORS templates — tests 10+ misconfiguration types including origin reflection, prefix/suffix match, null trust, subdomain trust, and special character bypass.

## How to Use
```
cors [flags]
```

## CLI Flags
```
Flag              Description
-u, --url         URL/domain to check its CORS policy
-d, --headers     Add headers to the request (e.g. "Cookie: test")
-i, --input       URL/domain list file to check their CORS policy
-t, --threads     Number of threads to use for CORS scan (default: 50)
-o, --output      Save the results to JSON file
-v, --verbose     Enable verbose mode and display results in realtime
-T, --timeout     Set requests timeout (default: 10 sec)
-p, --proxy       Enable proxy (http or socks5)
-h, --help        Show the help message and exit
```

## Example Commands
```bash
# Check CORS of specific domain
cors -u example.com

# Verbose mode (realtime results)
cors -vu example.com

# Save results to JSON file
cors -u example.com -o output_filename

# Check specific URL/endpoint
cors -u http://example.com/restapi

# With custom headers (cookies, auth)
cors -u example.com -d "Cookie: test"

# Scan multiple domains from file
cors -i top_100_domains.txt -t 100

# Using HTTP proxy
cors -u example.com -p http://127.0.0.1:8080

# Using SOCKS5 proxy
cors -u example.com -p socks5://127.0.0.1:8080
```

## Misconfiguration Types Detected
```
Type                        Severity    Description
─────────────────────────────────────────────────────────────────────
Reflect_any_origin          CRITICAL    Blindly reflects Origin header → any website can steal secrets
Prefix_match                HIGH        Trusts evil-example.com (attacker prefix)
Suffix_match                HIGH        Trusts evilexample.com (attacker suffix)
Not_escape_dot              HIGH        Trusts exampleXcom (dot not escaped in regex)
Substring_match             HIGH        Trusts example.co (substring match)
Trust_null                  HIGH        Trusts null origin → exploitable via iframe sandbox
HTTPS_trust_HTTP            MEDIUM      HTTPS site trusts HTTP origin → MITM can steal secrets
Trust_any_subdomain         MEDIUM      Any subdomain trusted → XSS on subdomain = full bypass
Custom_third_parties        LOW         Trusts unsafe third-parties like github.io
Special_characters_bypass   HIGH        Exploits browser handling of special chars (Safari/Chrome/Firefox)
```

## Parameters
- `target` (required): Domain or URL to check (e.g. example.com or https://api.example.com/endpoint)
- `headers`: Custom headers (e.g. "Cookie: session=abc")
- `threads`: Number of threads (default: 50)

## Output Interpretation
- `Reflect_any_origin` + credentials=true = **CRITICAL** (full account takeover)
- `Reflect_any_origin` = **HIGH** (server reflects any Origin)
- `Trust_null` = **HIGH** (exploitable via sandboxed iframes)
- `Prefix_match` / `Suffix_match` = **HIGH** (attacker can register matching domain)
- `Not_escape_dot` / `Substring_match` = **HIGH** (regex bypass)
- `Trust_any_subdomain` = **MEDIUM** (subdomain XSS = full CORS bypass)
- `HTTPS_trust_HTTP` = **MEDIUM** (MITM risk)
- `Custom_third_parties` = **LOW** (github.io etc)
- `Special_characters_bypass` = **HIGH** (browser-specific bypass)

## Best Practices
- Always run on API endpoints — CORS issues are critical for APIs
- Check both the main domain and API subdomains
- Pay special attention to endpoints that return sensitive data
- `Reflect_any_origin` + credentials is the most dangerous combination
- Test authenticated endpoints with Cookie headers for full coverage
- Use `-v` flag for realtime verbose output
- Save results with `-o` for JSON report integration

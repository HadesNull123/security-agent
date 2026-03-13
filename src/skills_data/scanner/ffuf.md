---
name: ffuf
category: scanner
binary_name: ffuf
---

# ffuf — Fuzz Faster U Fool

## When to Use
Use for directory/file discovery, virtual host discovery, parameter fuzzing, and any web content fuzzing. Place `FUZZ` keyword in the position to fuzz.

## How to Use
```
ffuf [flags]
```

## CLI Flags
```
HTTP OPTIONS:
   -H              Header "Name: Value" (multiple -H accepted)
   -X              HTTP method to use
   -b              Cookie data "NAME1=VALUE1; NAME2=VALUE2"
   -d              POST data
   -http2          use HTTP2 (default: false)
   -r              follow redirects (default: false)
   -recursion      scan recursively (FUZZ keyword, URL must end with it)
   -recursion-depth  max recursion depth (default: 0)
   -replay-proxy     replay matched requests using proxy
   -timeout          HTTP timeout seconds (default: 10)
   -u              target URL (use FUZZ keyword for fuzz position)
   -x              proxy URL (SOCKS5 or HTTP)

GENERAL OPTIONS:
   -ac             auto-calibrate filtering (default: false)
   -ach            per-host autocalibration
   -c              colorize output
   -json           JSON output (newline-delimited)
   -maxtime        max total runtime seconds (default: 0)
   -maxtime-job    max runtime per job seconds (default: 0)
   -noninteractive disable interactive console
   -p              delay between requests ("0.1" or "0.1-2.0")
   -rate           requests per second (default: 0 = unlimited)
   -s              silent mode
   -se             stop on spurious errors
   -sf             stop when >95% responses are 403
   -t              concurrent threads (default: 40)
   -v              verbose output (full URL + redirect location)

MATCHER OPTIONS:
   -mc             match status codes (default: 200-299,301,302,307,401,403,405,500)
   -ml             match line count
   -mr             match regex
   -ms             match response size
   -mt             match response time (">100" or "<100" ms)
   -mw             match word count

FILTER OPTIONS:
   -fc             filter status codes (comma-separated)
   -fl             filter line count
   -fr             filter regex
   -fs             filter response size
   -ft             filter response time
   -fw             filter word count

INPUT OPTIONS:
   -e              extensions (comma-separated, extends FUZZ)
   -ic             ignore wordlist comments
   -mode           multi-wordlist mode (clusterbomb, pitchfork, sniper)
   -request        file containing raw HTTP request
   -w              wordlist path (optional keyword: /path:KEYWORD)

OUTPUT OPTIONS:
   -o              output file
   -of             output format (json, ejson, html, md, csv, ecsv, all)
   -od             directory for matched results
   -or             don't create output if no results
```

## Example Commands
```bash
# Directory discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://example.com/FUZZ -mc all -fc 404 -c

# Directory discovery with extensions
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://example.com/FUZZ -e .php,.html,.js,.txt,.bak -mc 200,301,302,403

# Virtual host discovery
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u https://example.com/ -H "Host: FUZZ.example.com" -mc 200 -fs 0

# Parameter fuzzing (GET)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u https://example.com/page?FUZZ=value -mc 200

# POST data fuzzing
ffuf -w wordlist.txt -u https://example.com/login -X POST -d "user=admin&pass=FUZZ" -fc 401

# Auto-calibrate filtering
ffuf -w common.txt -u https://example.com/FUZZ -ac -c

# JSON output
ffuf -w common.txt -u https://example.com/FUZZ -o results.json -of json -s
```

## Output Interpretation
- Status 200 = resource found
- Status 301/302 = redirect (may be interesting)
- Status 403 = exists but forbidden (try bypass techniques)
- Status 500 = server error (potential vulnerability)
- Use `-fs` to filter common false-positive sizes

## Best Practices
- Always use `-ac` (auto-calibrate) for initial scans
- Use `-fc 404` to filter not-found responses
- Use `-mc all -fc 404` for broadest coverage
- Use `-rate` or `-p` to avoid WAF detection
- JSON output (`-of json`) for automated parsing

---
name: nikto
category: scanner
binary_name: nikto
---

# Nikto — Web Server Vulnerability Scanner

## When to Use
Run to detect outdated software, dangerous files, misconfigurations, and default installations. Catches issues nuclei may miss (especially legacy/obscure vulnerabilities).

## How to Use
```
nikto [options]
```

## CLI Flags
```
TARGET:
   -h, -host HOST         target host (host, IP, hostname, or URL)
   -p, -port PORT         port(s) to scan (default 80, comma-separated)
   -ssl                   force SSL mode on port
   -nossl                 disable SSL mode
   -vhost HOSTNAME        virtual host (Host header value)

TUNING:
   -Tuning TUNE           scan tuning (comma-separated):
                          1 = Interesting File / Seen in logs
                          2 = Misconfiguration / Default File
                          3 = Information Disclosure
                          4 = Injection (XSS/Script/HTML)
                          5 = Remote File Retrieval - Inside Web Root
                          6 = Denial of Service (not tested by default)
                          7 = Remote File Retrieval - Server Wide
                          8 = Command Execution / Remote Shell
                          9 = SQL Injection
                          0 = File Upload
                          a = Authentication Bypass
                          b = Software Identification
                          c = Remote Source Inclusion
                          x = Reverse Tuning (exclude types)

AUTHENTICATION:
   -id USER:PASS          HTTP basic auth credentials
   -id+ USER:PASS:REALM   HTTP basic auth with realm

PROXY:
   -useproxy URL          use HTTP proxy
   -useragent STRING      custom User-Agent

OUTPUT:
   -o, -output FILE       output file
   -Format FORMAT         output format (csv, htm, json, nbe, sql, txt, xml)
   -Display DISPLAY       control output display:
                          1 = Show redirects
                          2 = Show cookies received
                          3 = Show all 200/OK responses
                          4 = Show URLs requiring authentication
                          D = Debug output
                          E = Display all HTTP errors
                          P = Print progress
                          S = Scrub output of IPs and hostnames
                          V = Verbose output

CONFIGURATION:
   -config FILE           config file path
   -dbcheck               check database syntax
   -Plugins PLUGINS       plugins to run (default "ALL")
   -list-plugins          list all available plugins
   -evasion TECHNIQUE     IDS evasion techniques:
                          1 = Random URI encoding (non-UTF8)
                          2 = Directory self-reference (/.)
                          3 = Premature URL ending
                          4 = Prepend long random string
                          5 = Fake parameter
                          6 = TAB as request spacer
                          7 = Change URL case
                          8 = Use Windows directory separator (\)
                          A = Use carriage return
                          B = Use binary value
   -maxtime SECONDS       max scan time per host
   -timeout SECONDS       request timeout (default 10)
   -Pause SECONDS         delay between tests
   -no404                 disable 404 guessing
   -nolookup              skip DNS lookup
   -nointeractive         disable interactive features
   -update                update databases and plugins

DEBUG:
   -Version               display version
   -v                     verbose mode
```

## Example Commands
```bash
# Basic scan
nikto -h https://example.com

# Scan with JSON output
nikto -h https://example.com -Format json -o nikto.json

# Scan specific port
nikto -h example.com -p 8080

# Scan with tuning (misconfig + info disclosure)
nikto -h https://example.com -Tuning 2,3

# Multiple ports
nikto -h example.com -p 80,443,8080,8443

# Full scan with all tuning options
nikto -h https://example.com -Tuning 1234567890abc

# With evasion techniques
nikto -h https://example.com -evasion 1,2,4

# With timeout
nikto -h https://example.com -maxtime 300 -timeout 15
```

## Output Interpretation
- OSVDB references link to known vulnerability database entries
- "Server" line reveals server software version
- "+" prefix items are potential findings
- Items without "+" are informational

## Best Practices
- Use `-Format json` for automated parsing
- Use `-Tuning 2,3` for focused misconfig/disclosure scan
- Use `-maxtime` to prevent long-running scans
- Combine with nuclei for comprehensive coverage

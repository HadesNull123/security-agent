---
name: httpx
category: recon
binary_name: httpx
---

# httpx — HTTP Probing & Technology Detection

## When to Use
Run after subfinder/naabu to probe live HTTP services, detect technologies, grab titles, and check status codes.

## How to Use
```
httpx [flags]
```

## CLI Flags
```
INPUT:
   -l, -list string       file containing hosts to process
   -u, -target string[]   input target host(s) to probe

PROBES:
   -sc, -status-code      display response status-code
   -cl, -content-length   display content-length
   -ct, -content-type     display content-type
   -location              display redirect location
   -favicon               display mmh3 hash for /favicon.ico
   -hash string           display body hash (md5,mmh3,sha1,sha256,sha512)
   -jarm                  display JARM fingerprint hash
   -rt, -response-time    display response time
   -title                 display page title
   -bp, -body-preview     display first N chars of body (default 100)
   -server, -web-server   display server name
   -td, -tech-detect      detect technology (wappalyzer dataset)
   -method                display HTTP method
   -ip                    display host IP
   -cname                 display host CNAME
   -asn                   display host ASN
   -cdn                   display CDN/WAF in use

MATCHERS:
   -mc, -match-code string    match status code (-mc 200,302)
   -ml, -match-length string  match content length
   -ms, -match-string string  match response string
   -mr, -match-regex string   match response regex

FILTERS:
   -fc, -filter-code string   filter status code (-fc 403,401)
   -fl, -filter-length string filter content length
   -fs, -filter-string string filter response string
   -fe, -filter-regex string  filter response regex
   -fep, -filter-error-page   ML-based error page detection

RATE-LIMIT:
   -t, -threads int        concurrent threads (default 50)
   -rl, -rate-limit int    max requests/second (default 150)
   -rlm, -rate-limit-minute int  max requests/minute

MISCELLANEOUS:
   -pa, -probe-all-ips    probe all IPs for host
   -p, -ports string[]    ports to probe (eg http:1,2-10,https:80)
   -path string           path(s) to probe (comma-separated or file)
   -tls-probe             probe TLS domains
   -tls-grab              grab TLS/SSL data
   -pipeline              detect HTTP1.1 pipeline
   -http2                 detect HTTP2 support
   -vhost                 detect VHOST support

OUTPUT:
   -o, -output string     output file
   -j, -json              JSONL output
   -csv                   CSV output
   -irh, -include-response-header  include headers in JSON
   -irr, -include-response        include full request/response in JSON

CONFIGURATIONS:
   -r, -resolvers string[]    custom resolvers
   -H, -header string[]       custom headers
   -http-proxy, -proxy string  HTTP proxy
   -fr, -follow-redirects      follow redirects
   -maxr, -max-redirects int   max redirects (default 10)
   -timeout int                timeout seconds (default 10)
   -retries int                number of retries

DEBUG:
   -silent    display only results
   -v         verbose mode
```

## Example Commands
```bash
# Probe live hosts from subdomain list
subfinder -d example.com -silent | httpx -silent -sc -title -tech-detect

# Full probe with JSON output
httpx -u example.com -json -sc -title -td -server -ip -cdn -o httpx.json

# Probe specific ports
httpx -u example.com -ports 80,443,8080,8443 -sc -title

# Follow redirects and grab TLS info
httpx -u example.com -fr -tls-grab -json
```

## Output Interpretation
- Status codes: 200=live, 301/302=redirect, 403=forbidden, 404=not found
- Technologies detected reveal attack surface (e.g., WordPress → wpscan templates)
- CDN detection helps avoid scanning CDN IPs

## Best Practices
- Always use `-json` for structured output parsing
- Use `-td` (tech-detect) to identify technologies for targeted scanning
- Use `-sc -title` as minimum probes
- Pipe from subfinder: `subfinder -d target | httpx -silent`

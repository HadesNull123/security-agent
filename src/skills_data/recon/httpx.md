---
name: httpx
category: recon
binary_name: httpx
---

# httpx — HTTP Probing & Technology Detection

A fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library.

## When to Use
Run after subfinder/naabu to probe live HTTP services, detect technologies, grab titles, and check status codes.

## How to Use
```
httpx [flags]
```

## CLI Flags

### INPUT
```
-l, -list string              input file containing list of hosts to process
-rr, -request string          file containing raw request
-u, -target string[]          input target host(s) to probe
-im, -input-mode string       mode of input file (burp)
```

### PROBES
```
-sc, -status-code             display response status-code
-cl, -content-length          display response content-length
-ct, -content-type            display response content-type
-location                     display response redirect location
-favicon                      display mmh3 hash for '/favicon.ico' file
-hash string                  display response body hash (md5,mmh3,simhash,sha1,sha256,sha512)
-jarm                         display jarm fingerprint hash
-rt, -response-time           display response time
-lc, -line-count              display response body line count
-wc, -word-count              display response body word count
-title                        display page title
-bp, -body-preview            display first N characters of response body (default 100)
-server, -web-server          display server name
-td, -tech-detect             display technology in use based on wappalyzer dataset
-method                       display http request method
-ws, -websocket               display server using websocket
-ip                           display host ip
-cname                        display host cname
-extract-fqdn, -efqdn        get domain and subdomains from response body and header
-asn                          display host asn information
-cdn                          display cdn/waf in use (default true)
-probe                        display probe status
```

### HEADLESS
```
-ss, -screenshot              enable saving screenshot of the page using headless browser
-system-chrome                enable using local installed chrome for screenshot
-ho, -headless-options string[]  start headless chrome with additional options
-esb, -exclude-screenshot-bytes  exclude screenshot bytes from json output
-ehb, -exclude-headless-body  exclude headless header from json output
-st, -screenshot-timeout value  set timeout for screenshot (default 10s)
-jsc, -javascript-code string[]  execute JavaScript code after navigation
```

### MATCHERS
```
-mc, -match-code string       match response with specified status code (-mc 200,302)
-ml, -match-length string     match response with specified content length
-mlc, -match-line-count string  match response body with specified line count
-mwc, -match-word-count string  match response body with specified word count
-mfc, -match-favicon string[] match response with specified favicon hash
-ms, -match-string string[]   match response with specified string (-ms admin)
-mr, -match-regex string[]    match response with specified regex
-mcdn, -match-cdn string[]    match host with specified cdn provider
-mrt, -match-response-time string  match with specified response time (-mrt '< 1')
-mdc, -match-condition string match response with dsl expression condition
```

### EXTRACTOR
```
-er, -extract-regex string[]  display response content with matched regex
-ep, -extract-preset string[] display response content matched by pre-defined regex (url,ipv4,mail)
```

### FILTERS
```
-fc, -filter-code string      filter response with specified status code (-fc 403,401)
-fpt, -filter-page-type string[]  filter response with specified page type (login,captcha,parked)
-fd, -filter-duplicates       filter out near-duplicate responses
-fl, -filter-length string    filter response with specified content length
-flc, -filter-line-count string  filter response body with specified line count
-fwc, -filter-word-count string  filter response body with specified word count
-ffc, -filter-favicon string[]  filter response with specified favicon hash
-fs, -filter-string string[]  filter response with specified string
-fe, -filter-regex string[]   filter response with specified regex
-fcdn, -filter-cdn string[]   filter host with specified cdn provider
-frt, -filter-response-time string  filter with specified response time (-frt '> 1')
-fdc, -filter-condition string  filter response with dsl expression condition
-strip                        strips all tags in response (html,xml)
```

### RATE-LIMIT
```
-t, -threads int              number of threads to use (default 50)
-rl, -rate-limit int          maximum requests to send per second (default 150)
-rlm, -rate-limit-minute int  maximum requests to send per minute
```

### MISCELLANEOUS
```
-pa, -probe-all-ips           probe all the ips associated with same host
-p, -ports string[]           ports to probe (nmap syntax: eg http:1,2-10,11,https:80)
-path string                  path or list of paths to probe (comma-separated, file)
-tls-probe                    send http probes on the extracted TLS domains (dns_name)
-csp-probe                    send http probes on the extracted CSP domains
-tls-grab                     perform TLS(SSL) data grabbing
-pipeline                     probe and display server supporting HTTP1.1 pipeline
-http2                        probe and display server supporting HTTP2
-vhost                        probe and display server supporting VHOST
```

### OUTPUT
```
-o, -output string            file to write output results
-sr, -store-response          store http response to output directory
-srd, -store-response-dir string  store http response to custom directory
-ob, -omit-body               omit response body in output
-csv                          store output in csv format
-j, -json                     store output in JSONL(ines) format
-irh, -include-response-header  include http response headers in JSON output
-irr, -include-response       include http request/response in JSON output
-include-chain                include redirect http chain in JSON output
```

### CONFIGURATIONS
```
-r, -resolvers string[]       list of custom resolver (file or comma separated)
-allow string[]               allowed list of IP/CIDR's to process
-deny string[]                denied list of IP/CIDR's to process
-sni, -sni-name string        custom TLS SNI name
-random-agent                 enable Random User-Agent (default true)
-H, -header string[]          custom http headers to send with request
-http-proxy, -proxy string    proxy to use (eg http://127.0.0.1:8080)
-unsafe                       send raw requests skipping normalization
-fr, -follow-redirects        follow http redirects
-maxr, -max-redirects int     max number of redirects to follow (default 10)
-fhr, -follow-host-redirects  follow redirects on the same host
-x string                     request methods to probe, use 'all' for all methods
-body string                  post body to include in http request
-s, -stream                   stream mode - start without sorting
-timeout int                  timeout in seconds (default 10)
-retries int                  number of retries
```

### DEBUG
```
-silent                       silent mode (display only results)
-v, -verbose                  verbose mode
-version                      display httpx version
-stats                        display scan statistic
-nc, -no-color                disable colors in cli output
```

### OPTIMIZATIONS
```
-nf, -no-fallback             display both probed protocol (HTTPS and HTTP)
-nfs, -no-fallback-scheme     probe with protocol scheme specified in input
-maxhr, -max-host-error int   max error count per host before skipping (default 30)
-e, -exclude string[]         exclude host matching filter ('cdn','private-ips',cidr,ip,regex)
-delay value                  duration between each request (eg: 200ms, 1s)
```

## Parameters (tool wrapper)
- `target` (required): Single host/URL or file path prefixed with `@` (e.g. `@subdomains.txt`)

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

# Screenshot pages
httpx -u example.com -ss -system-chrome -json

# Extract emails and IPs from response
httpx -u example.com -ep url,ipv4,mail -json

# Filter out CDN hosts
httpx -l hosts.txt -fcdn cloudfront,fastly -sc -title
```

## Output Interpretation
- Status codes: 200=live, 301/302=redirect, 403=forbidden, 404=not found
- Technologies detected reveal attack surface (e.g., WordPress → wpscan templates)
- CDN detection helps avoid scanning CDN IPs
- JARM fingerprint identifies server-side TLS configuration

## Best Practices
- Always use `-json` for structured output parsing
- Use `-td` (tech-detect) to identify technologies for targeted scanning
- Use `-sc -title` as minimum probes
- Use `-fr` (follow-redirects) to get final destinations
- Pipe from subfinder: `subfinder -d target | httpx -silent`
- Use `-fc 404` to filter out dead pages
- Use `-threads` and `-rate-limit` to control scan speed
- Use `-screenshot` for visual recon when needed

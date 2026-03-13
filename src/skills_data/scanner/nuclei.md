---
name: nuclei
category: scanner
binary_name: nuclei
---

# Nuclei — Template-Based Vulnerability Scanner

## When to Use
ALWAYS run during scanning phase. The primary vulnerability detection tool using community templates. Covers CVEs, misconfigurations, exposures, defaults, and more.

## How to Use
```
nuclei [flags]
```

## CLI Flags
```
TARGET:
   -u, -target string[]       target URLs/hosts to scan
   -l, -list string           file containing targets (one per line)
   -resume string             resume scan using resume.cfg
   -sa, -scan-all-ips         scan all IPs associated with DNS record
   -iv, -ip-version string[]  IP version to scan (4,6) (default 4)

TEMPLATES:
   -nt, -new-templates            run only new templates from latest release
   -ntv, -new-templates-version string[]  run templates from specific version
   -as, -automatic-scan           automatic web scan using wappalyzer
   -t, -templates string[]        template or directory paths
   -turl, -template-url string[]  template URL to run
   -w, -workflows string[]        workflow or directory paths
   -tu, -template-update          update nuclei templates
   -td, -template-display         display template content
   -tgl, -tag-list                list available tags
   -code                          enable code protocol-based templates
   -dut, -disable-unsigned-templates  disable unsigned templates

FILTERING:
   -a, -author string[]          templates by author
   -tags string[]                templates by tag (e.g. cve,exposure,misconfig)
   -etags, -exclude-tags string[] exclude by tag
   -itags, -include-tags string[] include even if excluded
   -id, -template-id string[]    templates by ID
   -eid, -exclude-id string[]    exclude by ID
   -it, -include-templates string[]  use even if excluded
   -et, -exclude-templates string[]  exclude template/directory
   -em, -exclude-matchers string[]   exclude by matcher name
   -s, -severity string[]         filter by severity (info,low,medium,high,critical)
   -es, -exclude-severity string[] exclude by severity
   -pt, -type string[]            filter by protocol type (dns,http,file,tcp,etc.)
   -ept, -exclude-type string[]   exclude by protocol type
   -tc, -template-condition string[] template condition filters

RATE-LIMIT:
   -rl, -rate-limit int           max requests/second (default 150)
   -rlm, -rate-limit-minute int   max requests/minute
   -bs, -bulk-size int            max hosts analyzed in parallel (default 25)
   -c, -concurrency int           max templates executed in parallel (default 25)
   -hbs, -headless-bulk-size int  max headless hosts parallel (default 10)
   -headc, -headless-concurrency  max headless templates parallel (default 10)
   -jsc, -js-concurrency int      JS runtime concurrency (default 120)
   -pc, -payload-concurrency int  max payload concurrency (default 25)

OUTPUT:
   -o, -output string          output file
   -j, -jsonl                  JSONL output
   -irr, -include-rr           include request/response in output
   -nm, -no-meta               don't display match metadata
   -ts, -timestamp             display timestamp in output
   -rdb, -report-db string     nuclei reporting database
   -ms, -matcher-status        display match failure status
   -me, -markdown-export string  export in markdown directory
   -se, -sarif-export string   export in SARIF format

CONFIGURATIONS:
   -config string              nuclei config file path
   -fr, -follow-redirects      enable HTTP redirects
   -fhr, -follow-host-redirects  follow redirects on same host
   -mr, -max-redirects int     max redirects (default 10)
   -dr, -disable-redirects     disable HTTP redirects
   -H, -header string[]        custom headers ("header:value")
   -V, -var value              custom vars ("key=value")
   -r, -resolvers string       custom resolvers (file or comma separated)
   -sr, -system-resolvers      use OS resolvers as errors
   -dc, -disable-clustering    disable template clustering
   -passive                    passive HTTP response processing
   -fh2, -force-http2          force HTTP2 connections
   -dialer-timeout value       timeout for network requests (default 10s)
   -dialer-keep-alive value    keep-alive duration (default 30s)
   -lfa, -leave-default-ports  leave default ports (e.g. host:80)
   -spm, -stop-at-first-match  stop when first match found (per host)
   -timeout int                seconds to wait before timeout (default 10)
   -mhe, -max-host-error int   max errors for host before skipping (default 30)
   -retries int                number of retries (default 1)

INTERACTSH:
   -iserver, -interactsh-server string  interactsh server URL
   -itoken, -interactsh-token string    interactsh auth token
   -interactions-cache-size int         interactions cache size (default 5000)
   -interactions-eviction int           eviction seconds (default 60)
   -interactions-poll-duration int      poll seconds (default 5)
   -ni, -no-interactsh                  disable interactsh server

HEADLESS:
   -headless                   enable headless browser templates
   -page-timeout int           seconds for page load (default 20)
   -sb, -show-browser          show browser in headless mode
   -sc, -system-chrome         use local Chrome
   -lha, -list-headless-action  list available headless actions

DEBUG:
   -debug                      show all requests/responses
   -debug-req                  show request content
   -debug-resp                 show response content
   -silent                     display findings only
   -v, -verbose                verbose output
   -version                    display version

OPTIMIZATION:
   -timeout int                timeout seconds (default 10)
   -retries int                retries for failed requests
   -mhe, -max-host-error int   max errors per host (default 30)
   -nmhe, -no-mhe              disable max host error
   -hm, -host-max-errors int   max errors per host (default 30)
   -project                    avoid sending same request twice
```

## Example Commands
```bash
# Basic scan with default templates
nuclei -u https://example.com -silent

# Scan by severity
nuclei -u https://example.com -s critical,high,medium

# Scan with specific tags
nuclei -u https://example.com -tags cve,exposure,misconfig

# Scan for specific vulnerabilities
nuclei -u https://example.com -tags xss,sqli,ssrf,lfi

# Leak and misconfig detection
nuclei -u https://example.com -tags exposure,config,backup,git

# CORS misconfiguration
nuclei -u https://example.com -tags cors

# Technology-specific scan (auto-detect)
nuclei -u https://example.com -as

# Scan from file with JSON output
nuclei -l targets.txt -jsonl -o results.json

# Cloud misconfiguration
nuclei -u https://example.com -tags cloud,aws,s3,gcs,azure

# JWT testing
nuclei -u https://example.com -tags jwt
```

## Output Interpretation
- `[critical]` = immediate action required (RCE, SQLi, auth bypass)
- `[high]` = significant vulnerability
- `[medium]` = notable finding
- `[low]` = informational but worth noting
- `[info]` = detected technology/configuration

## Best Practices
- Use `-s critical,high,medium` for focused scanning
- Use `-as` (automatic scan) to auto-select templates based on detected technologies
- Use `-tags` to target specific vulnerability classes
- Use `-rl` to adjust rate limiting for target sensitivity
- JSON output (`-jsonl`) for automated finding parsing

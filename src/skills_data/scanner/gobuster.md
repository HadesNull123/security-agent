---
name: gobuster
category: scanner
binary_name: gobuster
---

# Gobuster — Directory/File & DNS Brute-Forcing

## When to Use
Use for directory/file discovery and DNS subdomain brute-forcing. Alternative to ffuf with different features.

## How to Use
```
gobuster [mode] [flags]
```

## CLI Flags
```
MODES:
   dir       directory/file enumeration
   dns       DNS subdomain enumeration
   vhost     virtual host discovery
   fuzz      fuzzing mode
   s3        S3 bucket enumeration
   gcs       GCS bucket enumeration
   tftp      TFTP enumeration

DIR MODE FLAGS:
   -u, --url string              target URL
   -w, --wordlist string         path to wordlist
   -t, --threads int             concurrent threads (default 10)
   -e, --expanded                expanded mode (print full URLs)
   -x, --extensions string       file extensions to search for (comma-separated)
   -r, --follow-redirect         follow redirects
   -H, --headers stringArray     HTTP headers ("Header: Value")
   -c, --cookies string          cookies to use
   -U, --username string         HTTP Basic auth username
   -P, --password string         HTTP Basic auth password
   -p, --proxy string            proxy URL
   -a, --useragent string        User-Agent string
   -k, --no-tls-validation       skip TLS verification
   -n, --no-status               don't print status codes
   -b, --status-codes-blacklist string  negative status codes (default "404")
   -s, --status-codes string           positive status codes
   --exclude-length string             exclude by response length
   -d, --discover-backup         discover backup files
   --timeout duration            HTTP timeout (default 10s)
   --delay duration              delay between requests
   --retry int                   number of retries on errors
   --no-error                    don't display errors
   --wildcard                    force continue on wildcard responses

OUTPUT:
   -o, --output string           output file
   -q, --quiet                   quiet mode (no banner/progress)
   --no-color                    disable color output
   -v, --verbose                 verbose output
   -z, --no-progress             don't display progress

DNS MODE FLAGS:
   -d, --domain string           target domain
   -w, --wordlist string         path to wordlist
   -r, --resolver string         custom DNS resolver
   -c, --show-cname              show CNAME records
   -i, --show-ips                show IP addresses
   --wildcard                    force continue on wildcard
   --timeout duration            DNS timeout (default 1s)

VHOST MODE FLAGS:
   -u, --url string              target URL
   -w, --wordlist string         path to wordlist
   --append-domain               append domain to words
   --domain string               domain for append mode
   --exclude-length string       exclude by response length

S3 MODE FLAGS:
   -w, --wordlist string         path to wordlist
   --maxfiles int                max files to list (default 5)
```

## Example Commands
```bash
# Directory discovery
gobuster dir -u https://example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50

# With extensions
gobuster dir -u https://example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,bak

# DNS subdomain brute-force
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -i

# Virtual host discovery
gobuster vhost -u https://example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# S3 bucket enumeration
gobuster s3 -w bucket-names.txt

# Quiet output with file
gobuster dir -u https://example.com -w common.txt -q -o results.txt
```

## Output Interpretation
- Status 200 = found and accessible
- Status 301/302 = redirect (follow to check)
- Status 403 = forbidden but exists
- Status 500 = server error (potential vuln)

## Best Practices
- Use `-t 50` for faster scanning (adjust based on target tolerance)
- Use `-x` with relevant extensions
- Use `-b 404` to filter common false positives
- S3 mode useful for cloud asset discovery

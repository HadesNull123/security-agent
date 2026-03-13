---
name: dnsx
category: recon
binary_name: dnsx
---

# dnsx — Fast DNS Toolkit

## When to Use
Run after subfinder to validate discovered subdomains via DNS resolution. Also useful for DNS brute-forcing and record enumeration.

## How to Use
```
dnsx [flags]
```

## CLI Flags
```
INPUT:
   -l, -list string      list of sub(domains)/hosts to resolve (file or stdin)
   -d, -domain string    domain to bruteforce (file or comma separated)
   -w, -wordlist string  words for brute forcing (file or comma separated)

QUERY:
   -a           query A record (default)
   -aaaa        query AAAA record
   -cname       query CNAME record
   -ns          query NS record
   -txt         query TXT record
   -srv         query SRV record
   -ptr         query PTR record
   -mx          query MX record
   -soa         query SOA record
   -axfr        query AXFR (zone transfer)
   -caa         query CAA record
   -any         query ANY record

FILTER:
   -re, -resp          display DNS response
   -ro, -resp-only     display response only
   -rc, -rcode string  filter by status code (noerror,servfail,refused)

PROBE:
   -cdn    display CDN name
   -asn    display host ASN

RATE-LIMIT:
   -t, -threads int      concurrent threads (default 100)
   -rl, -rate-limit int  DNS requests/second (default -1, disabled)

OUTPUT:
   -o, -output string   output file
   -j, -json            JSONL output

DEBUG:
   -silent    display only results
   -v         verbose output
   -raw       display raw DNS response
   -stats     display scan stats
   -version   display version

OPTIMIZATION:
   -retry int                   DNS attempts (default 2)
   -hf, -hostsfile              use system host file
   -trace                       perform DNS tracing
   -trace-max-recursion int     max trace recursion (default 32767)

CONFIGURATIONS:
   -r, -resolver string              custom resolvers (file or comma separated)
   -wt, -wildcard-threshold int      wildcard filter threshold (default 5)
   -wd, -wildcard-domain string      domain for wildcard filtering
```

## Example Commands
```bash
# Validate subdomains from subfinder
subfinder -d example.com -silent | dnsx -silent

# DNS resolution with A record
echo "example.com" | dnsx -a -resp

# Query multiple record types
echo "example.com" | dnsx -a -aaaa -cname -mx -txt -resp

# Zone transfer check (AXFR)
echo "example.com" | dnsx -axfr

# DNS brute-force
dnsx -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent

# JSON output with CDN detection
subfinder -d example.com | dnsx -json -cdn -asn -o dns_results.json
```

## Output Interpretation
- Resolved IPs confirm subdomain is active
- CNAME records reveal aliased services
- MX records show email infrastructure
- TXT records may contain SPF/DKIM/verification tokens
- AXFR success = zone transfer vulnerability (CRITICAL)
- CDN detection helps identify protected vs. direct hosts

## Best Practices
- Always pipe subfinder output through dnsx to validate
- Use `-json` for structured parsing
- Check for AXFR on discovered nameservers
- Use CDN detection to identify direct-IP targets

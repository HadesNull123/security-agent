---
name: subfinder
category: recon
binary_name: subfinder
---

# Subfinder — Fast Passive Subdomain Enumeration

## When to Use
ALWAYS run first in recon phase. Discovers subdomains via passive sources (no direct target contact).

## How to Use
```
subfinder [flags]
```

## CLI Flags
```
INPUT:
   -d, -domain string[]   domains to find subdomains for
   -dL, -list string      file containing list of domains for subdomain discovery

SOURCE:
   -s, -sources string[]          specific sources to use (-s crtsh,github)
   -recursive                     use only recursive-capable sources
   -all                           use all sources (slow)
   -es, -exclude-sources string[] sources to exclude (-es alienvault,zoomeyeapi)

FILTER:
   -m, -match string[]    subdomain or list of subdomain to match (file or comma separated)
   -f, -filter string[]   subdomain or list of subdomain to filter (file or comma separated)

RATE-LIMIT:
   -rl, -rate-limit int   max http requests per second
   -rls value              per-provider rate limit (-rls "hackertarget=10/s,shodan=15/s")
   -t int                  concurrent goroutines for resolving (-active only) (default 10)

OUTPUT:
   -o, -output string     file to write output to
   -oJ, -json             write output in JSONL format
   -oD, -output-dir string  directory to write output (-dL only)
   -cs, -collect-sources   include all sources in output (-json only)
   -oI, -ip                include host IP in output (-active only)

CONFIGURATION:
   -pc, -provider-config string  provider config file (API keys)
   -r string[]              custom resolvers (comma separated)
   -rL, -rlist string       file containing resolvers
   -nW, -active             display active subdomains only
   -proxy string            http proxy to use
   -ei, -exclude-ip         exclude IPs from the list

DEBUG:
   -silent          show only subdomains in output
   -v               verbose output
   -nc, -no-color   disable color
   -ls, -list-sources  list all available sources

OPTIMIZATION:
   -timeout int     seconds to wait before timing out (default 30)
   -max-time int    minutes to wait for results (default 10)
```

## Example Commands
```bash
# Basic subdomain enumeration
subfinder -d example.com -silent

# JSON output for parsing
subfinder -d example.com -json -o subdomains.json

# Use all sources (thorough)
subfinder -d example.com -all -o subs.txt

# Active mode with IP resolution
subfinder -d example.com -active -ip

# Multiple domains from file
subfinder -dL domains.txt -o all_subs.txt
```

## Output Interpretation
- Each line = one discovered subdomain
- JSON mode includes source information
- Pipe output to httpx for live host detection: `subfinder -d target.com | httpx`

## Best Practices
- Always use `-silent` for clean output
- Use `-json` when output will be parsed
- Combine with httpx to filter live hosts
- Use `-all` for deep scan mode, default sources for quick

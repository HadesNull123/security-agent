---
name: theharvester
category: recon
binary_name: theHarvester
---

# theHarvester — Email, Subdomain & IP Harvesting

## When to Use
Run for OSINT gathering — find email addresses, subdomains, IPs, and URLs using public sources (search engines, PGP key servers, Shodan).

## How to Use
```
theHarvester [options]
```

## CLI Flags
```
INPUT:
   -d DOMAIN          target domain to search
   -l LIMIT           limit results (default 500)
   -S START           start result number (default 0)

SOURCE:
   -b SOURCE          data source(s), comma-separated:
                      anubis, baidu, bevigil, binaryedge, bing, bingapi,
                      brave, bufferoverun, censys, certspotter, criminalip,
                      crtsh, dnsdumpster, duckduckgo, fullhunt, github-code,
                      hackertarget, hunter, hunterhow, intelx, netlas,
                      onyphe, otx, pentesttools, projectdiscovery,
                      rapiddns, rocketreach, securityTrails, shodan,
                      sitedossier, subdomainfinder, threatminer,
                      urlscan, virustotal, yahoo, zoomeye

PASSIVE:
   -n                 DNS lookup (brute force)
   -c                 DNS brute force with a custom dictionary
   -e DNS_SERVER      DNS server to use
   -r                 DNS reverse lookup
   -t DNS_TLD         perform DNS TLD expansion

OUTPUT:
   -f FILENAME        save results to HTML and XML files
   -o FILENAME        save results to specific format

NETWORK:
   -p                 port scan of discovered hosts (limited)
   -s                 Shodan search for hosts
   --virtual-host     verify virtual hosts with DNS resolution

SCREENSHOT:
   --screenshot PATH  take screenshots of resolved domains
```

## Example Commands
```bash
# Basic search with multiple sources
theHarvester -d example.com -b crtsh,hackertarget,dnsdumpster

# Comprehensive search
theHarvester -d example.com -b all -l 1000

# Search with specific source
theHarvester -d example.com -b shodan

# Save results
theHarvester -d example.com -b crtsh -f output
```

## Output Interpretation
- Emails: found email addresses (for phishing awareness)
- Subdomains: additional attack surface
- IPs: associated infrastructure
- Hosts: resolved hostnames

## Best Practices
- Use `-b crtsh,hackertarget,dnsdumpster` for quick scan
- Use `-b all` for deep scan
- Combine with subfinder for comprehensive coverage
- Results include email addresses useful for social engineering assessment

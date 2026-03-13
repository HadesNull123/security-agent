---
name: amass
category: recon
binary_name: amass
---

# Amass — Attack Surface Mapping

## When to Use
Use for comprehensive subdomain enumeration and network mapping when thoroughness is required. Slower than subfinder but finds more results via active techniques.

## How to Use
```
amass enum [flags]
```

## CLI Flags
```
SUBCOMMANDS:
   amass enum    - Perform enumerations and network mapping
   amass intel   - Discover targets for enumerations
   amass db      - Manipulate the Amass graph database

ENUM FLAGS:
   -active             attempt certificate name grabs and zone transfers
   -addr string        IPs and ranges (192.168.1.1-254) to find associated domains
   -asn int[]          ASNs to investigate
   -brute              perform brute force subdomain enumeration
   -cidr string        CIDRs to investigate
   -d string           comma-separated domain names to enumerate
   -demo               censor output for demonstrations/screenshots
   -df string          file of domain names to enumerate
   -dns-qps int        max DNS queries per second for each resolver
   -ef string          file of data sources to exclude
   -exclude string     comma-separated data sources to exclude
   -if string          file of data sources to include
   -include string     comma-separated data sources to include
   -list               print names of all available data sources
   -max-depth int      max subdomain label depth
   -max-dns-queries int    max total DNS queries
   -min-for-recursive int  min names for recursive brute forcing (default 1)
   -nf string          file of known subdomain names (to avoid re-querying)
   -norecursive        disable recursive brute forcing
   -o string           output file
   -oA string          output all formats (txt, json)
   -p int[]            ports to be used for active investigations
   -passive            only use passive sources (no direct target contact)
   -r string           comma-separated DNS resolvers
   -rf string          file of DNS resolvers
   -scripts string     directory of ADS scripts
   -timeout int        minutes to execute enumeration
   -v                  verbose output
   -w string           file of words for brute forcing

CONFIG:
   -config string      YAML config file path
   -dir string         output directory (default: $HOME/.config/amass)

OUTPUT:
   -json string        output as JSON
   -o string           output as text
```

## Example Commands
```bash
# Passive-only enumeration
amass enum -passive -d example.com -o subs.txt

# Active enumeration with brute force
amass enum -active -brute -d example.com -o subs.txt

# With custom wordlist
amass enum -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -d example.com

# JSON output
amass enum -d example.com -json amass.json
```

## Output Interpretation
- Each line = discovered subdomain
- JSON output includes data source and resolution info
- Active mode may trigger IDS alerts

## Best Practices
- Use `-passive` in quick mode
- Use `-active -brute` in deep mode
- Set `-timeout` to prevent long-running scans
- Use `-dns-qps` to control scan speed

---
name: wafw00f
category: recon
binary_name: wafw00f
---

# wafw00f — WAF Detection Tool

## When to Use
Run before scanning to detect Web Application Firewalls. Helps avoid detection and choose appropriate evasion techniques.

## How to Use
```
wafw00f [options] <url>
```

## CLI Flags
```
INPUT:
   <url>                target URL
   -i FILE              read targets from file

DETECTION:
   -a                   find all WAFs (don't stop at first match)
   -p PROXY             use proxy (e.g. http://127.0.0.1:8080)
   -t TEST              test for specific WAF (e.g. Cloudflare)

OUTPUT:
   -o FILE              output to file
   -f FORMAT            output format (csv, json, txt) (default txt)
   -v                   increase verbosity
   -l                   list all WAFs that can be detected
```

## Example Commands
```bash
# Basic WAF detection
wafw00f https://example.com

# Detect all WAFs (don't stop at first)
wafw00f -a https://example.com

# JSON output
wafw00f https://example.com -f json -o waf.json

# Scan multiple targets
wafw00f -i targets.txt -f json -o results.json

# List detectable WAFs
wafw00f -l
```

## Output Interpretation
- "is behind [WAF_NAME]" = WAF detected
- "No WAF detected" = no WAF or unrecognized WAF
- Common WAFs: Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, Sucuri

## Best Practices
- Always run before nuclei/ffuf scanning
- If WAF detected, use slower scan rates and evasion techniques
- Use `-a` for thorough detection

---
name: whatweb
category: recon
binary_name: whatweb
---

# WhatWeb — Web Technology Identification

## When to Use
Run to identify web technologies, CMS, frameworks, servers, and plugins on target URLs. Useful for fingerprinting before vulnerability scanning.

## How to Use
```
whatweb [options] <URLs>
```

## CLI Flags
```
TARGET SELECTION:
   <URLs>                 target URLs (space separated)
   -i, --input-file FILE  read targets from file (one per line)

DETECTION:
   -a, --aggression LEVEL  Set aggression level (1-4)
                           1: Stealthy (1 HTTP request, default)
                           3: Aggressive (triggers additional requests)
                           4: Heavy (tries all plugins for all URLs)
   -p, --plugins LIST     select plugins (comma separated, e.g. apache,wordpress)
   --list-plugins         list all plugins
   --info-plugins         list all plugins with details
   --grep REGEX           search plugin output

HTTP OPTIONS:
   -U, --user-agent STR   custom User-Agent
   -c, --cookie STR       set cookies (NAME=VALUE; NAME2=VALUE2)
   -H, --header STR       add HTTP header ("Accept-Language: fr")
   --follow-redirect WHEN  when to follow redirects (never,http-only,meta-only,same-site,same-domain,always) (default: always)
   --max-redirects NUM    max redirects to follow (default 10)
   --proxy HOST:PORT      set HTTP proxy
   --proxy-user USER:PASS proxy auth

OUTPUT:
   -v, --verbose          increase verbosity
   -q, --quiet            do not display brief logging
   --no-errors            suppress error messages
   --log-brief FILE       brief output log
   --log-verbose FILE     verbose output log
   --log-json FILE        JSON output log
   --log-xml FILE         XML output log
   --log-object FILE      Ruby object inspection log

PERFORMANCE:
   -t, --max-threads NUM  max simultaneous connections (default 25)
   --open-timeout SEC     connection timeout (default 15)
   --read-timeout SEC     read timeout (default 30)
   --wait SEC             wait between connections

AUTHENTICATION:
   -u, --user USER:PASS   HTTP basic auth
```

## Example Commands
```bash
# Basic scan
whatweb example.com

# JSON output
whatweb example.com --log-json whatweb.json

# Aggressive detection
whatweb -a 3 example.com

# Scan multiple targets from file
whatweb -i targets.txt --log-json results.json

# Verbose output
whatweb -v example.com
```

## Output Interpretation
- Identifies: CMS (WordPress, Joomla, Drupal), Frameworks (Rails, Django, Laravel), Servers (Apache, Nginx, IIS), Languages (PHP, ASP.NET, Python)
- Aggression level 1 = single request, level 3-4 = multiple requests
- JSON output provides structured data for parsing

## Best Practices
- Use aggression level 1 (default) for quick scanning
- Use level 3 for more accurate detection
- JSON output (`--log-json`) for structured parsing

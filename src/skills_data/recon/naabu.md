---
name: naabu
category: recon
binary_name: naabu
---

# Naabu — Fast Port Scanner

## When to Use
Run after subfinder to discover open ports on target hosts. Faster than nmap for large-scale scanning.

## How to Use
```
naabu [flags]
```

## CLI Flags
```
INPUT:
   -host string[]              hosts to scan (comma-separated)
   -list, -l string            file of hosts to scan
   -exclude-hosts, -eh string  hosts to exclude (comma-separated)
   -exclude-file, -ef string   file of hosts to exclude

PORT:
   -port, -p string            ports to scan (80,443, 100-200)
   -top-ports, -tp string      top ports to scan (default 100) [full,100,1000]
   -exclude-ports, -ep string  ports to exclude (comma-separated)
   -ports-file, -pf string     file of ports to scan
   -port-threshold, -pts int   port threshold to skip host
   -exclude-cdn, -ec           skip full scan for CDN/WAF (only 80,443)
   -display-cdn, -cdn          display cdn in use

RATE-LIMIT:
   -c int     internal worker threads (default 25)
   -rate int  packets per second (default 1000)

OUTPUT:
   -o, -output string  file to write output to
   -j, -json           JSON lines output
   -csv                CSV output

CONFIGURATION:
   -scan-all-ips, -sa           scan all IPs for DNS record
   -scan-type, -s string        port scan type (SYN/CONNECT) (default "c")
   -source-ip string            source ip (x.x.x.x:yyy)
   -interface, -i string        network interface for scan
   -nmap-cli string             nmap command on found results (e.g. -nmap-cli 'nmap -sV')
   -r string                    custom DNS resolvers (comma separated or file)
   -proxy string                socks5 proxy
   -resume                      resume scan using resume.cfg
   -passive                     passive open ports via Shodan InternetDB API

HOST-DISCOVERY:
   -sn, -host-discovery         perform only host discovery
   -wn, -with-host-discovery    enable host discovery
   -pe, -probe-icmp-echo        ICMP echo request ping
   -arp, -arp-ping              ARP ping

OPTIMIZATION:
   -retries int       number of retries (default 3)
   -timeout int       milliseconds before timeout (default 1000)
   -warm-up-time int  seconds between scan phases (default 2)
   -ping              ping probes for verification
   -verify            validate ports with TCP verification

DEBUG:
   -silent    display only results
   -debug     debug information
   -v         verbose output
```

## Example Commands
```bash
# Scan top 100 ports
naabu -host example.com -top-ports 100

# Full port scan with JSON output
naabu -host example.com -p - -json -o ports.json

# Scan from subfinder output
subfinder -d example.com -silent | naabu -silent

# Scan specific ports
naabu -host example.com -p 80,443,8080,8443,9090

# Top 1000 ports, SYN scan
naabu -host example.com -top-ports 1000 -scan-type s

# Passive mode (Shodan API, no packets sent)
naabu -host example.com -passive
```

## Output Interpretation
- Format: `host:port` (default) or JSON
- Use `-json` for structured parsing
- Pipe to httpx: `naabu -host target.com | httpx`

## Best Practices
- Use `-top-ports 100` for quick scan, `-top-ports 1000` or `-p -` for deep
- Use `-silent` for clean output
- Use `-json` when results will be parsed
- Combine with httpx for service detection

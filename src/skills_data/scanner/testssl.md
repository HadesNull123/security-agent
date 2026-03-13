---
name: testssl
category: scanner
binary_name: testssl.sh
---

# testssl.sh — SSL/TLS Testing

## When to Use
Run to audit SSL/TLS configuration: weak ciphers, expired certs, protocol vulnerabilities (Heartbleed, POODLE, DROWN, ROBOT), HSTS, OCSP stapling. Standard requirement for any security audit.

## How to Use
```
testssl.sh [options] <URI> or <host:port>
```

## CLI Flags
```
INPUT:
   <URI>                  host or host:port (default port 443)
   --file <file>          mass testing, one URI per line
   --mode <serial|parallel>  mass testing mode (default serial)

DEFAULT CHECKS (run without flags for all):
   -e, --each-cipher        check each local cipher remotely
   -E, --cipher-per-proto   check ciphers per protocol
   -s, --std, --standard    test standard cipher categories
   -p, --protocols          check TLS/SSL protocols
   -h, --header, --headers  check HSTS, HPKP, server/app banner string
   -U, --vulnerable         test all vulnerabilities
   -S, --server-defaults    display server certificate info
   -P, --server-preference  display server preferences

SINGLE CHECKS:
   -f, --pfs, --fs          check (perfect) forward secrecy settings
   -A, --beast              check BEAST vulnerability
   -O, --poodle             check POODLE (SSL) vulnerability
   -Z, --tls-fallback       check TLS_FALLBACK_SCSV
   -W, --sweet32            check SWEET32 vulnerability
   -F, --freak              check FREAK vulnerability
   -J, --logjam             check LOGJAM vulnerability
   -D, --drown              check DROWN vulnerability
   -R, --robot              check ROBOT vulnerability
   -B, --heartbleed         check Heartbleed vulnerability
   -I, --ccs, --ccs-injection  check CCS injection
   -T, --ticketbleed        check Ticketbleed
   -BB, --winshock          check Winshock
   -4, --rc4                check RC4 ciphers
   --crime                  check CRIME vulnerability

CERTIFICATE:
   --cert-form <PEM|DER>   certificate output format

OUTPUT:
   --quiet                 don't output banner
   --wide                  wider output for tests
   --color <0|1|2|3>       color level (0=none, 2=default)
   --json                  JSON output (flat)
   --jsonfile <file>       JSON output to file
   --json-pretty           pretty-printed JSON
   --csv                   CSV output
   --csvfile <file>        CSV output to file
   --html                  HTML output
   --htmlfile <file>       HTML output to file
   --log, --logging        log to file
   --logfile <file>        log output to file

CONFIGURATION:
   --openssl <path>        use specified openssl binary
   --ssl-native            fallback to openssl where sockets don't work
   --assuming-http         assume HTTP protocol (default auto-detect)
   --connect-timeout <sec> timeout for TCP connect (default 5)
   --openssl-timeout <sec> timeout for openssl (default 20)
   --sneaky                leave less traces in target logs
   --bugs                  enable workarounds for broken server implementations
   --warnings <batch|off>  control warning behavior
   --debug <0-6>           debug level
   --fast                  skip some tests for speed
   --ip <address>          test specific IP (for multi-homed hosts)
   -n, --nodns <min|none>  control DNS lookups
   --proxy <host:port>     use proxy (HTTP, HTTPS, SOCKS4, SOCKS5)
   --starttls <protocol>   STARTTLS protocol (ftp, smtp, pop3, imap, etc.)
   --xmpphost <host>       XMPP host for STARTTLS
```

## Example Commands
```bash
# Full SSL/TLS audit
testssl.sh https://example.com

# Check all vulnerabilities only
testssl.sh -U https://example.com

# Check Heartbleed specifically
testssl.sh -B https://example.com

# JSON output
testssl.sh --jsonfile results.json https://example.com

# Check HSTS and headers
testssl.sh -h https://example.com

# Quick scan (skip slow tests)
testssl.sh --fast https://example.com

# Scan specific port
testssl.sh example.com:8443

# Check protocols and ciphers
testssl.sh -p -E https://example.com

# Mass testing from file
testssl.sh --file targets.txt --mode parallel
```

## Output Interpretation
- 🔴 CRITICAL: Heartbleed, DROWN, ROBOT vulnerabilities
- 🟠 HIGH: Weak ciphers (RC4, DES), SSLv2/SSLv3 enabled
- 🟡 MEDIUM: Missing HSTS, weak DH parameters, TLS 1.0/1.1
- 🟢 OK: Strong configuration, TLS 1.2/1.3, AEAD ciphers

## Best Practices
- Use `--fast` for quick scan, full for deep
- Always check `-U` (vulnerabilities) at minimum
- JSON output (`--jsonfile`) for automated parsing
- Check HSTS header with `-h` flag

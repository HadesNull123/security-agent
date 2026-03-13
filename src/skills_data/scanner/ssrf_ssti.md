---
name: ssrf_ssti
category: scanner
binary_name: nuclei
virtual: true
---

# SSRF & SSTI Detection

## When to Use
Test for Server-Side Request Forgery (SSRF) and Server-Side Template Injection (SSTI)
when the target has parameters that accept URLs, file paths, or template-like input.
High-severity vuln class — always check during normal/deep scans.

## How to Use
This is a **virtual skill** — uses nuclei with specific tags.
Run nuclei with `--tags ssrf,ssti` to detect these vulnerabilities.

For more thorough testing:
- SSRF: Use ffuf with SSRF payloads against URL parameters
- SSTI: Look for template syntax in responses (e.g., {{7*7}} → 49)

## Parameters
- Use nuclei with `tags: "ssrf,ssti"`
- `target`: URL with injectable parameters

## Output Interpretation
- SSRF confirmed: Server makes requests to attacker-controlled server
  - Check for internal network access (169.254.169.254 = AWS metadata = CRITICAL)
  - File read via file:// protocol = CRITICAL
- SSTI confirmed: Template expression evaluated
  - Jinja2/Twig/Freemarker = RCE potential = CRITICAL

## Best Practices
- Test all URL-accepting parameters for SSRF
- Common SSRF targets: URL previews, PDF generators, webhook URLs
- For SSTI: try {{7*7}}, ${7*7}, #{7*7} based on framework
- ALWAYS test cloud metadata endpoint: http://169.254.169.254/latest/meta-data/

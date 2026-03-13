---
name: info_disclosure
category: scanner
binary_name: nuclei
virtual: true
---

# Information Disclosure Detection

## When to Use
Check for information leakage on ALL web targets during scanning phase.
Verbose error messages and debug pages reveal internal architecture to attackers.

## How to Use
This is a **virtual skill** — uses nuclei with disclosure-specific templates.
Run nuclei with `--tags disclosure,debug,error` to detect info leaks.

## Parameters
- Use nuclei with `tags: "disclosure,debug,error,listing"`
- `target`: URL to test

## Output Interpretation
- Debug mode enabled (Django debug, Laravel debug, Spring Boot actuator) = HIGH
- Stack traces in error responses = MEDIUM
- Server version in headers (Apache/2.4.49, nginx/1.18) = LOW
- Directory listing enabled = MEDIUM
- Default error pages revealing framework/version = LOW
- `/actuator/env`, `/actuator/health` exposed = HIGH (Spring Boot)
- `/__debug__/`, `/debug/default/view` = HIGH (Django/Yii debug)
- `/elmah.axd` = MEDIUM (.NET error logs)

## Best Practices
- Trigger errors intentionally: add `'`, `{{`, `%00` to parameters to get error pages
- Check response headers for `X-Powered-By`, `Server`, `X-AspNet-Version`
- Test framework-specific debug endpoints based on technologies detected in recon
- Check for directory listing by requesting directories without index files

---
name: sensitive_files
category: scanner
binary_name: nuclei
virtual: true
---

# Sensitive File Exposure Detection

## When to Use
ALWAYS include this check during scanning phase for ALL web targets.
Exposed sensitive files are among the most common and impactful findings.

## How to Use
This is a **virtual skill** — uses nuclei + ffuf/gobuster with sensitive-file wordlists.

### Step 1: Nuclei templates
Run nuclei with `--tags exposure,config,backup,files` to detect common exposed files.

### Step 2: Targeted ffuf/gobuster
Fuzz for sensitive paths using a curated list:
- `/.env`, `/.env.bak`, `/.env.production`
- `/wp-config.php`, `/wp-config.php.bak`
- `/web.config`, `/applicationhost.config`
- `/phpinfo.php`, `/info.php`
- `/server-status`, `/server-info`
- `/.htaccess`, `/.htpasswd`
- `/backup.sql`, `/dump.sql`, `/database.sql`
- `/.DS_Store`, `/Thumbs.db`
- `/robots.txt`, `/sitemap.xml`
- `/crossdomain.xml`, `/clientaccesspolicy.xml`
- `/elmah.axd`, `/trace.axd`
- `/composer.json`, `/package.json`, `/Gemfile`

## Parameters
- Use nuclei with `tags: "exposure,config,backup,files"`
- Use ffuf/gobuster with wordlist: `/usr/share/wordlists/common.txt`

## Output Interpretation
- `.env` exposed with DB credentials = CRITICAL
- `wp-config.php` with DB password = CRITICAL
- `phpinfo.php` accessible = MEDIUM (info disclosure)
- `backup.sql` downloadable = CRITICAL (full DB dump)
- `robots.txt` with hidden paths = INFO (recon value)
- `.DS_Store` = LOW (directory structure leak)

## Best Practices
- Check both root and common subdirectories (/admin/, /api/, /app/)
- Try common backup extensions: .bak, .old, .orig, .save, .swp, ~
- Check HTTP response codes: 200 = exposed, 403 = exists but protected
- Download and inspect content of any file found

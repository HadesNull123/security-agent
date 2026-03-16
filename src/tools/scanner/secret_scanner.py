"""Secret Scanner - Extracts leaked credentials from source files (JS/CSS/HTML) using regex.

Two modes of operation:
1. Pass `urls` (comma-separated list) to scan specific URLs for leaked credentials
2. Pass `target` (domain/URL) to auto-discover and scan JS/CSS/HTML files
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin, urlparse
import json

from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult

logger = logging.getLogger(__name__)

# Comprehensive regex for finding leaked credentials/secrets
SECRET_REGEX = re.compile(
    r"(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|"
    r"alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|"
    r"aos_key|api_key|api_key_secret|api_key_sid|api_secret|api\.googlemaps AIza|apidocs|apikey|"
    r"apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|"
    r"appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|"
    r"aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|"
    r"bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|"
    r"browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|"
    r"built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|"
    r"cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|"
    r"clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|"
    r"cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn\.login|"
    r"connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|"
    r"database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|"
    r"dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|"
    r"docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|"
    r"dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|"
    r"elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env\.heroku_api_key|"
    r"env\.sonatype_password|eureka\.awssecretkey|firebase|jwt_secret|private_key|secret_key|"
    r"slack_token|stripe_key|stripe_secret|twilio_sid|twilio_token|github_token|gitlab_token|"
    r"heroku_api_key|mailgun_key|sendgrid_key|sentry_dsn|shopify_key|square_token|"
    r"paypal_secret|recaptcha_secret|google_maps_key)[a-z0-9_ .\-,]{0,25})"
    r"""(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9a-zA-Z\-_=]{8,64})['"]"""
)

# Additional patterns for common secret formats
ADDITIONAL_PATTERNS = [
    # AWS Access Key
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    # Google API Key
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API Key"),
    # Slack Token
    (re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,250}"), "Slack Token"),
    # GitHub Token
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"), "GitHub Token"),
    # Generic high-entropy strings near keywords
    (re.compile(r'(?i)(password|passwd|pwd|secret|token|key)\s*[:=]\s*["\']([^"\']{8,64})["\']'), "Generic Secret"),
    # Private key blocks
    (re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"), "Private Key"),
    # JWT tokens
    (re.compile(r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*"), "JWT Token"),
]


class SecretScannerTool(BaseTool):
    """
    Scans URLs for leaked credentials using regex.
    
    Can be used in two ways:
    1. Pass `urls` (comma-separated) to scan specific JS/CSS/HTML URLs
    2. Pass `target` (domain/URL) to auto-crawl and scan all discovered JS/CSS/HTML files
    """
    name = "secret_scanner"
    description = (
        "Extracts leaked credentials (API keys, passwords, tokens, private keys, JWT) from "
        "JS/CSS/HTML files using regex patterns. Pass 'target' for auto-crawl mode, or 'urls' "
        "for specific URLs discovered by katana/httpx."
    )
    phase = ScanPhase.SCANNING

    def is_available(self) -> bool:
        """Always available — pure Python tool, no external binary needed."""
        return True

    def _fetch_url(self, url: str) -> str:
        """Fetch URL content using urllib."""
        if not url.startswith("http"):
            url = f"https://{url}"
        
        req = Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
        )
        try:
            with urlopen(req, timeout=15) as response:
                return response.read().decode('utf-8', errors='ignore')
        except (HTTPError, URLError, Exception) as e:
            logger.debug(f"Secret scanner failed to fetch {url}: {e}")
            return ""

    def _crawl_for_assets(self, target: str) -> list[str]:
        """
        Fetch the target page and extract JS/CSS/HTML links.
        This is a lightweight crawl to discover asset URLs for scanning.
        """
        if not target.startswith("http"):
            target = f"https://{target}"

        urls_to_scan = [target]  # Always scan the main page

        content = self._fetch_url(target)
        if not content:
            return urls_to_scan

        # Extract JS files
        js_pattern = re.compile(r'(?:src|href)\s*=\s*["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', re.IGNORECASE)
        for match in js_pattern.finditer(content):
            url = match.group(1)
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = urljoin(target, url)
            elif not url.startswith("http"):
                url = urljoin(target, url)
            urls_to_scan.append(url)

        # Extract CSS files
        css_pattern = re.compile(r'href\s*=\s*["\']([^"\']*\.css(?:\?[^"\']*)?)["\']', re.IGNORECASE)
        for match in css_pattern.finditer(content):
            url = match.group(1)
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = urljoin(target, url)
            elif not url.startswith("http"):
                url = urljoin(target, url)
            urls_to_scan.append(url)

        # Extract inline script source maps and webpack chunks
        chunk_pattern = re.compile(r'["\']([^"\']*(?:chunk|bundle|vendor|main|app)[^"\']*\.js(?:\?[^"\']*)?)["\']')
        for match in chunk_pattern.finditer(content):
            url = match.group(1)
            if url.startswith("/"):
                url = urljoin(target, url)
            elif not url.startswith("http"):
                url = urljoin(target, url)
            if url.startswith("http"):
                urls_to_scan.append(url)

        return list(set(urls_to_scan))

    def _scan_content(self, content: str, url: str) -> list[dict]:
        """Scan content for secrets using all regex patterns."""
        findings = []

        # Main regex scan
        for match in SECRET_REGEX.finditer(content):
            key_context = match.group(1).strip()
            secret_value = match.group(4).strip()
            
            # Filter false positives
            if len(secret_value) < 8 or secret_value.lower() in ("undefined", "null", "true", "false", "function", "object"):
                continue

            findings.append({
                "url": url,
                "type": "credential_leak",
                "key_type": key_context,
                "secret": secret_value[:20] + "..." if len(secret_value) > 20 else secret_value,
                "full_match": match.group(0)[:200],
            })

        # Additional pattern scans
        for pattern, pattern_name in ADDITIONAL_PATTERNS:
            for match in pattern.finditer(content):
                match_text = match.group(0)
                if len(match_text) > 7:  # Min length check
                    findings.append({
                        "url": url,
                        "type": pattern_name,
                        "key_type": pattern_name,
                        "secret": match_text[:30] + "..." if len(match_text) > 30 else match_text,
                        "full_match": match_text[:200],
                    })

        return findings

    async def _run(self, target: str = "", urls: str = "", **kwargs: Any) -> ToolResult:
        """
        Run the secret scanner.
        
        - If `urls` is provided: scan those specific URLs
        - If only `target` is provided: auto-crawl the target page to find JS/CSS files, then scan them
        """
        url_list = []

        if urls:
            url_list = [u.strip() for u in urls.split(",") if u.strip()]
        elif target:
            # Auto-crawl mode: discover JS/CSS files from the target page
            logger.info(f"Secret scanner: auto-crawling {target} for JS/CSS/HTML assets...")
            url_list = self._crawl_for_assets(target)
            logger.info(f"Secret scanner: found {len(url_list)} assets to scan")
        
        if not url_list:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error="No URLs provided and no target to crawl. Pass 'target' or 'urls'.",
                command_used="secret_scanner",
            )

        findings = []
        scanned = 0
        failed = 0

        for url in url_list[:100]:  # Cap at 100 URLs
            scanned += 1
            content = self._fetch_url(url)
            if not content:
                failed += 1
                continue

            url_findings = self._scan_content(content, url)
            findings.extend(url_findings)

        # Deduplicate by secret value
        unique_findings = []
        seen = set()
        for f in findings:
            key = f"{f['key_type']}:{f['secret']}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        data = {
            "target": target or url_list[0],
            "scanned_urls": scanned,
            "failed_urls": failed,
            "total_assets_discovered": len(url_list),
            "leaks_found": len(unique_findings),
            "findings": unique_findings,
        }

        return ToolResult(
            tool_name=self.name,
            success=True,
            data=data,
            raw_output=json.dumps(data, indent=2),
            command_used=f"secret_scanner ({scanned} URLs scanned, {len(unique_findings)} leaks found)",
        )

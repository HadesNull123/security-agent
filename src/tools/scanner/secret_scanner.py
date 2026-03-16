"""Secret Scanner - Extracts leaked credentials from source files (JS/CSS/HTML) using regex."""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import json

from src.core.config import ScanPhase
from src.tools import BaseTool, ToolResult

logger = logging.getLogger(__name__)

# The user-provided regex for finding leaked credentials
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
    r"env\.sonatype_password|eureka\.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}"
    r"['\"]([0-9a-zA-Z\-_=]{8,64})['\"]"
)

class SecretScannerTool(BaseTool):
    """
    Scans a given URL (or list of URLs) for leaked credentials using regex.
    Useful for scanning JS, CSS, and HTML source code discovered during recon.
    """
    name = "secret_scanner"
    description = "Extracts leaked credentials (API keys, passwords, tokens) from JS/CSS/HTML files using regex."
    phase = ScanPhase.SCANNING

    def _fetch_url(self, url: str) -> str:
        """Fetch URL content using urllib."""
        if not url.startswith("http"):
            url = f"http://{url}"
        
        req = Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
        )
        try:
            with urlopen(req, timeout=10) as response:
                return response.read().decode('utf-8', errors='ignore')
        except (HTTPError, URLError, Exception) as e:
            logger.debug(f"Secret scanner failed to fetch {url}: {e}")
            return ""

    async def _run(self, urls: str, **kwargs: Any) -> ToolResult:
        """
        Run the secret scanner against provided URLs.
        urls can be a single URL or a comma-separated list of URLs.
        """
        url_list = [u.strip() for u in urls.split(",") if u.strip()]
        if not url_list:
            return ToolResult(
                tool_name=self.name,
                success=False,
                error="No URLs provided to scan.",
                command_used="secret_scanner",
            )

        findings = []
        scanned = 0
        failed = 0

        for url in url_list:
            scanned += 1
            content = self._fetch_url(url)
            if not content:
                failed += 1
                continue

            matches = SECRET_REGEX.finditer(content)
            for match in matches:
                # Group 1 is the key name context, Group 4 is the actual secret value
                key_context = match.group(1).strip()
                secret_value = match.group(4).strip()
                
                # Basic entropy/length check to reduce false positives
                if len(secret_value) < 8 or secret_value.lower() in ("undefined", "null", "true", "false"):
                    continue

                findings.append({
                    "url": url,
                    "key_type": key_context,
                    "secret": secret_value,
                    "match_preview": match.group(0)
                })

        success = scanned > 0
        data = {
            "scanned_urls": scanned,
            "failed_urls": failed,
            "leaks_found": len(findings),
            "findings": findings
        }

        # Deduplicate findings by secret
        unique_findings = []
        seen_secrets = set()
        for f in findings:
            if f["secret"] not in seen_secrets:
                seen_secrets.add(f["secret"])
                unique_findings.append(f)
        data["findings"] = unique_findings
        data["leaks_found"] = len(unique_findings)

        return ToolResult(
            tool_name=self.name,
            success=success,
            data=data,
            raw_output=json.dumps(data, indent=2),
            command_used=f"secret_scanner {len(url_list)} URLs",
        )

"""
Tool Auto-Updater — Downloads latest tool binaries from GitHub Releases.

Detects current OS/architecture and downloads the correct binary.
Checks local version vs latest GitHub release; updates only when needed.
Saves binaries to ~/.local/bin/ (no Go compiler required).
"""

from __future__ import annotations

import asyncio
import gzip
import io
import json
import logging
import os
import platform
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

# ─── Install directory ──────────────────────────────────────
INSTALL_DIR = Path.home() / ".local" / "bin"
VERSION_CACHE_FILE = Path.home() / ".local" / "share" / "security_agent" / "tool_versions.json"


@dataclass
class GitHubToolInfo:
    """GitHub release info for a tool."""
    name: str                         # e.g. "nuclei"
    repo: str                         # e.g. "projectdiscovery/nuclei"
    binary_name: str = ""             # binary name inside archive (default = name)
    asset_pattern: str = ""           # regex pattern for release asset filename
    post_install: list[str] = field(default_factory=list)  # commands to run after install
    # Some repos (e.g. gobuster) use Title-Case: "Linux", "Windows", "Darwin" / "x86_64" "arm64"
    os_format: str = "lower"          # "lower" (linux) or "title" (Linux)
    arch_format: str = "pd"           # "pd" (amd64) or "native" (x86_64)


def _detect_platform() -> tuple[str, str]:
    """Detect OS and architecture for GitHub release asset matching."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Normalize OS
    os_name = {
        "linux": "linux",
        "darwin": "darwin",
        "windows": "windows",
    }.get(system, system)

    # Normalize architecture
    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "armv7",
    }.get(machine, machine)

    return os_name, arch


def _build_asset_patterns(tool_info: "GitHubToolInfo", os_name: str, arch: str) -> list[str]:
    """Build multiple regex patterns to match correct release asset, accounting for naming variations."""
    # Map arch to native names
    arch_native = {"amd64": "x86_64", "arm64": "arm64", "armv7": "armv7l"}.get(arch, arch)

    # OS and arch variants to try
    os_variants = [os_name, os_name.capitalize()]  # ["linux", "Linux"]
    arch_variants = list(dict.fromkeys([arch, arch_native]))  # ["amd64", "x86_64"]  deduplicated

    patterns = []
    for o in os_variants:
        for a in arch_variants:
            patterns.append(rf"(?i){re.escape(tool_info.name)}_[\d.]+_{o}_{a}\.(zip|tar\.gz|tgz)")
            patterns.append(rf"(?i){re.escape(tool_info.name)}_{o}_{a}\.(zip|tar\.gz|tgz)")
    return patterns


def _build_asset_pattern(tool_name: str, os_name: str, arch: str) -> str:
    """Legacy single-pattern builder (kept for compatibility)."""
    return rf"(?i){re.escape(tool_name)}_[\d.]+_{os_name}_{arch}\.(zip|tar\.gz)"


# ─── Tool Registry ─────────────────────────────────────────

GITHUB_TOOLS: dict[str, GitHubToolInfo] = {
    "nuclei": GitHubToolInfo(
        name="nuclei",
        repo="projectdiscovery/nuclei",
        post_install=["nuclei", "-update-templates", "-silent"],
    ),
    "subfinder": GitHubToolInfo(
        name="subfinder",
        repo="projectdiscovery/subfinder",
    ),
    "httpx": GitHubToolInfo(
        name="httpx",
        repo="projectdiscovery/httpx",
    ),
    "naabu": GitHubToolInfo(
        name="naabu",
        repo="projectdiscovery/naabu",
    ),
    "katana": GitHubToolInfo(
        name="katana",
        repo="projectdiscovery/katana",
    ),
    "dnsx": GitHubToolInfo(
        name="dnsx",
        repo="projectdiscovery/dnsx",
    ),
    # ffuf uses ProjectDiscovery-style naming
    "ffuf": GitHubToolInfo(
        name="ffuf",
        repo="ffuf/ffuf",
    ),
    # gobuster uses Title-Case: gobuster_Linux_x86_64.tar.gz
    "gobuster": GitHubToolInfo(
        name="gobuster",
        repo="OJ/gobuster",
        os_format="title",    # Linux not linux
        arch_format="native", # x86_64 not amd64
    ),
    # amass uses similar Title-Case conventions
    "amass": GitHubToolInfo(
        name="amass",
        repo="owasp-amass/amass",
        os_format="title",
        arch_format="native",
    ),
}


class ToolUpdater:
    """Auto-update tools by downloading prebuilt binaries from GitHub Releases."""

    def __init__(self):
        self.os_name, self.arch = _detect_platform()
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        VERSION_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._version_cache = self._load_version_cache()

        # Ensure INSTALL_DIR is in PATH
        install_str = str(INSTALL_DIR)
        if install_str not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{install_str}:{os.environ.get('PATH', '')}"

    # ─── Version Cache ──────────────────────────────────────

    def _load_version_cache(self) -> dict[str, str]:
        try:
            if VERSION_CACHE_FILE.exists():
                return json.loads(VERSION_CACHE_FILE.read_text())
        except Exception:
            pass
        return {}

    def _save_version_cache(self) -> None:
        try:
            VERSION_CACHE_FILE.write_text(json.dumps(self._version_cache, indent=2))
        except Exception as e:
            logger.debug(f"Could not save version cache: {e}")

    # ─── GitHub API ─────────────────────────────────────────

    async def _get_latest_release(self, repo: str) -> dict | None:
        """Get latest release info from GitHub API."""
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                resp = await client.get(url, headers={"Accept": "application/vnd.github.v3+json"})
                if resp.status_code == 200:
                    return resp.json()
                logger.warning(f"GitHub API returned {resp.status_code} for {repo}")
        except Exception as e:
            logger.warning(f"Failed to check GitHub releases for {repo}: {e}")
        return None

    def _find_asset(self, release: dict, tool_info: GitHubToolInfo) -> dict | None:
        """Find the correct asset for current OS/arch using multiple naming patterns."""
        assets = release.get("assets", [])
        tool_name = tool_info.name

        # Try all pattern combinations (handles Linux/linux, amd64/x86_64, etc.)
        patterns = _build_asset_patterns(tool_info, self.os_name, self.arch)
        for pattern in patterns:
            for asset in assets:
                if re.match(pattern, asset.get("name", "")):
                    return asset

        # Final fallback: keyword-based match (case-insensitive)
        arch_native = {"amd64": "x86_64", "arm64": "arm64"}.get(self.arch, self.arch)
        skip_exts = (".txt", ".sig", ".sha256", ".pem", ".sbom")
        for asset in assets:
            name = asset.get("name", "").lower()
            if (tool_name in name
                    and self.os_name in name
                    and any(a in name for a in [self.arch, arch_native])
                    and not any(name.endswith(ext) for ext in skip_exts)):
                return asset

        return None

    # ─── Download & Install ─────────────────────────────────

    async def _download_and_install(self, asset: dict, tool_info: GitHubToolInfo) -> bool:
        """Download asset, extract binary, install to INSTALL_DIR."""
        url = asset.get("browser_download_url", "")
        filename = asset.get("name", "")
        tool_name = tool_info.binary_name or tool_info.name

        logger.info(f"⬇️  Downloading {tool_name}: {filename}")

        try:
            async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.content

            # Extract binary from archive
            binary_data = None
            with tempfile.TemporaryDirectory() as tmpdir:
                archive_path = os.path.join(tmpdir, filename)
                with open(archive_path, "wb") as f:
                    f.write(data)

                # Extract archive
                if filename.endswith(".zip"):
                    with zipfile.ZipFile(archive_path) as zf:
                        zf.extractall(tmpdir)
                elif filename.endswith(".tar.gz") or filename.endswith(".tgz"):
                    with tarfile.open(archive_path, "r:gz") as tf:
                        tf.extractall(tmpdir)
                elif filename.endswith(".gz"):
                    with gzip.open(archive_path, "rb") as gz:
                        binary_data = gz.read()

                # Find the binary in extracted files
                if binary_data is None:
                    for root, dirs, files in os.walk(tmpdir):
                        for f in files:
                            if f == tool_name or f == f"{tool_name}.exe":
                                binary_path = os.path.join(root, f)
                                with open(binary_path, "rb") as bf:
                                    binary_data = bf.read()
                                break
                        if binary_data:
                            break

                if binary_data is None:
                    logger.error(f"Could not find {tool_name} binary in {filename}")
                    return False

                # Write binary to install dir
                dest = INSTALL_DIR / tool_name
                dest.write_bytes(binary_data)
                dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

                logger.info(f"✅ {tool_name} installed to {dest}")

                # Run post-install commands
                if tool_info.post_install:
                    cmd = " ".join(tool_info.post_install)
                    logger.info(f"Running post-install: {cmd}")
                    try:
                        proc = await asyncio.create_subprocess_shell(
                            cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        await asyncio.wait_for(proc.communicate(), timeout=120)
                    except Exception as e:
                        logger.warning(f"Post-install command failed: {e}")

                return True

        except Exception as e:
            logger.error(f"Failed to download/install {tool_name}: {e}")
            return False

    # ─── Public API ─────────────────────────────────────────

    async def check_and_update(self, tool_name: str) -> tuple[bool, str]:
        """
        Check if a tool needs updating and install/update if needed.

        Returns:
            (updated: bool, message: str)
        """
        tool_info = GITHUB_TOOLS.get(tool_name)
        if not tool_info:
            return False, f"{tool_name} is not in GitHub tools registry"

        release = await self._get_latest_release(tool_info.repo)
        if not release:
            return False, f"Could not check latest release for {tool_name}"

        latest_version = release.get("tag_name", "").lstrip("v")
        cached_version = self._version_cache.get(tool_name, "")

        # Check if already at latest version
        if cached_version == latest_version:
            binary_path = INSTALL_DIR / (tool_info.binary_name or tool_info.name)
            if binary_path.exists():
                return True, f"{tool_name} is already at latest version ({latest_version})"

        # Find correct asset for this platform
        asset = self._find_asset(release, tool_info)
        if not asset:
            return False, (
                f"No prebuilt binary found for {tool_name} "
                f"({self.os_name}/{self.arch}). "
                f"Available: {[a['name'] for a in release.get('assets', [])]}"
            )

        # Download and install
        success = await self._download_and_install(asset, tool_info)
        if success:
            self._version_cache[tool_name] = latest_version
            self._save_version_cache()
            action = "updated" if cached_version else "installed"
            return True, f"{tool_name} {action} to v{latest_version}"
        else:
            return False, f"Failed to install {tool_name} v{latest_version}"

    async def update_all(self, tool_names: list[str] | None = None) -> dict[str, tuple[bool, str]]:
        """Check and update all GitHub-based tools in parallel."""
        names = tool_names or list(GITHUB_TOOLS.keys())
        names = [n for n in names if n in GITHUB_TOOLS]
        results: dict[str, tuple[bool, str]] = {}

        # Limit concurrent downloads to avoid rate-limiting
        sem = asyncio.Semaphore(4)

        async def _update_one(name: str) -> tuple[str, bool, str]:
            async with sem:
                success, msg = await self.check_and_update(name)
                return name, success, msg

        tasks = [_update_one(name) for name in names]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for item in completed:
            if isinstance(item, Exception):
                logger.warning(f"Update task failed: {item}")
                continue
            name, success, msg = item
            results[name] = (success, msg)
            logger.info(f"  {'✅' if success else '❌'} {name}: {msg}")

        return results

    def get_installed_versions(self) -> dict[str, str]:
        """Return cached version info for all tools."""
        return dict(self._version_cache)


# Global singleton
updater = ToolUpdater()

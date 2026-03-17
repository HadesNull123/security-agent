"""
Wordlist Manager — Auto-downloads SecLists wordlists from GitHub.

Provides 3 sizes for directory brute-force:
  - small  (~5k lines)   — quick scan
  - medium (~100k lines) — normal scan
  - large  (~2M lines)   — deep scan

Saves to ~/.local/share/security_agent/wordlists/
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

# ─── Storage Location ────────────────────────────────────────
WORDLIST_DIR = Path.home() / ".local" / "share" / "security_agent" / "wordlists"

# ─── Wordlist Definitions ────────────────────────────────────
# Raw GitHub URLs from SecLists (danielmiessler/SecLists)
SECLISTS_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"

WORDLISTS = {
    # Directory brute-force
    "dir_small": {
        "path": WORDLIST_DIR / "dir_small.txt",
        "url": f"{SECLISTS_BASE}/Discovery/Web-Content/common.txt",
        "description": "~4,700 common web paths (quick scan)",
        "size_hint": "small",
    },
    "dir_medium": {
        "path": WORDLIST_DIR / "dir_medium.txt",
        "url": f"{SECLISTS_BASE}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
        "description": "~220,000 directory names (normal scan)",
        "size_hint": "medium",
    },
    "dir_large": {
        "path": WORDLIST_DIR / "dir_large.txt",
        "url": f"{SECLISTS_BASE}/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt",
        "description": "~1,270,000 directory names (deep scan)",
        "size_hint": "large",
    },
    # API endpoint discovery
    "api_paths": {
        "path": WORDLIST_DIR / "api_paths.txt",
        "url": f"{SECLISTS_BASE}/Discovery/Web-Content/api/api-endpoints.txt",
        "description": "~600 common API endpoints",
        "size_hint": "small",
    },
    # Backup files
    "backup_files": {
        "path": WORDLIST_DIR / "backup_files.txt",
        "url": f"{SECLISTS_BASE}/Discovery/Web-Content/quickhits.txt",
        "description": "~2,500 common sensitive paths and backup files",
        "size_hint": "small",
    },
    # DNS subdomains
    "subdomains_small": {
        "path": WORDLIST_DIR / "subdomains_small.txt",
        "url": f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-5000.txt",
        "description": "~5,000 common subdomains (quick scan)",
        "size_hint": "small",
    },
    "subdomains_large": {
        "path": WORDLIST_DIR / "subdomains_large.txt",
        "url": f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-110000.txt",
        "description": "~110,000 common subdomains (deep scan)",
        "size_hint": "large",
    },
}

# ─── Scan level → wordlist mapping ──────────────────────────
SCAN_WORDLISTS = {
    "quick":  {"dir": "dir_small",  "subdomains": "subdomains_small", "api": "api_paths"},
    "normal": {"dir": "dir_medium", "subdomains": "subdomains_small", "api": "api_paths"},
    "deep":   {"dir": "dir_large",  "subdomains": "subdomains_large", "api": "api_paths"},
}


class WordlistManager:
    """Download and manage wordlists for directory/DNS brute-force."""

    def __init__(self):
        WORDLIST_DIR.mkdir(parents=True, exist_ok=True)

    def get_wordlist_path(self, name: str) -> str:
        """Return path to wordlist, downloading if not present."""
        if name not in WORDLISTS:
            raise ValueError(f"Unknown wordlist: {name}. Available: {list(WORDLISTS.keys())}")
        return str(WORDLISTS[name]["path"])

    def get_for_scan(self, mode: str, wordlist_type: str) -> str:
        """
        Get the wordlist path for a scan mode and type.

        Args:
            mode: "quick", "normal", or "deep"
            wordlist_type: "dir", "subdomains", or "api"

        Returns:
            Absolute path to wordlist file
        """
        mode = mode.lower()
        if mode not in SCAN_WORDLISTS:
            mode = "normal"
        name = SCAN_WORDLISTS[mode].get(wordlist_type, "dir_medium")
        return self.get_wordlist_path(name)

    def is_available(self, name: str) -> bool:
        """Check if wordlist file exists locally."""
        if name not in WORDLISTS:
            return False
        return WORDLISTS[name]["path"].exists()

    def get_missing(self, names: list[str] | None = None) -> list[str]:
        """Return list of wordlists that need downloading."""
        check = names or list(WORDLISTS.keys())
        return [n for n in check if not self.is_available(n)]

    async def download(self, name: str) -> tuple[bool, str]:
        """Download a single wordlist."""
        if name not in WORDLISTS:
            return False, f"Unknown wordlist: {name}"

        info = WORDLISTS[name]
        dest: Path = info["path"]

        if dest.exists():
            return True, f"{name} already exists ({dest})"

        logger.info(f"⬇️  Downloading wordlist '{name}': {info['description']}")

        try:
            async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
                async with client.stream("GET", info["url"]) as resp:
                    resp.raise_for_status()
                    with open(dest, "wb") as f:
                        async for chunk in resp.aiter_bytes(chunk_size=65536):
                            f.write(chunk)

            size_mb = dest.stat().st_size / (1024 * 1024)
            logger.info(f"✅ {name} downloaded ({size_mb:.1f} MB → {dest})")
            return True, f"{name} downloaded: {dest}"

        except Exception as e:
            # Clean up partial file
            if dest.exists():
                dest.unlink()
            logger.error(f"Failed to download {name}: {e}")
            return False, f"Failed to download {name}: {e}"

    async def ensure_for_scan(self, mode: str) -> dict[str, str]:
        """
        Ensure all wordlists needed for a scan mode are available.
        Downloads missing ones in parallel.

        Returns:
            dict of {wordlist_type: path}
        """
        mode = mode.lower() if mode in SCAN_WORDLISTS else "normal"
        needs = SCAN_WORDLISTS[mode]  # {"dir": "dir_medium", ...}

        # Find missing
        missing = [name for name in needs.values() if not self.is_available(name)]

        if missing:
            logger.info(f"📥 Downloading {len(missing)} wordlist(s) for {mode} scan...")
            tasks = [self.download(name) for name in missing]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for name, result in zip(missing, results):
                if isinstance(result, Exception):
                    logger.warning(f"Wordlist {name} download failed: {result}")
                else:
                    success, msg = result
                    if not success:
                        logger.warning(f"Wordlist {name}: {msg}")

        # Return paths, fallback to system wordlists if download failed
        paths = {}
        for wl_type, name in needs.items():
            wl_path = WORDLISTS[name]["path"]
            if wl_path.exists():
                paths[wl_type] = str(wl_path)
            else:
                # Fallback to system wordlists
                system_wl = "/usr/share/wordlists/dirb/common.txt"
                if not os.path.exists(system_wl):
                    system_wl = "/usr/share/wordlists/common.txt"
                paths[wl_type] = system_wl
                logger.warning(f"Using system fallback wordlist for {wl_type}: {system_wl}")

        return paths


# Global singleton
wordlist_manager = WordlistManager()

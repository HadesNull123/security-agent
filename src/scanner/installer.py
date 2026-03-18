"""
Tool Installer - Automatically installs missing security tools.
Supports Go-based tools (ProjectDiscovery), pip packages, and apt packages.
"""

from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """Information about a security tool and how to install it."""
    name: str
    binary_name: str  # CLI binary name
    install_method: str  # "go", "pip", "apt", "manual"
    install_command: str
    check_command: str = ""  # command to verify installation
    description: str = ""


# Registry of all installable tools
TOOL_REGISTRY: dict[str, ToolInfo] = {
    # ── Recon ──
    "subfinder": ToolInfo(
        name="subfinder",
        binary_name="subfinder",
        install_method="go",
        install_command="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        description="Subdomain discovery tool",
    ),
    "naabu": ToolInfo(
        name="naabu",
        binary_name="naabu",
        install_method="go",
        install_command="sudo apt-get install -y libpcap-dev && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        description="Fast port scanner",
    ),
    "katana": ToolInfo(
        name="katana",
        binary_name="katana",
        install_method="go",
        install_command="go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        description="Web crawler",
    ),
    "httpx": ToolInfo(
        name="httpx",
        binary_name="httpx",
        install_method="go",
        install_command="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        description="HTTP probing and tech detection",
    ),

    "amass": ToolInfo(
        name="amass",
        binary_name="amass",
        install_method="go",
        install_command="go install -v github.com/owasp-amass/amass/v4/...@master",
        description="Comprehensive subdomain enumeration",
    ),
    "whatweb": ToolInfo(
        name="whatweb",
        binary_name="whatweb",
        install_method="apt",
        install_command="sudo apt-get install -y whatweb",
        description="Web technology fingerprinting",
    ),
    "wafw00f": ToolInfo(
        name="wafw00f",
        binary_name="wafw00f",
        install_method="pip",
        install_command="pip install --break-system-packages wafw00f",
        description="WAF detection tool",
    ),

    # ── Scanner ──
    "nuclei": ToolInfo(
        name="nuclei",
        binary_name="nuclei",
        install_method="go",
        install_command="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        description="Template-based vulnerability scanner",
    ),
    "ffuf": ToolInfo(
        name="ffuf",
        binary_name="ffuf",
        install_method="go",
        install_command="go install -v github.com/ffuf/ffuf/v2@latest",
        description="Fast web fuzzer",
    ),
    "gobuster": ToolInfo(
        name="gobuster",
        binary_name="gobuster",
        install_method="go",
        install_command="go install -v github.com/OJ/gobuster/v3@latest",
        description="Directory/DNS brute-forcing",
    ),

    # ── Exploit ──
    "sqlmap": ToolInfo(
        name="sqlmap",
        binary_name="sqlmap",
        install_method="pip",
        install_command="pip install --break-system-packages sqlmap",
        description="SQL injection tool",
    ),
    "commix": ToolInfo(
        name="commix",
        binary_name="commix",
        install_method="pip",
        install_command="pip install --break-system-packages commix",
        description="OS command injection tool",
    ),
    "searchsploit": ToolInfo(
        name="searchsploit",
        binary_name="searchsploit",
        install_method="manual",
        install_command="git clone https://gitlab.com/exploit-database/exploitdb.git ~/.local/share/exploitdb && mkdir -p ~/.local/bin && ln -sf ~/.local/share/exploitdb/searchsploit ~/.local/bin/searchsploit && chmod +x ~/.local/share/exploitdb/searchsploit",
        description="Exploit database search tool",
    ),
    "dnsx": ToolInfo(
        name="dnsx",
        binary_name="dnsx",
        install_method="go",
        install_command="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        description="Fast DNS resolution and enumeration toolkit",
    ),
    "nikto": ToolInfo(
        name="nikto",
        binary_name="nikto",
        install_method="apt",
        install_command="sudo apt-get install -y nikto",
        description="Web server vulnerability scanner",
    ),
    "testssl": ToolInfo(
        name="testssl",
        binary_name="testssl.sh",
        install_method="manual",
        install_command="git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/.local/share/testssl && mkdir -p ~/.local/bin && ln -sf ~/.local/share/testssl/testssl.sh ~/.local/bin/testssl.sh",
        description="SSL/TLS configuration testing tool",
    ),
    "secret_scanner": ToolInfo(
        name="secret_scanner",
        binary_name="__builtin__",
        install_method="builtin",
        install_command="",
        description="Built-in credential leak scanner (pure Python, no install needed)",
    ),
    "email_security": ToolInfo(
        name="email_security",
        binary_name="__builtin__",
        install_method="builtin",
        install_command="",
        description="Built-in email security checker (SPF, DKIM, DMARC — pure Python, no install needed)",
    ),
    "dalfox": ToolInfo(
        name="dalfox",
        binary_name="dalfox",
        install_method="manual",
        install_command=(
            "mkdir -p ~/.local/bin && "
            "curl -sL $(curl -s https://api.github.com/repos/hahwul/dalfox/releases/latest "
            "| grep 'browser_download_url.*linux_amd64.tar.gz' | head -1 | cut -d'\"' -f4) "
            "| tar xz -C /tmp && mv /tmp/dalfox ~/.local/bin/ && chmod +x ~/.local/bin/dalfox"
        ),
        description="XSS vulnerability scanner (reflected, stored, DOM-based XSS)",
    ),
    "crlfuzz": ToolInfo(
        name="crlfuzz",
        binary_name="crlfuzz",
        install_method="manual",
        install_command=(
            "mkdir -p ~/.local/bin && "
            "curl -sL $(curl -s https://api.github.com/repos/dwisiswant0/crlfuzz/releases/latest "
            "| grep 'browser_download_url.*linux_amd64.tar.gz' | head -1 | cut -d'\"' -f4) "
            "| tar xz -C /tmp && mv /tmp/crlfuzz ~/.local/bin/ && chmod +x ~/.local/bin/crlfuzz"
        ),
        description="CRLF injection scanner (HTTP response splitting)",
    ),
    "corscanner": ToolInfo(
        name="corscanner",
        binary_name="cors",
        install_method="pip",
        install_command="pip install --break-system-packages corscanner",
        description="CORS misconfiguration scanner",
    ),
}


class ToolInstaller:
    """Automatically installs missing security tools."""

    def __init__(self):
        self._go_available: bool | None = None
        # Ensure ~/go/bin and ~/.local/bin are in PATH with HIGH priority
        # This prevents Python package CLIs (e.g. httpx) from shadowing Go binaries
        go_bin = os.path.expanduser("~/go/bin")
        local_bin = os.path.expanduser("~/.local/bin")
        current_path = os.environ.get("PATH", "")
        prepend_paths = []
        if go_bin not in current_path:
            prepend_paths.append(go_bin)
        if local_bin not in current_path:
            prepend_paths.append(local_bin)
        if prepend_paths:
            os.environ["PATH"] = ":".join(prepend_paths) + ":" + current_path

    def is_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool binary exists in PATH.

        Special handling for:
        - Go tools that conflict with Python packages (e.g. 'httpx')
        - Builtin Python tools (e.g. 'secret_scanner') — always available
        """
        info = TOOL_REGISTRY.get(tool_name)
        if not info:
            return shutil.which(tool_name) is not None

        # Builtin tools are always available (pure Python, no external binary)
        if info.install_method == "builtin":
            return True

        # For Go-installed tools, check ~/go/bin first (authoritative location)
        if info.install_method == "go":
            go_bin_path = os.path.expanduser(f"~/go/bin/{info.binary_name}")
            if os.path.isfile(go_bin_path) and os.access(go_bin_path, os.X_OK):
                return True
            # For httpx specifically: Python httpx library also installs a CLI,
            # so shutil.which("httpx") may find the WRONG binary.
            # Only trust shutil.which if the resolved path contains "go/bin".
            if info.binary_name == "httpx":
                resolved = shutil.which("httpx")
                if resolved and "go/bin" in resolved:
                    return True
                return False  # Python httpx found, not Go httpx


        return shutil.which(info.binary_name) is not None

    def get_missing_tools(self, tool_names: list[str]) -> list[str]:
        """Return list of tools that are not installed."""
        return [name for name in tool_names if not self.is_tool_installed(name)]

    def check_prerequisites(self) -> dict[str, bool]:
        """Check which install methods are available."""
        return {
            "go": shutil.which("go") is not None,
            "pip": shutil.which("pip") is not None or shutil.which("pip3") is not None,
            "apt": shutil.which("apt-get") is not None,
            "manual": shutil.which("git") is not None,  # manual installs use git clone
            "builtin": True,  # Always available
        }

    async def install_tool(self, tool_name: str) -> tuple[bool, str]:
        """
        Install a single tool.
        For Go tools, tries GitHub Releases binary first (no Go compiler needed),
        then falls back to `go install`.

        Returns:
            (success: bool, message: str)
        """
        info = TOOL_REGISTRY.get(tool_name)
        if not info:
            return False, f"Unknown tool: {tool_name}. Not in registry."

        if self.is_tool_installed(tool_name):
            return True, f"{tool_name} is already installed."

        # Builtin tools don't need installation
        if info.install_method == "builtin":
            return True, f"{tool_name} is a built-in Python tool (always available)."

        # ★ For Go tools: try GitHub Releases binary download first
        if info.install_method == "go":
            try:
                from src.scanner.updater import updater, GITHUB_TOOLS
                if tool_name in GITHUB_TOOLS:
                    logger.info(f"Trying GitHub Releases binary for {tool_name}...")
                    success, msg = await updater.check_and_update(tool_name)
                    if success and self.is_tool_installed(tool_name):
                        return True, f"{tool_name} installed via GitHub Releases: {msg}"
                    logger.info(f"GitHub download failed, falling back to go install: {msg}")
            except Exception as e:
                logger.debug(f"GitHub download attempt failed: {e}")

        prereqs = self.check_prerequisites()
        if not prereqs.get(info.install_method, False):
            return False, (
                f"Cannot install {tool_name}: {info.install_method} is not available. "
                f"Please install {info.install_method} first."
            )

        logger.info(f"Installing {tool_name} via {info.install_method}...")

        try:
            proc = await asyncio.create_subprocess_shell(
                info.install_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "GOPATH": os.path.expanduser("~/go")},
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

            if proc.returncode == 0:
                # For Go tools, ensure GOPATH/bin is in PATH
                if info.install_method == "go":
                    go_bin = os.path.expanduser("~/go/bin")
                    if go_bin not in os.environ.get("PATH", ""):
                        os.environ["PATH"] = f"{go_bin}:{os.environ.get('PATH', '')}"

                # For pip tools, ensure ~/.local/bin is in PATH (macOS/Linux)
                if info.install_method == "pip":
                    local_bin = os.path.expanduser("~/.local/bin")
                    if local_bin not in os.environ.get("PATH", ""):
                        os.environ["PATH"] = f"{local_bin}:{os.environ.get('PATH', '')}"

                if self.is_tool_installed(tool_name):
                    logger.info(f"✅ {tool_name} installed successfully.")
                    return True, f"{tool_name} installed successfully."
                else:
                    return False, f"{tool_name} install command succeeded but binary not found in PATH."
            else:
                error = stderr.decode("utf-8", errors="replace")
                return False, f"Failed to install {tool_name}: {error[:500]}"

        except asyncio.TimeoutError:
            return False, f"Installation of {tool_name} timed out (300s)."
        except Exception as e:
            return False, f"Error installing {tool_name}: {str(e)}"

    async def install_all_missing(self, tool_names: list[str]) -> dict[str, tuple[bool, str]]:
        """Install all missing tools and return status for each."""
        missing = self.get_missing_tools(tool_names)
        results = {}
        for name in missing:
            success, msg = await self.install_tool(name)
            results[name] = (success, msg)
        return results

    def get_status(self, tool_names: list[str] | None = None) -> dict[str, dict]:
        """Get installation status of all registered tools."""
        names = tool_names or list(TOOL_REGISTRY.keys())
        status = {}
        for name in names:
            info = TOOL_REGISTRY.get(name)
            installed = self.is_tool_installed(name)
            status[name] = {
                "installed": installed,
                "install_method": info.install_method if info else "unknown",
                "description": info.description if info else "",
            }
        return status


# Global singleton
installer = ToolInstaller()

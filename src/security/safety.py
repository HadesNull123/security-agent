"""
Safety layer for the Security Agent.
Validates commands, enforces scope, and prevents dangerous operations.
Includes exploit code validation via AST analysis.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Directories where wordlists may reside — block everything else
ALLOWED_WORDLIST_DIRS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/opt/wordlists",
    "/opt/seclists",
    "/tmp/",
]

# Characters that should never appear in a target string
_SHELL_META_CHARS = re.compile(r"[;|`$(){}\\!&<>\n\r]")

# Commands that should NEVER be executed
BLOCKED_COMMANDS = [
    "rm -rf /",
    "rm -rf /*",
    "mkfs",
    "dd if=/dev/zero",
    ":(){:|:&};:",  # fork bomb
    "chmod -R 777 /",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "format",
    "init 0",
    "init 6",
    "kill -9 1",
    "userdel",
    "passwd root",
    "> /etc/passwd",
    "> /etc/shadow",
]

# Patterns that indicate dangerous operations
DANGEROUS_PATTERNS = [
    r"rm\s+(-rf?\s+)?/(?!tmp)",  # rm outside of /tmp
    r">\s*/etc/",  # writing to /etc
    r">\s*/dev/",  # writing to /dev
    r"curl.*\|\s*(bash|sh|zsh)",  # piping curl to shell
    r"wget.*\|\s*(bash|sh|zsh)",  # piping wget to shell
    r"eval\s*\(",  # eval in shell
    r"python.*-c.*os\.system",  # python code execution
    r"nc\s+-[el]",  # netcat listeners

    # ── Reverse Shell Patterns ───────────────────────────
    r"bash\s+-i\s+>&?\s*/dev/tcp/",  # bash reverse shell
    r"/dev/tcp/\d+\.\d+\.\d+\.\d+",  # /dev/tcp redirect
    r"mkfifo\s+/tmp/",  # named pipe reverse shell
    r"nc\s+.*-e\s+(/(bin|usr)/)?sh",  # netcat exec shell
    r"ncat\s+.*--exec",  # ncat exec
    r"socat\s+.*exec:",  # socat exec
    r"python.*socket.*connect.*dup2",  # python reverse shell
    r"perl\s+-e\s+.*socket.*INET",  # perl reverse shell
    r"ruby\s+-rsocket\s+-e",  # ruby reverse shell
    r"php\s+-r\s+.*fsockopen",  # php reverse shell
    r"lua\s+-e\s+.*socket",  # lua reverse shell
    r"powershell.*-e\s+[A-Za-z0-9+/=]{20,}",  # encoded powershell
    r"msfvenom",  # payload generation
    r"msfconsole.*exploit",  # direct exploitation (use tool instead)

    # ── Persistence Mechanisms ───────────────────────────
    r"crontab\s+(-[er]|.*\*/)",  # cron jobs
    r"(echo|cat|printf)\s+.*>>\s*/etc/cron",  # cron injection
    r"systemctl\s+(enable|start|mask)",  # systemd persistence
    r"at\s+\d",  # at job scheduling
    r"(echo|cat)\s+.*>>\s*~/\.bashrc",  # bashrc injection
    r"(echo|cat)\s+.*>>\s*~/\.profile",  # profile injection
    r"ssh-keygen.*authorized_keys",  # SSH key planting

    # ── Crypto Miners ────────────────────────────────────
    r"xmrig|minergate|coinhive|cryptonight",
    r"stratum\+tcp://",  # mining pool connection

    # ── Data Exfiltration ────────────────────────────────
    r"curl\s+.*-d\s+@/etc/(passwd|shadow)",  # credential exfil
    r"wget\s+--post-file=/etc/",  # file exfil via POST
    r"base64\s+/etc/(passwd|shadow)",  # encode sensitive files

    # ── Privilege Escalation ─────────────────────────────
    r"chmod\s+[u+]*s\s+",  # SUID bit setting
    r"chown\s+root",  # ownership change to root
    r"sudo\s+-i",  # interactive sudo
    r"su\s+-\s*$",  # su to root
]


class SafetyError(Exception):
    """Raised when a safety check fails."""
    pass


class SafetyGuard:
    """
    Validates and sanitizes operations before execution.
    Enforces target scope and blocks dangerous commands.
    """

    def __init__(self, allowed_scope: list[str] | None = None, safe_mode: bool = True):
        """
        Args:
            allowed_scope: List of allowed target domains/CIDRs. Empty = all allowed.
            safe_mode: If True, require confirmation for exploitation phase.
        """
        self.allowed_scope = allowed_scope or []
        self.safe_mode = safe_mode

    # ── Target Sanitization ──────────────────────────────────

    @staticmethod
    def sanitize_target(target: str) -> str:
        """Strip shell metacharacters that could be used for injection.

        Since commands run via create_subprocess_exec (no shell), these
        chars have no effect, but stripping them prevents the LLM from
        constructing payloads that could be dangerous if execution mode
        ever changes.
        """
        return _SHELL_META_CHARS.sub("", target).strip()

    def validate_all_targets(self, args: dict) -> None:
        """Check scope for *every* argument that could contain a target.

        The LLM may embed extra targets in fields like ``blind_url``,
        ``urls``, or ``cookie`` header values.  We inspect all of them.
        """
        target_keys = {"target", "blind_url", "urls"}
        for key in target_keys:
            value = args.get(key, "")
            if not value:
                continue
            # Handle comma-separated lists (e.g. urls field)
            for fragment in str(value).split(","):
                fragment = fragment.strip()
                if fragment:
                    self.validate_target(fragment)

    @staticmethod
    def validate_wordlist_path(path: str) -> None:
        """Ensure wordlist paths resolve inside allowed directories.

        Prevents the LLM from reading /etc/shadow or other sensitive files
        by passing them as a "wordlist".
        """
        if not path:
            return
        resolved = os.path.realpath(path)
        for allowed_dir in ALLOWED_WORDLIST_DIRS:
            if resolved.startswith(os.path.realpath(allowed_dir)):
                return
        raise SafetyError(
            f"Wordlist path '{path}' is outside allowed directories. "
            f"Allowed: {ALLOWED_WORDLIST_DIRS}"
        )

    def validate_command(self, command: str) -> bool:
        """
        Check if a command is safe to execute.

        Raises:
            SafetyError: If the command is blocked.
        """
        command_lower = command.lower().strip()

        # Check against blocked commands
        for blocked in BLOCKED_COMMANDS:
            if blocked in command_lower:
                raise SafetyError(f"Blocked dangerous command: {blocked}")

        # Check dangerous patterns
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, command_lower):
                raise SafetyError(f"Command matches dangerous pattern: {pattern}")

        return True

    def validate_target(self, target: str) -> bool:
        """
        Validate that a target is within the allowed scope.

        Raises:
            SafetyError: If the target is out of scope.
        """
        if not self.allowed_scope:
            # No scope restriction
            return True

        # Parse target
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.hostname or target

        for allowed in self.allowed_scope:
            # Check domain match
            if host == allowed or host.endswith(f".{allowed}"):
                return True

            # Check CIDR match
            try:
                network = ipaddress.ip_network(allowed, strict=False)
                try:
                    ip = ipaddress.ip_address(host)
                    if ip in network:
                        return True
                except ValueError:
                    pass
            except ValueError:
                pass

        raise SafetyError(
            f"Target '{target}' is outside allowed scope. "
            f"Allowed: {self.allowed_scope}"
        )

    def validate_tool_args(self, tool_name: str, args: dict) -> bool:
        """Validate tool-specific arguments for safety."""
        # ── Wordlist path validation (applies to any tool) ─────────
        for key in ("wordlist",):
            if wl := args.get(key):
                self.validate_wordlist_path(wl)

        # SQLMap: prevent --os-pwn and --os-bof
        if tool_name == "sqlmap":
            dangerous_flags = {"os_pwn", "os_bof", "reg_read", "reg_add", "reg_del"}
            for flag in dangerous_flags:
                if args.get(flag):
                    raise SafetyError(f"Blocked dangerous sqlmap flag: --{flag.replace('_', '-')}")

        # Commix: validate OS commands
        if tool_name == "commix":
            if os_cmd := args.get("os_cmd"):
                self.validate_command(os_cmd)

        # Metasploit: only allow when CVE is specified
        if tool_name == "metasploit":
            action = args.get("action", "search")
            if action == "exploit":
                search_query = args.get("search_query", "")
                module = args.get("module", "")
                # Must reference a CVE
                has_cve = bool(
                    re.search(r"cve[-_]?\d{4}[-_]\d+", search_query, re.IGNORECASE)
                    or re.search(r"cve[-_]?\d{4}[-_]\d+", module, re.IGNORECASE)
                )
                if not has_cve:
                    raise SafetyError(
                        "Metasploit exploitation requires a specific CVE reference. "
                        "For non-CVE exploits, use the custom_exploit tool to write Python code."
                    )
                if self.safe_mode:
                    raise SafetyError(
                        "Metasploit exploitation is restricted in safe mode. "
                        "Set safe_mode=False to enable."
                    )

        return True

    def validate_exploit_code(self, code: str) -> bool:
        """
        Validate AI-generated exploit code via sandbox AST analysis.

        Raises:
            SafetyError: If the code contains dangerous patterns.
        """
        from src.security.sandbox import ExploitSandbox
        sandbox = ExploitSandbox(allowed_scope=self.allowed_scope)
        violations = sandbox.validate_code(code)
        if violations:
            raise SafetyError(
                "Exploit code validation failed:\n"
                + "\n".join(f"  - {v}" for v in violations)
            )
        return True

    def check_all(self, target: str, tool_name: str, args: dict, command: str = "") -> bool:
        """Run all safety checks."""
        # Sanitize the primary target
        target = self.sanitize_target(target)
        self.validate_target(target)
        # Check scope for all target-like arguments
        self.validate_all_targets(args)
        self.validate_tool_args(tool_name, args)
        if command:
            self.validate_command(command)
        return True


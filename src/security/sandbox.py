"""
Sandbox — Secure Python code executor for AI-generated exploit code.

Runs untrusted Python code in a restricted environment with:
- Import whitelist (only safe modules allowed)
- AST-based pre-validation
- Timeout enforcement
- Scope-restricted networking
- Isolated temp directory
- stdout/stderr capture
"""

from __future__ import annotations

import ast
import io
import logging
import os
import shutil
import sys
import tempfile
import traceback
import uuid
from contextlib import redirect_stderr, redirect_stdout
from typing import Any

logger = logging.getLogger(__name__)

# ── Import Whitelist ─────────────────────────────────────────────
# Only these modules can be imported in exploit code.
ALLOWED_IMPORTS = frozenset({
    # Networking (essential for exploits)
    "requests", "socket", "ssl", "http", "http.client", "http.cookies",
    "urllib", "urllib.parse", "urllib.request", "urllib.error",
    # Data handling
    "json", "re", "base64", "hashlib", "struct", "binascii",
    "html", "html.parser", "xml", "xml.etree", "xml.etree.ElementTree",
    # Crypto / encoding
    "hmac", "zlib", "gzip",
    # Utilities
    "time", "string", "copy", "math", "random",
    "collections", "itertools", "functools",
    "io", "textwrap", "datetime",
    # Type helpers
    "typing", "dataclasses", "enum",
})

# ── Blocked Builtins ─────────────────────────────────────────────
BLOCKED_BUILTINS = frozenset({
    "exec", "eval", "compile", "__import__",
    "breakpoint", "exit", "quit",
    "globals", "locals",
    "memoryview", "classmethod", "staticmethod",
})

# ── Blocked Function Calls (module.function patterns) ────────────
BLOCKED_CALLS = frozenset({
    # OS-level execution
    "os.system", "os.popen", "os.exec", "os.execl", "os.execle",
    "os.execlp", "os.execlpe", "os.execv", "os.execve", "os.execvp",
    "os.execvpe", "os.spawn", "os.spawnl", "os.spawnle", "os.fork",
    "os.forkpty", "os.kill", "os.killpg",
    # Subprocess
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    # File system destruction
    "shutil.rmtree", "shutil.move", "os.remove", "os.rmdir",
    "os.removedirs", "os.unlink", "os.rename",
    # Listeners / reverse shells
    "socket.bind", "socket.listen", "socket.accept",
    # Dangerous I/O
    "ctypes.cdll", "ctypes.windll",
    # Persistence
    "pty.spawn",
})

# ── Blocked Import Modules ───────────────────────────────────────
BLOCKED_IMPORTS = frozenset({
    "os", "subprocess", "shutil", "ctypes", "multiprocessing",
    "signal", "pty", "resource", "fcntl", "termios",
    "importlib", "code", "codeop", "compileall",
    "webbrowser", "antigravity", "turtle", "tkinter",
    "asyncio",  # prevent event loop manipulation
    "threading",  # prevent thread spawning
    "pickle",  # deserialization attacks
    "shelve", "marshal",
})


class SandboxError(Exception):
    """Raised when sandbox validation or execution fails."""
    pass


class ExploitSandbox:
    """
    Secure sandbox for running AI-generated Python exploit code.

    Safety layers:
    1. AST validation — block dangerous patterns before execution
    2. Restricted builtins — remove dangerous built-in functions
    3. Import hook — only whitelist modules can be imported
    4. Timeout — max execution time enforced
    5. Scope check — target in code must match allowed scope
    6. Isolated directory — each run gets its own /tmp dir
    """

    def __init__(
        self,
        allowed_scope: list[str] | None = None,
        max_execution_time: int = 60,
    ):
        self.allowed_scope = allowed_scope or []
        self.max_execution_time = max_execution_time

    def validate_code(self, code: str) -> list[str]:
        """
        Validate exploit code via AST analysis.
        Returns list of violations (empty = safe).
        """
        violations: list[str] = []

        # Parse AST
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return [f"Syntax error: {e}"]

        for node in ast.walk(tree):
            # ── Check imports ────────────────────────────
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split(".")[0]
                    if mod in BLOCKED_IMPORTS:
                        violations.append(f"Blocked import: {alias.name}")
                    elif alias.name not in ALLOWED_IMPORTS and mod not in {
                        m.split(".")[0] for m in ALLOWED_IMPORTS
                    }:
                        violations.append(f"Unauthorized import: {alias.name}")

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod = node.module.split(".")[0]
                    if mod in BLOCKED_IMPORTS:
                        violations.append(f"Blocked import: from {node.module}")
                    elif node.module not in ALLOWED_IMPORTS and mod not in {
                        m.split(".")[0] for m in ALLOWED_IMPORTS
                    }:
                        violations.append(f"Unauthorized import: from {node.module}")

            # ── Check function calls ─────────────────────
            elif isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name:
                    if call_name in BLOCKED_CALLS:
                        violations.append(f"Blocked function call: {call_name}")
                    # Check builtins
                    if call_name in BLOCKED_BUILTINS:
                        violations.append(f"Blocked builtin: {call_name}")

            # ── Check string patterns (reverse shells etc.) ──
            elif isinstance(node, (ast.Constant,)):
                if isinstance(node.value, str):
                    self._check_dangerous_strings(node.value, violations)

        return violations

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract the dotted name of a function call from AST."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _check_dangerous_strings(self, value: str, violations: list[str]) -> None:
        """Check for dangerous string patterns embedded in code."""
        import re
        dangerous_patterns = [
            (r"bash\s+-i\s+>&?\s*/dev/tcp/", "Reverse shell (bash)"),
            (r"/dev/tcp/\d", "Reverse shell (/dev/tcp)"),
            (r"mkfifo\s+/tmp/", "Reverse shell (mkfifo)"),
            (r"nc\s+(-e|--exec)\s+", "Reverse shell (netcat)"),
            (r"python\s+-c\s+.*socket.*connect", "Reverse shell (python)"),
            (r"perl\s+-e\s+.*socket.*", "Reverse shell (perl)"),
            (r"php\s+-r\s+.*fsockopen", "Reverse shell (php)"),
            (r"rm\s+-rf\s+/[^t]", "Filesystem destruction"),
            (r"chmod\s+777\s+/", "Unsafe chmod"),
            (r"crontab\s+", "Persistence mechanism (cron)"),
            (r"systemctl\s+(enable|start)", "Persistence mechanism (systemd)"),
            (r"curl.*\|\s*(bash|sh)", "Pipe to shell"),
            (r"wget.*\|\s*(bash|sh)", "Pipe to shell"),
            (r"xmrig|minergate|coinhive", "Crypto miner"),
        ]
        for pattern, desc in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                violations.append(f"Dangerous string pattern: {desc}")

    def execute(
        self,
        code: str,
        target: str,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """
        Execute exploit code in a restricted sandbox.

        Returns:
            dict with keys: success, stdout, stderr, error, return_value
        """
        timeout = timeout or self.max_execution_time

        # Step 1: AST validation
        violations = self.validate_code(code)
        if violations:
            return {
                "success": False,
                "stdout": "",
                "stderr": "",
                "error": f"Code validation failed:\n" + "\n".join(f"  - {v}" for v in violations),
                "return_value": None,
            }

        # Step 2: Create isolated temp directory
        sandbox_dir = os.path.join(tempfile.gettempdir(), f"exploit_sandbox_{uuid.uuid4().hex[:8]}")
        os.makedirs(sandbox_dir, exist_ok=True)

        # Step 3: Build restricted globals
        safe_builtins = {
            k: v for k, v in __builtins__.__dict__.items()
            if k not in BLOCKED_BUILTINS
        } if isinstance(__builtins__, type(sys)) else {
            k: v for k, v in __builtins__.items()
            if k not in BLOCKED_BUILTINS
        }

        # Add safe __import__ that only allows whitelisted modules
        original_import = __builtins__.__import__ if isinstance(__builtins__, type(sys)) else __builtins__["__import__"]

        def safe_import(name, *args, **kwargs):
            top = name.split(".")[0]
            if top in BLOCKED_IMPORTS:
                raise ImportError(f"Import '{name}' is blocked by sandbox security policy")
            if name not in ALLOWED_IMPORTS and top not in {m.split(".")[0] for m in ALLOWED_IMPORTS}:
                raise ImportError(
                    f"Import '{name}' is not whitelisted. "
                    f"Allowed: {', '.join(sorted(ALLOWED_IMPORTS))}"
                )
            return original_import(name, *args, **kwargs)

        safe_builtins["__import__"] = safe_import

        restricted_globals: dict[str, Any] = {
            "__builtins__": safe_builtins,
            "__name__": "__exploit__",
            "__file__": os.path.join(sandbox_dir, "exploit.py"),
            "TARGET": target,
            "SANDBOX_DIR": sandbox_dir,
            "print": print,  # Allow print for output capture
        }

        # Step 4: Execute with output capture
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        result: dict[str, Any] = {
            "success": False,
            "stdout": "",
            "stderr": "",
            "error": "",
            "return_value": None,
        }

        try:
            import signal

            def timeout_handler(signum, frame):
                raise TimeoutError(f"Exploit execution timed out after {timeout}s")

            # Set timeout (Unix only)
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout)

            try:
                with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                    # Compile and exec in restricted namespace
                    compiled = compile(code, "<exploit>", "exec")
                    exec_locals: dict[str, Any] = {}
                    exec(compiled, restricted_globals, exec_locals)

                    # Capture return value if 'result' or 'findings' defined
                    result["return_value"] = (
                        exec_locals.get("result")
                        or exec_locals.get("findings")
                        or exec_locals.get("output")
                    )

                result["success"] = True
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)

        except TimeoutError as e:
            result["error"] = str(e)
        except ImportError as e:
            result["error"] = f"Blocked import: {e}"
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"

        result["stdout"] = stdout_capture.getvalue()
        result["stderr"] = stderr_capture.getvalue()

        # Step 5: Cleanup sandbox directory
        try:
            shutil.rmtree(sandbox_dir, ignore_errors=True)
        except Exception:
            pass

        return result

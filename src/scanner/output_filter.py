"""
Output Filter - Truncates and cleans verbose tool outputs before passing to LLM.
Extracts key information and discards noise to save tokens.
"""

from __future__ import annotations

import json
import re
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Maximum output sizes (in characters)
MAX_RAW_OUTPUT = 50000       # Max stored in database
MAX_LLM_OUTPUT = 4000        # Default max sent to LLM per tool result
MAX_SUMMARY_OUTPUT = 2000    # Max for summary context

# Adaptive limits: high-value tools get more space, low-value tools get less
TOOL_OUTPUT_LIMITS: dict[str, int] = {
    # High-value: findings/vulns that LLM must see fully
    "nuclei": 8000,
    "zap": 8000,
    "acunetix": 8000,
    "sqlmap": 6000,
    "commix": 6000,
    "searchsploit": 4000,
    "metasploit": 6000,
    # Medium-value: useful but can be summarized
    "ffuf": 4000,
    "gobuster": 4000,
    "katana": 3000,
    # Low-value: mostly structural data
    "subfinder": 2000,
    "naabu": 2000,
    "httpx": 2500,
    "whatweb": 2500,
    "wafw00f": 1500,
    "amass": 2000,
    "dnsx": 2000,
    # Scanner tools
    "nikto": 6000,
    "testssl": 4000,
    # Exploit tools
    "custom_exploit": 5000,
}

# Patterns to strip from outputs (noise)
NOISE_PATTERNS = [
    r'\x1b\[[0-9;]*m',                    # ANSI color codes
    r'^\s*$',                               # Empty lines
    r'^[-=]{3,}$',                          # Separator lines
    r'^\s*#.*$',                            # Comment lines
    r'^\[INF\].*$',                         # Info log lines
    r'^\[WRN\].*$',                         # Warning log lines
    r'^\[DBG\].*$',                         # Debug log lines
    r'^\s*\d+\.\d+\.\d+.*compiled\s+\d+',  # Version/compilation info
    r'^\s*Using\s+default\s+',             # Default value messages
    r'^\s*Loading\s+templates?\s+',        # Template loading messages
]

# Credential patterns to redact from output (prevent data leak to LLM/reports)
CREDENTIAL_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*\S+'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)(token|bearer|auth)\s*[=:]\s*[A-Za-z0-9\-_.]{20,}'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)(secret[_-]?key)\s*[=:]\s*\S+'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*\S+'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)(private[_-]?key)\s*[=:]\s*\S+'), r'\1=***REDACTED***'),
    (re.compile(r'(?i)(Authorization:\s*Bearer\s+)\S+', re.IGNORECASE), r'\1***REDACTED***'),
]


class OutputFilter:
    """
    Filters and truncates tool outputs to reduce token usage.
    """

    def __init__(
        self,
        max_llm_output: int = MAX_LLM_OUTPUT,
        max_raw_output: int = MAX_RAW_OUTPUT,
    ):
        self.max_llm_output = max_llm_output
        self.max_raw_output = max_raw_output

    def clean(self, output: str) -> str:
        """Remove noise patterns and redact credentials from output."""
        # Redact credentials first (before any truncation)
        for pattern, replacement in CREDENTIAL_PATTERNS:
            output = pattern.sub(replacement, output)

        lines = output.splitlines()
        cleaned = []
        for line in lines:
            skip = False
            for pattern in NOISE_PATTERNS:
                if re.match(pattern, line):
                    skip = True
                    break
            if not skip:
                cleaned.append(line)
        return "\n".join(cleaned)

    def truncate_for_storage(self, output: str) -> str:
        """Truncate output for database storage."""
        if len(output) <= self.max_raw_output:
            return output
        half = self.max_raw_output // 2
        return (
            output[:half]
            + f"\n\n... [{len(output) - self.max_raw_output} chars truncated] ...\n\n"
            + output[-half:]
        )

    def truncate_for_llm(self, output: str) -> str:
        """Truncate output for LLM consumption. Keeps beginning and end."""
        output = self.clean(output)
        if len(output) <= self.max_llm_output:
            return output

        # Keep first 60% and last 40%
        head_size = int(self.max_llm_output * 0.6)
        tail_size = self.max_llm_output - head_size - 100  # space for truncation msg
        return (
            output[:head_size]
            + f"\n\n... [{len(output)} total chars, showing head+tail] ...\n\n"
            + output[-tail_size:]
        )

    def filter_json_results(self, data: dict[str, Any], max_items: int = 30) -> dict[str, Any]:
        """
        Filter JSON result data to reduce size while keeping important info.
        Limits list items and removes verbose fields.
        """
        filtered = {}
        for key, value in data.items():
            if isinstance(value, list):
                if len(value) > max_items:
                    filtered[key] = value[:max_items]
                    filtered[f"{key}_total"] = len(value)
                    filtered[f"{key}_note"] = f"Showing first {max_items} of {len(value)} results"
                else:
                    filtered[key] = value
            elif isinstance(value, str) and len(value) > 1000:
                filtered[key] = value[:1000] + "..."
            else:
                filtered[key] = value
        return filtered

    def summarize_tool_result(self, tool_name: str, data: dict[str, Any], raw_output: str) -> str:
        """
        Create a concise summary of a tool result for the LLM.
        Prioritizes structured data over raw output.
        Uses adaptive limits based on tool importance.
        """
        limit = TOOL_OUTPUT_LIMITS.get(tool_name, self.max_llm_output)
        parts = [f"[{tool_name}] Results:"]

        # Use structured data if available
        if data:
            filtered = self.filter_json_results(data)
            json_str = json.dumps(filtered, indent=2, default=str)
            if len(json_str) <= limit:
                parts.append(json_str)
            else:
                # Further reduce: only keep counts and key fields
                summary_data = {}
                for k, v in filtered.items():
                    if isinstance(v, (int, float, bool, str)):
                        summary_data[k] = v
                    elif isinstance(v, list):
                        summary_data[f"{k}_count"] = len(v)
                        # Show first items as sample, more for high-value tools
                        sample_size = 10 if tool_name in ("nuclei", "zap", "acunetix") else 5
                        summary_data[f"{k}_sample"] = v[:sample_size]
                    elif isinstance(v, dict):
                        summary_data[k] = v
                parts.append(json.dumps(summary_data, indent=2, default=str))
        elif raw_output:
            parts.append(self.truncate_for_llm(raw_output))

        result = "\n".join(parts)
        return result[:limit]

    def estimate_tokens(self, text: str) -> int:
        """Rough token estimate (1 token ≈ 4 chars for English, ≈ 2 for code)."""
        # Simple heuristic
        return len(text) // 3


# Global singleton
output_filter = OutputFilter()

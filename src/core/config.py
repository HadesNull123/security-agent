"""
Configuration management for Security Agent.
Supports multiple LLM providers and external tool API configurations.
All settings can be configured via .env file or environment variables.
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    GEMINI = "gemini"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


class ScanPhase(str, Enum):
    """Phases of the security scan pipeline."""
    RECON = "recon"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


class Severity(str, Enum):
    """Vulnerability severity levels aligned with CVSS."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LLMConfig(BaseSettings):
    """LLM provider configuration."""
    provider: LLMProvider = LLMProvider.GEMINI
    model: str = "gemini-2.5-pro"

    # API Keys
    google_api_key: str = ""
    openai_api_key: str = ""
    anthropic_api_key: str = ""

    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"

    # LLM Parameters
    temperature: float = 0.1
    max_tokens: int = 8192

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}

    @field_validator("provider", mode="before")
    @classmethod
    def validate_provider(cls, v: str) -> LLMProvider:
        if isinstance(v, str):
            return LLMProvider(v.lower())
        return v


class AcunetixConfig(BaseSettings):
    """Acunetix API configuration."""
    api_url: str = ""
    api_key: str = ""
    verify_ssl: bool = False

    model_config = {"env_prefix": "ACUNETIX_", "env_file": ".env", "extra": "ignore"}


class BurpConfig(BaseSettings):
    """Burp Suite Enterprise API configuration."""
    api_url: str = ""
    api_key: str = ""

    model_config = {"env_prefix": "BURP_", "env_file": ".env", "extra": "ignore"}


class ZAPConfig(BaseSettings):
    """OWASP ZAP API configuration."""
    api_url: str = "http://localhost:8080"
    api_key: str = ""

    model_config = {"env_prefix": "ZAP_", "env_file": ".env", "extra": "ignore"}


class ShodanConfig(BaseSettings):
    """Shodan API configuration."""
    api_key: str = ""

    model_config = {"env_prefix": "SHODAN_", "env_file": ".env", "extra": "ignore"}


class MetasploitConfig(BaseSettings):
    """Metasploit RPC configuration."""
    rpc_host: str = "127.0.0.1"
    rpc_port: int = 55553
    rpc_password: str = ""
    rpc_ssl: bool = True

    model_config = {"env_prefix": "METASPLOIT_", "env_file": ".env", "extra": "ignore"}


class AgentConfig(BaseSettings):
    """Main agent configuration."""
    # LLM
    llm_provider: LLMProvider = LLMProvider.GEMINI
    llm_model: str = "gemini-2.5-pro"

    # Execution limits
    tool_timeout: int = 300
    max_scan_time: int = 3600
    max_retries: int = 3

    # Paths
    report_output_dir: str = "./reports"
    database_path: str = "./data/security_agent.db"
    log_level: str = "INFO"

    # Safety
    safe_mode: bool = True  # Require confirmation before exploitation
    allowed_scope: list[str] = Field(default_factory=list)  # Allowed target CIDRs/domains

    model_config = {"env_prefix": "", "env_file": ".env", "extra": "ignore"}

    def ensure_dirs(self) -> None:
        """Create necessary directories."""
        Path(self.report_output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)


def _is_placeholder(value: str) -> bool:
    """
    Check whether an env var value is a placeholder / not actually configured.

    Returns True (= should be ignored) for:
    - Empty strings or whitespace-only
    - Values starting with 'your-' (e.g. 'your-google-api-key')
    - Common placeholder patterns like 'changeme', 'xxx', 'TODO', 'REPLACE_ME'
    """
    if not value or not value.strip():
        return True

    v = value.strip().lower()

    # Explicit placeholder prefixes/patterns
    placeholder_patterns = (
        "your-", "your_", "enter-", "enter_",
        "replace", "changeme", "change-me", "change_me",
        "xxx", "todo", "fixme", "placeholder",
        "put-your", "put_your", "insert-", "insert_",
        "<", "{", "example",
    )

    for p in placeholder_patterns:
        if v.startswith(p):
            return True

    return False


class Config:
    """Root configuration container. Aggregates all sub-configurations."""

    def __init__(self, env_file: str | None = None):
        if env_file and os.path.exists(env_file):
            os.environ.setdefault("ENV_FILE", env_file)

        self.agent = AgentConfig()
        self.llm = LLMConfig(
            provider=self.agent.llm_provider,
            model=self.agent.llm_model,
        )
        self.acunetix = AcunetixConfig()
        self.burp = BurpConfig()
        self.zap = ZAPConfig()
        self.shodan = ShodanConfig()
        self.metasploit = MetasploitConfig()

        # Clear placeholder / empty values so they're treated as "not configured"
        self._sanitize_configs()

        # Validate LLM API key
        self._validate_llm_config()

    def _sanitize_configs(self) -> None:
        """
        Clear placeholder values loaded from .env so they're treated as not configured.

        Handles cases like:
          ZAP_API_KEY=           → empty string → cleared
          ACUNETIX_API_KEY=your-acunetix-api-key  → placeholder → cleared
          GOOGLE_API_KEY=AIza... → real value → kept
        """
        # Configs with string fields that should be cleared if they're placeholders
        configs_to_check = [
            (self.acunetix, ["api_url", "api_key"]),
            (self.burp, ["api_url", "api_key"]),
            (self.zap, ["api_url", "api_key"]),
            (self.shodan, ["api_key"]),
            (self.metasploit, ["rpc_password"]),
            (self.llm, ["google_api_key", "openai_api_key", "anthropic_api_key"]),
        ]

        for config_obj, fields in configs_to_check:
            for field_name in fields:
                value = getattr(config_obj, field_name, "")
                if isinstance(value, str) and _is_placeholder(value):
                    object.__setattr__(config_obj, field_name, "")

    def _validate_llm_config(self) -> None:
        """Ensure the selected LLM provider has a matching API key."""
        provider = self.llm.provider
        key_map = {
            LLMProvider.GEMINI: ("GOOGLE_API_KEY", self.llm.google_api_key),
            LLMProvider.OPENAI: ("OPENAI_API_KEY", self.llm.openai_api_key),
            LLMProvider.ANTHROPIC: ("ANTHROPIC_API_KEY", self.llm.anthropic_api_key),
        }
        if provider in key_map:
            env_name, key_value = key_map[provider]
            if not key_value:
                import warnings
                warnings.warn(
                    f"LLM provider is '{provider.value}' but {env_name} is not set. "
                    f"The agent will fail when trying to connect. "
                    f"Set {env_name} in your .env file.",
                    UserWarning,
                    stacklevel=2,
                )

    def get_active_api_tools(self) -> dict[str, bool]:
        """Return which external API tools are configured and available."""
        return {
            "acunetix": bool(self.acunetix.api_url and self.acunetix.api_key),
            "burp": bool(self.burp.api_url and self.burp.api_key),
            "zap": bool(self.zap.api_key),
            "shodan": bool(self.shodan.api_key),
            "metasploit": bool(self.metasploit.rpc_password),
        }

    def to_summary(self) -> dict[str, Any]:
        """Return a safe summary (no secrets) for display."""
        api_status = self.get_active_api_tools()
        return {
            "llm_provider": self.llm.provider.value,
            "llm_model": self.llm.model,
            "tool_timeout": self.agent.tool_timeout,
            "max_scan_time": self.agent.max_scan_time,
            "safe_mode": self.agent.safe_mode,
            "external_apis": {k: "✅ configured" if v else "❌ not configured" for k, v in api_status.items()},
        }

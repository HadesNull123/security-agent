"""
Spec File Parser — Reads project specification files (PDF, JSON, MD, YAML, TXT)
and extracts text content for LLM analysis.

Supports: .pdf, .json, .md, .txt, .yaml, .yml
PDF reading uses PyPDF2 (optional — falls back to error message if not installed).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Maximum characters to extract from spec file (to stay within LLM context)
MAX_SPEC_CHARS = 50_000

# Supported extensions
SUPPORTED_EXTENSIONS = {".pdf", ".json", ".md", ".txt", ".yaml", ".yml"}


class SpecParseError(Exception):
    """Raised when spec file cannot be parsed."""


def parse_spec_file(path: str) -> str:
    """
    Parse a project specification file and return its text content.

    Args:
        path: Absolute or relative path to the spec file.

    Returns:
        Plain text content of the spec file, truncated to MAX_SPEC_CHARS.

    Raises:
        SpecParseError: If the file cannot be read or parsed.
        FileNotFoundError: If the file does not exist.
    """
    file_path = Path(path).resolve()

    if not file_path.exists():
        raise FileNotFoundError(f"Spec file not found: {file_path}")

    ext = file_path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise SpecParseError(
            f"Unsupported file format: {ext}. "
            f"Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    logger.info(f"📄 Parsing spec file: {file_path.name} ({ext})")

    try:
        if ext == ".pdf":
            content = _parse_pdf(file_path)
        elif ext == ".json":
            content = _parse_json(file_path)
        elif ext in (".yaml", ".yml"):
            content = _parse_yaml(file_path)
        elif ext in (".md", ".txt"):
            content = _parse_text(file_path)
        else:
            content = _parse_text(file_path)
    except SpecParseError:
        raise
    except Exception as e:
        raise SpecParseError(f"Failed to parse {file_path.name}: {e}") from e

    # Truncate if too long
    if len(content) > MAX_SPEC_CHARS:
        logger.warning(
            f"Spec file truncated: {len(content):,} → {MAX_SPEC_CHARS:,} chars"
        )
        content = content[:MAX_SPEC_CHARS] + "\n\n[... TRUNCATED — file too large ...]"

    logger.info(f"✅ Spec file parsed: {len(content):,} chars extracted")
    return content


def _parse_pdf(path: Path) -> str:
    """Extract text from PDF file using PyPDF2."""
    try:
        from PyPDF2 import PdfReader
    except ImportError:
        try:
            from pypdf import PdfReader
        except ImportError:
            raise SpecParseError(
                "PDF reading requires PyPDF2 or pypdf. "
                "Install with: pip install PyPDF2"
            )

    reader = PdfReader(str(path))
    pages_text = []
    for i, page in enumerate(reader.pages):
        text = page.extract_text()
        if text:
            pages_text.append(f"--- Page {i + 1} ---\n{text}")

    if not pages_text:
        raise SpecParseError(f"No text could be extracted from PDF: {path.name}")

    return "\n\n".join(pages_text)


def _parse_json(path: Path) -> str:
    """Parse JSON file and return formatted content."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Smart formatting based on content type
    if isinstance(data, dict):
        # If it looks like an OpenAPI / Swagger spec
        if "openapi" in data or "swagger" in data or "paths" in data:
            return _format_openapi(data)
        # If it has endpoints or routes
        if "endpoints" in data or "routes" in data or "apis" in data:
            return json.dumps(data, indent=2, ensure_ascii=False)

    return json.dumps(data, indent=2, ensure_ascii=False)


def _parse_yaml(path: Path) -> str:
    """Parse YAML file and return formatted content."""
    import yaml

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if isinstance(data, dict):
        # Check for OpenAPI spec
        if "openapi" in data or "swagger" in data or "paths" in data:
            return _format_openapi(data)

    # Convert to readable format
    return yaml.dump(data, default_flow_style=False, allow_unicode=True)


def _parse_text(path: Path) -> str:
    """Read plain text or markdown file."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _format_openapi(spec: dict) -> str:
    """
    Format an OpenAPI/Swagger spec into a concise, LLM-friendly text.
    Extracts the most security-relevant information.
    """
    lines = []

    # Basic info
    info = spec.get("info", {})
    lines.append(f"# API: {info.get('title', 'Unknown')}")
    lines.append(f"Version: {info.get('version', 'N/A')}")
    if desc := info.get("description"):
        lines.append(f"Description: {desc[:500]}")

    # Servers / base URL
    servers = spec.get("servers", [])
    if servers:
        lines.append(f"\nServers: {', '.join(s.get('url', '') for s in servers)}")

    # Security schemes
    components = spec.get("components", {})
    security_schemes = components.get("securitySchemes", {})
    if security_schemes:
        lines.append("\n## Security Schemes")
        for name, scheme in security_schemes.items():
            scheme_type = scheme.get("type", "unknown")
            lines.append(f"- {name}: {scheme_type} ({scheme.get('scheme', scheme.get('in', ''))})")

    # Paths / Endpoints
    paths = spec.get("paths", {})
    if paths:
        lines.append(f"\n## Endpoints ({len(paths)} paths)")
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ("get", "post", "put", "patch", "delete", "options", "head"):
                    summary = details.get("summary", details.get("operationId", ""))
                    lines.append(f"\n### {method.upper()} {path}")
                    if summary:
                        lines.append(f"  Summary: {summary}")

                    # Parameters
                    params = details.get("parameters", [])
                    if params:
                        param_strs = []
                        for p in params:
                            p_name = p.get("name", "?")
                            p_in = p.get("in", "?")
                            p_required = "required" if p.get("required") else "optional"
                            param_strs.append(f"{p_name} ({p_in}, {p_required})")
                        lines.append(f"  Params: {', '.join(param_strs)}")

                    # Request body
                    if req_body := details.get("requestBody"):
                        content = req_body.get("content", {})
                        for ct, schema_info in content.items():
                            schema = schema_info.get("schema", {})
                            props = schema.get("properties", {})
                            if props:
                                fields = list(props.keys())[:20]
                                lines.append(f"  Body ({ct}): {', '.join(fields)}")

                    # Security
                    security = details.get("security", [])
                    if security:
                        sec_names = [list(s.keys())[0] for s in security if s]
                        lines.append(f"  Auth: {', '.join(sec_names)}")

    return "\n".join(lines)


def get_supported_formats() -> str:
    """Return human-readable list of supported formats."""
    return ", ".join(sorted(SUPPORTED_EXTENSIONS))

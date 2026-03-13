"""
Skills System - Loads tool knowledge from .md skill files.
Each skill file teaches the AI HOW to use a security tool using
YAML frontmatter (metadata) + Markdown sections (knowledge).

File structure:
    skills/
    ├── recon/subfinder.md, naabu.md, ...
    ├── scanner/nuclei.md, ffuf.md, ...
    ├── exploit/sqlmap.md, commix.md, ...
    └── modes/quick.md, normal.md, deep.md
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default skills directory — bundled inside the src package
SKILLS_DIR = Path(__file__).parent.parent / "skills_data"


def _parse_frontmatter(content: str) -> tuple[dict[str, str], str]:
    """
    Parse YAML frontmatter from markdown content.
    Returns (metadata_dict, markdown_body).
    """
    if not content.startswith("---"):
        return {}, content

    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, content

    metadata: dict[str, str] = {}
    for line in parts[1].strip().splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            metadata[key.strip()] = value.strip()

    return metadata, parts[2].strip()


def _parse_sections(body: str) -> dict[str, str]:
    """
    Parse markdown H2 sections into a dict.
    E.g. "## When to Use\ntext..." → {"when_to_use": "text..."}
    """
    sections: dict[str, str] = {}
    current_key = ""
    current_lines: list[str] = []

    for line in body.splitlines():
        if line.startswith("## "):
            if current_key and current_lines:
                sections[current_key] = "\n".join(current_lines).strip()
            heading = line[3:].strip()
            current_key = heading.lower().replace(" ", "_")
            current_lines = []
        elif line.startswith("# "):
            continue  # Skip H1 (title)
        else:
            current_lines.append(line)

    if current_key and current_lines:
        sections[current_key] = "\n".join(current_lines).strip()

    return sections


class SkillLoader:
    """
    Loads and caches tool skills from .md files.
    Provides the same API as the old skills module.
    """

    def __init__(self, skills_dir: Path | str | None = None):
        self.skills_dir = Path(skills_dir) if skills_dir else SKILLS_DIR
        self._cache: dict[str, dict[str, Any]] = {}
        self._modes_cache: dict[str, str] = {}
        self._loaded = False

    def _load_all(self) -> None:
        """Load all skill files from disk into cache."""
        if self._loaded:
            return

        if not self.skills_dir.exists():
            logger.warning(f"Skills directory not found: {self.skills_dir}")
            self._loaded = True
            return

        # Load tool skills from category subdirs
        for category_dir in ("recon", "scanner", "exploit"):
            cat_path = self.skills_dir / category_dir
            if not cat_path.exists():
                continue
            for md_file in cat_path.glob("*.md"):
                try:
                    content = md_file.read_text(encoding="utf-8")
                    metadata, body = _parse_frontmatter(content)
                    sections = _parse_sections(body)

                    name = metadata.get("name", md_file.stem)
                    self._cache[name] = {
                        "name": name,
                        "category": metadata.get("category", category_dir),
                        "binary_name": metadata.get("binary_name", name),
                        "requires_config": metadata.get("requires_config", "false").lower() == "true",
                        "sections": sections,
                        "raw_body": body,
                        "file_path": str(md_file),
                    }
                except Exception as e:
                    logger.warning(f"Failed to load skill {md_file}: {e}")

        # Load scan modes
        modes_path = self.skills_dir / "modes"
        if modes_path.exists():
            for md_file in modes_path.glob("*.md"):
                try:
                    content = md_file.read_text(encoding="utf-8")
                    _, body = _parse_frontmatter(content)
                    self._modes_cache[md_file.stem] = body
                except Exception as e:
                    logger.warning(f"Failed to load mode {md_file}: {e}")

        self._loaded = True
        logger.info(f"Loaded {len(self._cache)} tool skills + {len(self._modes_cache)} scan modes")

    def get_skill(self, tool_name: str) -> dict[str, Any] | None:
        """Get skill for a specific tool."""
        self._load_all()
        return self._cache.get(tool_name)

    def get_skills_for_phase(self, phase: str) -> list[dict[str, Any]]:
        """Get skills relevant to a scan phase."""
        self._load_all()
        phase_map = {
            "recon": "recon",
            "scanning": "scanner",
            "exploitation": "exploit",
        }
        category = phase_map.get(phase, phase)
        return [s for s in self._cache.values() if s["category"] == category]

    def get_all_skills(self) -> dict[str, dict[str, Any]]:
        """Get all loaded skills."""
        self._load_all()
        return self._cache.copy()


# ─── Global singleton ────────────────────────────────────────

_loader = SkillLoader()


def get_skill(tool_name: str) -> dict[str, Any] | None:
    """Get skill for a specific tool."""
    return _loader.get_skill(tool_name)


def get_skills_for_phase(phase: str) -> list[dict[str, Any]]:
    """Get skills relevant to a scan phase."""
    return _loader.get_skills_for_phase(phase)


def get_skills_prompt(phase: str, available_tools: list[str], scan_mode: str = "normal") -> str:
    """
    Generate a skills prompt section for the AI.
    Only includes skills for tools that are actually available.
    In quick mode, further restricts to essential tools only.
    """
    skills = _loader.get_skills_for_phase(phase)
    if not skills:
        return ""

    # O3: Quick mode — only include essential tool skills
    quick_tools = {"subfinder", "httpx", "nuclei"}

    parts = ["## Available Tool Skills\n"]
    for skill in skills:
        if skill["name"] not in available_tools:
            continue
        if scan_mode == "quick" and skill["name"] not in quick_tools:
            continue

        sections = skill.get("sections", {})

        parts.append(f"### {skill['name']}")

        if when := sections.get("when_to_use"):
            parts.append(f"**When to use:** {when}")
        if how := sections.get("how_to_use"):
            parts.append(f"**How to use:** {how}")
        if params := sections.get("parameters"):
            parts.append(f"**Parameters:**\n{params}")
        if output := sections.get("output_interpretation"):
            parts.append(f"**Output interpretation:** {output}")
        if practices := sections.get("best_practices"):
            parts.append(f"**Best practices:**\n{practices}")

        parts.append("")

    return "\n".join(parts)


def get_scan_mode_guidance(mode: str) -> str:
    """
    Get guidance text for different scan modes.
    Reads from skills/modes/ .md files.
    """
    _loader._load_all()

    body = _loader._modes_cache.get(mode)
    if body:
        return body

    # Fallback for unknown modes
    return f"SCAN MODE: {mode.upper()}\nNo specific guidance available for this mode.\n"

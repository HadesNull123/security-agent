---
name: git_leak
category: scanner
binary_name: nuclei
virtual: true
---

# Git / Source Code Leak Detection

## When to Use
Check for exposed version control repositories and source maps on ALL web targets.
A leaked `.git` directory = full source code + commit history + potentially secrets.

## How to Use
This is a **virtual skill** — uses nuclei with git-specific templates.

### Step 1: Nuclei templates
Run nuclei with `--tags git,svn,exposure` to detect VCS leaks.

### Step 2: Manual checks (via ffuf/gobuster)
Fuzz these paths specifically:
- `/.git/HEAD` (Git — if returns `ref: refs/heads/...` = CRITICAL)
- `/.git/config` (Git config with remote URLs)
- `/.gitignore` (reveals project structure)
- `/.svn/entries` (Subversion)
- `/.hg/` (Mercurial)
- `/.bzr/` (Bazaar)
- Source maps: `/*.js.map`, `/assets/*.js.map`, `/static/js/*.js.map`

## Parameters
- Use nuclei with `tags: "git,svn,exposure"`
- `target`: URL to test

## Output Interpretation
- `/.git/HEAD` accessible = CRITICAL (full source code recovery possible)
- `/.git/config` shows remote URL = HIGH (source repo location leaked)
- `/.gitignore` accessible = LOW (reveals project structure)
- `/.svn/entries` accessible = CRITICAL (source code leak)
- Source maps (`.js.map`) accessible = MEDIUM (frontend source code)

## Best Practices
- If `.git/HEAD` is found, note that entire repo can be reconstructed with tools like `git-dumper`
- Check for secrets in git history (API keys, passwords in old commits)
- Source maps reveal original unminified code — check for hardcoded secrets
- Also check subdirectories: /app/.git/, /api/.git/, /blog/.git/

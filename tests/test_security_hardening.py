"""
Tests for P0 security hardening:
  - Target sanitization
  - Wordlist path traversal prevention
  - Multi-argument scope checking
  - Credential scrubbing in output filter
"""

import pytest
from src.security.safety import SafetyGuard, SafetyError


# ── Target Sanitization ─────────────────────────────────────

class TestSanitizeTarget:
    def test_strips_shell_metacharacters(self):
        guard = SafetyGuard()
        assert guard.sanitize_target("example.com; rm -rf /") == "example.com rm -rf /"
        assert guard.sanitize_target("example.com|cat /etc/passwd") == "example.comcat /etc/passwd"
        assert guard.sanitize_target("$(whoami).example.com") == "whoami.example.com"

    def test_strips_backticks(self):
        guard = SafetyGuard()
        assert guard.sanitize_target("`id`@example.com") == "id@example.com"

    def test_preserves_valid_targets(self):
        guard = SafetyGuard()
        assert guard.sanitize_target("https://example.com/path?q=1") == "https://example.com/path?q=1"
        assert guard.sanitize_target("192.168.1.1") == "192.168.1.1"
        assert guard.sanitize_target("example.com") == "example.com"

    def test_strips_newlines(self):
        guard = SafetyGuard()
        assert guard.sanitize_target("example.com\nmalicious.com") == "example.commodious.com"

    def test_empty_and_whitespace(self):
        guard = SafetyGuard()
        assert guard.sanitize_target("") == ""
        assert guard.sanitize_target("   ") == ""


# ── Wordlist Path Validation ────────────────────────────────

class TestWordlistPathValidation:
    def test_allows_standard_paths(self):
        guard = SafetyGuard()
        # Should not raise
        guard.validate_wordlist_path("/usr/share/wordlists/rockyou.txt")
        guard.validate_wordlist_path("/usr/share/seclists/Discovery/Web-Content/common.txt")
        guard.validate_wordlist_path("/tmp/my_wordlist.txt")

    def test_blocks_etc_shadow(self):
        guard = SafetyGuard()
        with pytest.raises(SafetyError, match="outside allowed directories"):
            guard.validate_wordlist_path("/etc/shadow")

    def test_blocks_etc_passwd(self):
        guard = SafetyGuard()
        with pytest.raises(SafetyError, match="outside allowed directories"):
            guard.validate_wordlist_path("/etc/passwd")

    def test_blocks_dot_dot_traversal(self):
        guard = SafetyGuard()
        with pytest.raises(SafetyError, match="outside allowed directories"):
            guard.validate_wordlist_path("/usr/share/wordlists/../../etc/shadow")

    def test_blocks_home_directory(self):
        guard = SafetyGuard()
        with pytest.raises(SafetyError, match="outside allowed directories"):
            guard.validate_wordlist_path("/home/user/.ssh/id_rsa")

    def test_empty_path_skipped(self):
        guard = SafetyGuard()
        # Should not raise
        guard.validate_wordlist_path("")
        guard.validate_wordlist_path(None)


# ── Multi-Argument Scope Checking ───────────────────────────

class TestValidateAllTargets:
    def test_checks_target_field(self):
        guard = SafetyGuard(allowed_scope=["example.com"])
        with pytest.raises(SafetyError):
            guard.validate_all_targets({"target": "https://evil.com/test"})

    def test_checks_blind_url_field(self):
        guard = SafetyGuard(allowed_scope=["example.com"])
        with pytest.raises(SafetyError):
            guard.validate_all_targets({"blind_url": "https://attacker.com/callback"})

    def test_checks_urls_field_csv(self):
        guard = SafetyGuard(allowed_scope=["example.com"])
        with pytest.raises(SafetyError):
            guard.validate_all_targets({"urls": "https://example.com,https://evil.com"})

    def test_allows_in_scope_targets(self):
        guard = SafetyGuard(allowed_scope=["example.com"])
        # Should not raise
        guard.validate_all_targets({"target": "https://example.com/path"})
        guard.validate_all_targets({"blind_url": "https://example.com/callback"})

    def test_empty_args_pass(self):
        guard = SafetyGuard(allowed_scope=["example.com"])
        guard.validate_all_targets({})
        guard.validate_all_targets({"mode": "fast"})


# ── Tool Args Validation (Wordlist Integration) ─────────────

class TestToolArgsWordlist:
    def test_blocks_dangerous_wordlist_in_tool_args(self):
        guard = SafetyGuard()
        with pytest.raises(SafetyError, match="outside allowed directories"):
            guard.validate_tool_args("ffuf", {"wordlist": "/etc/shadow"})

    def test_allows_valid_wordlist_in_tool_args(self):
        guard = SafetyGuard()
        guard.validate_tool_args("ffuf", {"wordlist": "/usr/share/wordlists/common.txt"})


# ── check_all Integration ───────────────────────────────────

class TestCheckAll:
    def test_sanitizes_and_validates(self):
        guard = SafetyGuard(allowed_scope=["example.com"])
        # Should not raise — target is in scope even with shell chars stripped
        result = guard.check_all("https://example.com;ls", "nuclei", {"target": "https://example.com"})
        assert result is True

    def test_blocks_out_of_scope_in_args(self):
        guard = SafetyGuard(allowed_scope=["example.com"])
        with pytest.raises(SafetyError):
            guard.check_all(
                "https://example.com",
                "dalfox",
                {"target": "https://example.com", "blind_url": "https://evil.com/callback"},
            )


# ── Credential Scrubbing in OutputFilter ────────────────────

class TestCredentialScrubbing:
    def test_redacts_api_key(self):
        from src.scanner.output_filter import OutputFilter
        f = OutputFilter()
        output = f.clean("api_key=sk-abc123xyz789 found in response")
        assert "sk-abc123xyz789" not in output
        assert "***REDACTED***" in output

    def test_redacts_password(self):
        from src.scanner.output_filter import OutputFilter
        f = OutputFilter()
        output = f.clean("password=SuperSecret123! detected")
        assert "SuperSecret123!" not in output
        assert "***REDACTED***" in output

    def test_redacts_bearer_token(self):
        from src.scanner.output_filter import OutputFilter
        f = OutputFilter()
        output = f.clean("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123")
        assert "eyJhbGciOiJIUzI1NiJ9" not in output
        assert "***REDACTED***" in output

    def test_redacts_aws_keys(self):
        from src.scanner.output_filter import OutputFilter
        f = OutputFilter()
        output = f.clean("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        assert "wJalrXUtnFEMI" not in output
        assert "***REDACTED***" in output

    def test_preserves_non_sensitive_content(self):
        from src.scanner.output_filter import OutputFilter
        f = OutputFilter()
        output = f.clean("HTTP/1.1 200 OK\nContent-Type: text/html\nServer: nginx")
        assert "HTTP/1.1 200 OK" in output
        assert "Server: nginx" in output

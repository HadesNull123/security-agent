"""
Database layer using aiosqlite for persistent storage of scan results.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

import aiosqlite

from src.core.models import Finding, ScanSession, Target, ToolExecution, ExploitResult

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'initialized',
    current_phase TEXT NOT NULL DEFAULT 'recon',
    targets_json TEXT DEFAULT '[]',
    started_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT DEFAULT 'medium',
    category TEXT DEFAULT '',
    cve_ids TEXT DEFAULT '[]',
    cvss_score REAL,
    affected_url TEXT DEFAULT '',
    affected_host TEXT DEFAULT '',
    affected_port INTEGER,
    evidence TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    tool_source TEXT DEFAULT '',
    references_json TEXT DEFAULT '[]',
    extra_data TEXT DEFAULT '{}',
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

CREATE TABLE IF NOT EXISTS tool_executions (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    command TEXT DEFAULT '',
    arguments TEXT DEFAULT '{}',
    phase TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    output TEXT DEFAULT '',
    error TEXT DEFAULT '',
    duration_seconds REAL DEFAULT 0.0,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

CREATE TABLE IF NOT EXISTS exploit_results (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    tool_used TEXT NOT NULL,
    payload TEXT DEFAULT '',
    success INTEGER DEFAULT 0,
    output TEXT DEFAULT '',
    access_gained TEXT DEFAULT '',
    data_extracted TEXT DEFAULT '{}',
    executed_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id),
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_tool_exec_session ON tool_executions(session_id);
CREATE INDEX IF NOT EXISTS idx_exploit_session ON exploit_results(session_id);
"""


class Database:
    """Async SQLite database manager."""

    def __init__(self, db_path: str = "./data/security_agent.db"):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        """Connect to database and initialize schema."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(SCHEMA_SQL)
        await self._db.commit()
        logger.info(f"Database connected: {self.db_path}")

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._db

    # ---- Sessions ----

    async def create_session(self, session: ScanSession) -> None:
        targets_json = json.dumps([t.model_dump(mode="json") for t in session.targets])
        await self.db.execute(
            "INSERT INTO scan_sessions (id, status, current_phase, targets_json, started_at) VALUES (?, ?, ?, ?, ?)",
            (session.id, session.status, session.current_phase.value, targets_json, session.started_at.isoformat()),
        )
        await self.db.commit()

    async def update_session_status(self, session_id: str, status: str, phase: str | None = None) -> None:
        if phase:
            await self.db.execute(
                "UPDATE scan_sessions SET status=?, current_phase=? WHERE id=?",
                (status, phase, session_id),
            )
        else:
            await self.db.execute(
                "UPDATE scan_sessions SET status=? WHERE id=?",
                (status, session_id),
            )
        await self.db.commit()

    async def complete_session(self, session_id: str) -> None:
        await self.db.execute(
            "UPDATE scan_sessions SET status='completed', completed_at=? WHERE id=?",
            (datetime.utcnow().isoformat(), session_id),
        )
        await self.db.commit()

    # ---- Findings ----

    async def save_finding(self, session_id: str, finding: Finding) -> None:
        await self.db.execute(
            """INSERT OR IGNORE INTO findings
            (id, session_id, title, description, severity, confidence, category,
             cve_ids, cvss_score, affected_url, affected_host, affected_port,
             evidence, remediation, tool_source, references_json, extra_data, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.id, session_id, finding.title, finding.description,
                finding.severity.value, finding.confidence, finding.category,
                json.dumps(finding.cve_ids), finding.cvss_score,
                finding.affected_url, finding.affected_host, finding.affected_port,
                finding.evidence, finding.remediation, finding.tool_source,
                json.dumps(finding.references), json.dumps(finding.extra_data),
                finding.discovered_at.isoformat(),
            ),
        )
        await self.db.commit()

    async def batch_save_findings(self, session_id: str, findings: list) -> None:
        """Save multiple findings in a single transaction (O1 optimization)."""
        for finding in findings:
            await self.db.execute(
                """INSERT OR IGNORE INTO findings
                (id, session_id, title, description, severity, confidence, category,
                 cve_ids, cvss_score, affected_url, affected_host, affected_port,
                 evidence, remediation, tool_source, references_json, extra_data, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.id, session_id, finding.title, finding.description,
                    finding.severity.value, finding.confidence, finding.category,
                    json.dumps(finding.cve_ids), finding.cvss_score,
                    finding.affected_url, finding.affected_host, finding.affected_port,
                    finding.evidence, finding.remediation, finding.tool_source,
                    json.dumps(finding.references), json.dumps(finding.extra_data),
                    finding.discovered_at.isoformat(),
                ),
            )
        await self.db.commit()

    async def get_findings(self, session_id: str) -> list[dict]:
        cursor = await self.db.execute(
            "SELECT * FROM findings WHERE session_id=? ORDER BY severity", (session_id,)
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # ---- Tool Executions ----

    async def save_tool_execution(self, session_id: str, execution: ToolExecution) -> None:
        await self.db.execute(
            """INSERT INTO tool_executions
            (id, session_id, tool_name, command, arguments, phase, status,
             output, error, duration_seconds, started_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                execution.id, session_id, execution.tool_name, execution.command,
                json.dumps(execution.arguments), execution.phase.value, execution.status,
                execution.output, execution.error, execution.duration_seconds,
                execution.started_at.isoformat(),
                execution.completed_at.isoformat() if execution.completed_at else None,
            ),
        )
        await self.db.commit()

    # ---- Exploit Results ----

    async def save_exploit_result(self, session_id: str, result: ExploitResult) -> None:
        await self.db.execute(
            """INSERT INTO exploit_results
            (id, session_id, finding_id, tool_used, payload, success,
             output, access_gained, data_extracted, executed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result.id, session_id, result.finding_id, result.tool_used,
                result.payload, int(result.success), result.output,
                result.access_gained, json.dumps(result.data_extracted),
                result.executed_at.isoformat(),
            ),
        )
        await self.db.commit()

    # ---- Statistics ----

    async def get_session_stats(self, session_id: str) -> dict:
        """Get summary statistics for a scan session."""
        findings_cursor = await self.db.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings WHERE session_id=? GROUP BY severity",
            (session_id,),
        )
        severity_counts = {row["severity"]: row["cnt"] for row in await findings_cursor.fetchall()}

        tools_cursor = await self.db.execute(
            "SELECT COUNT(*) as cnt FROM tool_executions WHERE session_id=?",
            (session_id,),
        )
        tool_count = (await tools_cursor.fetchone())["cnt"]

        exploits_cursor = await self.db.execute(
            "SELECT COUNT(*) as total, SUM(success) as successful FROM exploit_results WHERE session_id=?",
            (session_id,),
        )
        exploit_row = await exploits_cursor.fetchone()

        return {
            "findings_by_severity": severity_counts,
            "total_findings": sum(severity_counts.values()),
            "tools_executed": tool_count,
            "exploits_attempted": exploit_row["total"] or 0,
            "exploits_successful": exploit_row["successful"] or 0,
        }

"""
Vector Memory Store - SQLite-backed vector storage for agent context and knowledge.
Uses simple cosine similarity with TF-IDF vectors stored in SQLite.
Enables the agent to recall past scan results, patterns, and learned behaviors.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class VectorMemory:
    """
    SQLite-backed vector memory for the security agent.
    Stores text chunks with TF-IDF vectors for semantic search.
    No external embedding API needed — runs fully locally.
    """

    def __init__(self, db_path: str = "./data/security_agent.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._vocab: dict[str, int] = {}
        self._idf: dict[str, float] = {}
        self._idf_dirty: bool = True  # Lazy IDF rebuild

    def connect(self) -> None:
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()
        self._idf_dirty = True  # Will rebuild on first search

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("VectorMemory not connected")
        return self._conn

    def _create_tables(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS memory_chunks (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                category TEXT NOT NULL,
                content TEXT NOT NULL,
                metadata TEXT DEFAULT '{}',
                vector TEXT DEFAULT '[]',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_memory_category ON memory_chunks(category);
            CREATE INDEX IF NOT EXISTS idx_memory_session ON memory_chunks(session_id);

            CREATE TABLE IF NOT EXISTS memory_vocab (
                term TEXT PRIMARY KEY,
                doc_freq INTEGER DEFAULT 1
            );
        """)
        self.conn.commit()

    # ─── Tokenization ──────────────────────────────────────────

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Simple whitespace + punctuation tokenizer."""
        text = text.lower()
        text = re.sub(r'[^a-z0-9\s\.\-\_\/\:]', ' ', text)
        tokens = text.split()
        # Remove very short tokens and stopwords
        stopwords = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been',
                      'has', 'have', 'had', 'do', 'does', 'did', 'will', 'would',
                      'could', 'should', 'may', 'might', 'can', 'shall', 'to',
                      'of', 'in', 'for', 'on', 'with', 'at', 'by', 'from', 'as',
                      'into', 'through', 'during', 'before', 'after', 'and', 'or',
                      'but', 'if', 'then', 'than', 'that', 'this', 'it', 'its'}
        return [t for t in tokens if len(t) > 1 and t not in stopwords]

    def _tf_vector(self, tokens: list[str]) -> dict[str, float]:
        """Compute term-frequency vector."""
        counts = Counter(tokens)
        total = len(tokens) or 1
        return {term: count / total for term, count in counts.items()}

    def _build_idf(self) -> None:
        """Build IDF dictionary from stored vocab."""
        cursor = self.conn.execute("SELECT COUNT(*) FROM memory_chunks")
        total_docs = cursor.fetchone()[0] or 1

        cursor = self.conn.execute("SELECT term, doc_freq FROM memory_vocab")
        for row in cursor.fetchall():
            self._idf[row["term"]] = math.log(total_docs / (row["doc_freq"] + 1))

    def _tfidf_vector(self, tokens: list[str]) -> list[tuple[str, float]]:
        """Compute TF-IDF vector as sparse list of (term, score) tuples."""
        tf = self._tf_vector(tokens)
        vector = []
        for term, freq in tf.items():
            idf = self._idf.get(term, math.log(10))  # default IDF for new terms
            vector.append((term, freq * idf))
        return vector

    @staticmethod
    def _cosine_similarity(v1: list[tuple[str, float]], v2: list[tuple[str, float]]) -> float:
        """Cosine similarity between two sparse TF-IDF vectors."""
        d1 = dict(v1)
        d2 = dict(v2)
        common_terms = set(d1.keys()) & set(d2.keys())
        if not common_terms:
            return 0.0

        dot = sum(d1[t] * d2[t] for t in common_terms)
        mag1 = math.sqrt(sum(v * v for v in d1.values()))
        mag2 = math.sqrt(sum(v * v for v in d2.values()))

        if mag1 == 0 or mag2 == 0:
            return 0.0
        return dot / (mag1 * mag2)

    # ─── Store & Retrieve ───────────────────────────────────────

    def store(
        self,
        content: str,
        category: str,
        session_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Store a text chunk in memory with its vector.

        Args:
            content: Text content to store
            category: e.g. "recon_result", "finding", "tool_output", "skill"
            session_id: Optional scan session ID
            metadata: Additional metadata

        Returns:
            chunk ID
        """
        chunk_id = hashlib.md5(f"{content[:200]}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12]
        tokens = self._tokenize(content)
        vector = self._tfidf_vector(tokens)

        # Update vocabulary
        seen_terms = set()
        for term in tokens:
            if term not in seen_terms:
                self.conn.execute(
                    "INSERT INTO memory_vocab (term, doc_freq) VALUES (?, 1) "
                    "ON CONFLICT(term) DO UPDATE SET doc_freq = doc_freq + 1",
                    (term,),
                )
                seen_terms.add(term)

        self.conn.execute(
            "INSERT OR REPLACE INTO memory_chunks (id, session_id, category, content, metadata, vector, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                chunk_id, session_id, category,
                content[:50000],  # limit stored content
                json.dumps(metadata or {}),
                json.dumps(vector),
                datetime.utcnow().isoformat(),
            ),
        )
        self.conn.commit()
        self._idf_dirty = True  # Mark IDF for rebuild on next search

        return chunk_id

    def search(
        self,
        query: str,
        top_k: int = 5,
        category: str | None = None,
        session_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search memory for relevant chunks.

        Args:
            query: Search query
            top_k: Number of results to return
            category: Filter by category
            session_id: Filter by session

        Returns:
            List of matching chunks with similarity scores
        """
        tokens = self._tokenize(query)
        query_vector = self._tfidf_vector(tokens)

        if not query_vector:
            return []

        # Lazy IDF rebuild only when searching
        if self._idf_dirty:
            self._build_idf()
            self._idf_dirty = False

        # Build SQL filter
        sql = "SELECT * FROM memory_chunks WHERE 1=1"
        params: list[Any] = []
        if category:
            sql += " AND category = ?"
            params.append(category)
        if session_id:
            sql += " AND session_id = ?"
            params.append(session_id)

        cursor = self.conn.execute(sql, params)
        results = []
        for row in cursor.fetchall():
            stored_vector = json.loads(row["vector"])
            if not stored_vector:
                continue
            # Convert stored vector from list of lists to list of tuples
            stored_tuples = [(v[0], v[1]) for v in stored_vector]
            sim = self._cosine_similarity(query_vector, stored_tuples)
            if sim > 0.01:  # minimum threshold
                results.append({
                    "id": row["id"],
                    "content": row["content"],
                    "category": row["category"],
                    "similarity": round(sim, 4),
                    "metadata": json.loads(row["metadata"]),
                    "session_id": row["session_id"],
                })

        # Sort by similarity descending
        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:top_k]

    def get_context(
        self,
        query: str,
        max_tokens: int = 3000,
        category: str | None = None,
    ) -> str:
        """
        Get relevant context as a string, suitable for injecting into LLM prompts.
        Truncates to fit within token budget.
        """
        results = self.search(query, top_k=10, category=category)
        if not results:
            return ""

        context_parts = []
        total_len = 0
        for r in results:
            chunk = f"[{r['category']}] (relevance: {r['similarity']:.2f})\n{r['content']}"
            # Rough token estimate: 1 token ≈ 4 chars
            chunk_tokens = len(chunk) // 4
            if total_len + chunk_tokens > max_tokens:
                # Truncate this chunk to fit
                remaining = (max_tokens - total_len) * 4
                if remaining > 100:
                    context_parts.append(chunk[:remaining] + "...")
                break
            context_parts.append(chunk)
            total_len += chunk_tokens

        return "\n---\n".join(context_parts)

    def clear_session(self, session_id: str) -> None:
        """Clear all memory for a session."""
        self.conn.execute("DELETE FROM memory_chunks WHERE session_id = ?", (session_id,))
        self.conn.commit()

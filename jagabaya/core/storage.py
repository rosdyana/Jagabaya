"""
SQLite session storage for Jagabaya.

Provides persistent session storage with resume capability.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from jagabaya.models.session import SessionState, ScanPhase


class SessionStorage:
    """
    SQLite-based session storage for persistence and resume.

    Stores session state in a SQLite database for:
    - Crash recovery
    - Resume interrupted scans
    - Historical session tracking

    Example:
        >>> storage = SessionStorage("./output")
        >>> storage.save_session(session)
        >>> session = storage.load_session("abc123")
        >>> resumable = storage.get_resumable_sessions()
    """

    def __init__(self, output_dir: str | Path):
        """
        Initialize the session storage.

        Args:
            output_dir: Directory for the database file
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.output_dir / "sessions.db"
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'running',
                    current_phase TEXT NOT NULL,
                    current_step INTEGER NOT NULL DEFAULT 0,
                    max_steps INTEGER NOT NULL DEFAULT 100,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    state_json TEXT NOT NULL,
                    error TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS session_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    step_number INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    tool TEXT,
                    target TEXT,
                    success INTEGER,
                    timestamp TEXT NOT NULL,
                    duration_seconds REAL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_status 
                ON sessions(status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_actions_session 
                ON session_actions(session_id)
            """)
            conn.commit()

    def save_session(
        self,
        session: SessionState,
        current_step: int = 0,
        max_steps: int = 100,
        status: str = "running",
    ) -> None:
        """
        Save or update session state.

        Args:
            session: Session state to save
            current_step: Current step number
            max_steps: Maximum steps allowed
            status: Session status (running, completed, failed, interrupted)
        """
        now = datetime.now().isoformat()
        state_json = json.dumps(session.model_dump(mode="json"), default=str)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions 
                (session_id, target, status, current_phase, current_step, max_steps,
                 started_at, updated_at, completed_at, state_json, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session.session_id,
                    session.target,
                    status,
                    session.current_phase.value,
                    current_step,
                    max_steps,
                    session.started_at.isoformat(),
                    now,
                    session.completed_at.isoformat() if session.completed_at else None,
                    state_json,
                    session.error,
                ),
            )
            conn.commit()

    def load_session(self, session_id: str) -> SessionState | None:
        """
        Load a session by ID.

        Args:
            session_id: Session ID to load

        Returns:
            SessionState if found, None otherwise
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT state_json FROM sessions WHERE session_id = ?", (session_id,)
            )
            row = cursor.fetchone()

            if not row:
                return None

            data = json.loads(row["state_json"])
            return SessionState.model_validate(data)

    def get_session_info(self, session_id: str) -> dict[str, Any] | None:
        """
        Get session metadata without loading full state.

        Args:
            session_id: Session ID

        Returns:
            Session info dict or None
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT session_id, target, status, current_phase, 
                       current_step, max_steps, started_at, updated_at,
                       completed_at, error
                FROM sessions WHERE session_id = ?
            """,
                (session_id,),
            )
            row = cursor.fetchone()

            if not row:
                return None

            return dict(row)

    def get_resumable_sessions(self) -> list[dict[str, Any]]:
        """
        Get all sessions that can be resumed.

        Returns:
            List of resumable session info dicts
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT session_id, target, status, current_phase,
                       current_step, max_steps, started_at, updated_at
                FROM sessions 
                WHERE status IN ('running', 'interrupted')
                ORDER BY updated_at DESC
            """)
            return [dict(row) for row in cursor.fetchall()]

    def list_sessions(
        self,
        limit: int = 20,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        List all sessions.

        Args:
            limit: Maximum number of sessions to return
            status: Filter by status (optional)

        Returns:
            List of session info dicts
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            if status:
                cursor = conn.execute(
                    """
                    SELECT session_id, target, status, current_phase,
                           current_step, max_steps, started_at, updated_at,
                           completed_at
                    FROM sessions 
                    WHERE status = ?
                    ORDER BY updated_at DESC
                    LIMIT ?
                """,
                    (status, limit),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT session_id, target, status, current_phase,
                           current_step, max_steps, started_at, updated_at,
                           completed_at
                    FROM sessions 
                    ORDER BY updated_at DESC
                    LIMIT ?
                """,
                    (limit,),
                )

            return [dict(row) for row in cursor.fetchall()]

    def mark_completed(
        self,
        session_id: str,
        status: str = "completed",
    ) -> None:
        """
        Mark a session as completed.

        Args:
            session_id: Session ID
            status: Final status (completed, failed, cancelled)
        """
        now = datetime.now().isoformat()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                UPDATE sessions 
                SET status = ?, completed_at = ?, updated_at = ?
                WHERE session_id = ?
            """,
                (status, now, now, session_id),
            )
            conn.commit()

    def mark_interrupted(self, session_id: str, error: str | None = None) -> None:
        """
        Mark a session as interrupted (can be resumed).

        Args:
            session_id: Session ID
            error: Optional error message
        """
        now = datetime.now().isoformat()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                UPDATE sessions 
                SET status = 'interrupted', updated_at = ?, error = ?
                WHERE session_id = ?
            """,
                (now, error, session_id),
            )
            conn.commit()

    def add_action(
        self,
        session_id: str,
        step_number: int,
        action: str,
        tool: str | None = None,
        target: str | None = None,
        success: bool | None = None,
        duration_seconds: float | None = None,
    ) -> None:
        """
        Record an action for a session.

        Args:
            session_id: Session ID
            step_number: Current step number
            action: Action description
            tool: Tool used (optional)
            target: Target of action (optional)
            success: Whether action succeeded (optional)
            duration_seconds: Duration in seconds (optional)
        """
        now = datetime.now().isoformat()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO session_actions 
                (session_id, step_number, action, tool, target, success, 
                 timestamp, duration_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session_id,
                    step_number,
                    action,
                    tool,
                    target,
                    1 if success else (0 if success is False else None),
                    now,
                    duration_seconds,
                ),
            )
            conn.commit()

    def get_actions(self, session_id: str) -> list[dict[str, Any]]:
        """
        Get all actions for a session.

        Args:
            session_id: Session ID

        Returns:
            List of action records
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT step_number, action, tool, target, success, 
                       timestamp, duration_seconds
                FROM session_actions 
                WHERE session_id = ?
                ORDER BY step_number
            """,
                (session_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session and its actions.

        Args:
            session_id: Session ID to delete

        Returns:
            True if deleted, False if not found
        """
        with sqlite3.connect(self.db_path) as conn:
            # Delete actions first
            conn.execute("DELETE FROM session_actions WHERE session_id = ?", (session_id,))
            # Delete session
            cursor = conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            conn.commit()
            return cursor.rowcount > 0

    def cleanup_old_sessions(self, days: int = 30) -> int:
        """
        Delete sessions older than specified days.

        Args:
            days: Delete sessions older than this many days

        Returns:
            Number of sessions deleted
        """
        cutoff = datetime.now().timestamp() - (days * 86400)
        cutoff_iso = datetime.fromtimestamp(cutoff).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            # Get sessions to delete
            cursor = conn.execute(
                """
                SELECT session_id FROM sessions
                WHERE updated_at < ? AND status IN ('completed', 'failed', 'cancelled')
            """,
                (cutoff_iso,),
            )
            session_ids = [row[0] for row in cursor.fetchall()]

            if not session_ids:
                return 0

            # Delete actions
            placeholders = ",".join("?" * len(session_ids))
            conn.execute(
                f"DELETE FROM session_actions WHERE session_id IN ({placeholders})", session_ids
            )

            # Delete sessions
            conn.execute(f"DELETE FROM sessions WHERE session_id IN ({placeholders})", session_ids)
            conn.commit()

            return len(session_ids)

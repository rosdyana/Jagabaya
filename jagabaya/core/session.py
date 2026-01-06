"""
Session management for Jagabaya.

Handles session state persistence, history tracking, and result management.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from jagabaya.models.session import SessionState, SessionResult, ScanPhase
from jagabaya.models.findings import Finding


class SessionManager:
    """
    Manages session state and persistence.
    
    The SessionManager handles:
    - Creating new sessions
    - Saving/loading session state
    - Managing session history
    - Exporting results
    
    Example:
        >>> manager = SessionManager(output_dir="./results")
        >>> session = manager.create_session("example.com")
        >>> manager.save_session(session)
    """
    
    def __init__(
        self,
        output_dir: str | Path = "./jagabaya_output",
        auto_save: bool = True,
        save_interval: int = 10,
    ):
        """
        Initialize the SessionManager.
        
        Args:
            output_dir: Directory for session data
            auto_save: Automatically save session state
            save_interval: Actions between auto-saves
        """
        self.output_dir = Path(output_dir)
        self.auto_save = auto_save
        self.save_interval = save_interval
        self._action_count = 0
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def create_session(
        self,
        target: str,
        scope: list[str] | None = None,
        blacklist: list[str] | None = None,
        session_id: str | None = None,
    ) -> SessionState:
        """
        Create a new session.
        
        Args:
            target: Primary target
            scope: List of in-scope targets
            blacklist: List of out-of-scope targets
            session_id: Optional session ID (auto-generated if not provided)
        
        Returns:
            New SessionState instance
        """
        session_id = session_id or uuid4().hex[:12]
        
        session = SessionState(
            session_id=session_id,
            target=target,
            scope=scope or [target],
            blacklist=blacklist or [],
            started_at=datetime.now(),
            current_phase=ScanPhase.RECONNAISSANCE,
        )
        
        return session
    
    def save_session(self, session: SessionState) -> Path:
        """
        Save session state to disk.
        
        Args:
            session: Session state to save
        
        Returns:
            Path to saved session file
        """
        session_dir = self.output_dir / session.session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        # Save session state
        session_file = session_dir / "session.json"
        with open(session_file, "w") as f:
            json.dump(session.model_dump(mode="json"), f, indent=2, default=str)
        
        return session_file
    
    def load_session(self, session_id: str) -> SessionState | None:
        """
        Load a session from disk.
        
        Args:
            session_id: Session ID to load
        
        Returns:
            SessionState if found, None otherwise
        """
        session_file = self.output_dir / session_id / "session.json"
        
        if not session_file.exists():
            return None
        
        try:
            with open(session_file) as f:
                data = json.load(f)
            return SessionState.model_validate(data)
        except Exception as e:
            print(f"Error loading session: {e}")
            return None
    
    def list_sessions(self) -> list[dict[str, Any]]:
        """
        List all saved sessions.
        
        Returns:
            List of session summaries
        """
        sessions = []
        
        if not self.output_dir.exists():
            return sessions
        
        for session_dir in self.output_dir.iterdir():
            if not session_dir.is_dir():
                continue
            
            session_file = session_dir / "session.json"
            if not session_file.exists():
                continue
            
            try:
                with open(session_file) as f:
                    data = json.load(f)
                
                sessions.append({
                    "session_id": data.get("session_id"),
                    "target": data.get("target"),
                    "started_at": data.get("started_at"),
                    "current_phase": data.get("current_phase"),
                    "findings_count": len(data.get("findings", [])),
                })
            except Exception:
                continue
        
        # Sort by start time (most recent first)
        sessions.sort(key=lambda x: x.get("started_at", ""), reverse=True)
        
        return sessions
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session.
        
        Args:
            session_id: Session ID to delete
        
        Returns:
            True if deleted, False if not found
        """
        import shutil
        
        session_dir = self.output_dir / session_id
        
        if not session_dir.exists():
            return False
        
        shutil.rmtree(session_dir)
        return True
    
    def export_findings(
        self,
        session: SessionState,
        format: str = "json",
    ) -> str:
        """
        Export findings from a session.
        
        Args:
            session: Session to export from
            format: Export format (json, csv)
        
        Returns:
            Exported findings as string
        """
        if format == "json":
            findings_data = [f.model_dump(mode="json") for f in session.findings]
            return json.dumps(findings_data, indent=2, default=str)
        
        elif format == "csv":
            lines = ["severity,title,target,category,tool"]
            for finding in session.findings:
                lines.append(
                    f"{finding.severity.value},"
                    f"\"{finding.title}\","
                    f"{finding.target},"
                    f"{finding.category.value},"
                    f"{finding.tool}"
                )
            return "\n".join(lines)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def save_findings(
        self,
        session: SessionState,
        format: str = "json",
    ) -> Path:
        """
        Save findings to a file.
        
        Args:
            session: Session to save findings from
            format: Export format
        
        Returns:
            Path to saved file
        """
        session_dir = self.output_dir / session.session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        
        ext = "json" if format == "json" else "csv"
        findings_file = session_dir / f"findings.{ext}"
        
        content = self.export_findings(session, format)
        
        with open(findings_file, "w") as f:
            f.write(content)
        
        return findings_file
    
    def create_result(self, session: SessionState) -> SessionResult:
        """
        Create a SessionResult from the current session state.
        
        Args:
            session: Session state
        
        Returns:
            SessionResult summary
        """
        return SessionResult(
            session_id=session.session_id,
            target=session.target,
            started_at=session.started_at,
            completed_at=session.completed_at or datetime.now(),
            findings=session.findings,
            findings_summary=session.get_findings_summary(),
            discovered_assets=session.discovered_assets,
            tool_executions=session.tool_executions,
            ai_decisions=session.ai_decisions,
            total_tools_run=len(session.tool_executions),
            total_ai_calls=len(session.ai_decisions),
        )
    
    def maybe_auto_save(self, session: SessionState) -> bool:
        """
        Auto-save session if conditions are met.
        
        Args:
            session: Session to save
        
        Returns:
            True if saved
        """
        if not self.auto_save:
            return False
        
        self._action_count += 1
        
        if self._action_count >= self.save_interval:
            self.save_session(session)
            self._action_count = 0
            return True
        
        return False
    
    def get_session_dir(self, session: SessionState) -> Path:
        """
        Get the directory for a session.
        
        Args:
            session: Session
        
        Returns:
            Path to session directory
        """
        session_dir = self.output_dir / session.session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir

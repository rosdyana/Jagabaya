"""
Tests for SQLite session storage.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

from jagabaya.core.storage import SessionStorage
from jagabaya.models.session import SessionState, ScanPhase


class TestSessionStorage:
    """Tests for SessionStorage class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for tests."""
        tmp = tempfile.mkdtemp()
        yield tmp
        # Cleanup - handle Windows file locking
        try:
            shutil.rmtree(tmp)
        except PermissionError:
            pass

    @pytest.fixture
    def storage(self, temp_dir):
        """Create a SessionStorage instance."""
        return SessionStorage(temp_dir)

    @pytest.fixture
    def sample_session(self):
        """Create a sample session for testing."""
        return SessionState(
            session_id="test123",
            target="example.com",
            scope=["example.com", "*.example.com"],
            current_phase=ScanPhase.RECONNAISSANCE,
        )

    def test_init_creates_db(self, temp_dir):
        """Test that initialization creates the database."""
        storage = SessionStorage(temp_dir)
        assert storage.db_path.exists()

    def test_save_and_load_session(self, storage, sample_session):
        """Test saving and loading a session."""
        storage.save_session(sample_session, current_step=5, max_steps=100)

        loaded = storage.load_session("test123")
        assert loaded is not None
        assert loaded.session_id == "test123"
        assert loaded.target == "example.com"
        assert loaded.current_phase == ScanPhase.RECONNAISSANCE

    def test_load_nonexistent_session(self, storage):
        """Test loading a session that doesn't exist."""
        loaded = storage.load_session("nonexistent")
        assert loaded is None

    def test_get_session_info(self, storage, sample_session):
        """Test getting session metadata."""
        storage.save_session(sample_session, current_step=10, max_steps=50, status="running")

        info = storage.get_session_info("test123")
        assert info is not None
        assert info["session_id"] == "test123"
        assert info["target"] == "example.com"
        assert info["status"] == "running"
        assert info["current_step"] == 10
        assert info["max_steps"] == 50

    def test_list_sessions(self, storage, sample_session):
        """Test listing all sessions."""
        storage.save_session(sample_session, current_step=5, max_steps=100)

        sessions = storage.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "test123"

    def test_list_sessions_with_status_filter(self, storage, sample_session):
        """Test listing sessions filtered by status."""
        storage.save_session(sample_session, status="completed")

        # Should find when filtering for completed
        sessions = storage.list_sessions(status="completed")
        assert len(sessions) == 1

        # Should not find when filtering for running
        sessions = storage.list_sessions(status="running")
        assert len(sessions) == 0

    def test_get_resumable_sessions(self, storage):
        """Test getting resumable sessions."""
        # Create running session
        session1 = SessionState(session_id="running1", target="a.com")
        storage.save_session(session1, status="running")

        # Create interrupted session
        session2 = SessionState(session_id="interrupted1", target="b.com")
        storage.save_session(session2, status="interrupted")

        # Create completed session
        session3 = SessionState(session_id="completed1", target="c.com")
        storage.save_session(session3, status="completed")

        resumable = storage.get_resumable_sessions()
        assert len(resumable) == 2
        session_ids = [s["session_id"] for s in resumable]
        assert "running1" in session_ids
        assert "interrupted1" in session_ids
        assert "completed1" not in session_ids

    def test_mark_completed(self, storage, sample_session):
        """Test marking a session as completed."""
        storage.save_session(sample_session, status="running")
        storage.mark_completed("test123", status="completed")

        info = storage.get_session_info("test123")
        assert info["status"] == "completed"
        assert info["completed_at"] is not None

    def test_mark_interrupted(self, storage, sample_session):
        """Test marking a session as interrupted."""
        storage.save_session(sample_session, status="running")
        storage.mark_interrupted("test123", error="User cancelled")

        info = storage.get_session_info("test123")
        assert info["status"] == "interrupted"
        assert info["error"] == "User cancelled"

    def test_add_and_get_actions(self, storage, sample_session):
        """Test adding and retrieving actions."""
        storage.save_session(sample_session)

        storage.add_action(
            "test123", 1, "port_scan", tool="nmap", target="example.com", success=True
        )
        storage.add_action(
            "test123", 2, "vuln_scan", tool="nuclei", target="example.com", success=True
        )

        actions = storage.get_actions("test123")
        assert len(actions) == 2
        assert actions[0]["action"] == "port_scan"
        assert actions[0]["tool"] == "nmap"
        assert actions[1]["step_number"] == 2

    def test_delete_session(self, storage, sample_session):
        """Test deleting a session."""
        storage.save_session(sample_session)
        storage.add_action("test123", 1, "test_action")

        result = storage.delete_session("test123")
        assert result is True

        # Session should be gone
        assert storage.load_session("test123") is None
        assert storage.get_actions("test123") == []

    def test_delete_nonexistent_session(self, storage):
        """Test deleting a session that doesn't exist."""
        result = storage.delete_session("nonexistent")
        assert result is False

    def test_update_session_preserves_state(self, storage, sample_session):
        """Test that updating a session preserves changes."""
        storage.save_session(sample_session, current_step=5, max_steps=100, status="running")

        # Load, modify, save
        loaded = storage.load_session("test123")
        loaded.current_phase = ScanPhase.SCANNING
        storage.save_session(loaded, current_step=10, max_steps=100, status="running")

        # Verify changes persisted
        reloaded = storage.load_session("test123")
        assert reloaded.current_phase == ScanPhase.SCANNING

        info = storage.get_session_info("test123")
        assert info["current_step"] == 10


class TestSessionStorageEdgeCases:
    """Edge case tests for SessionStorage."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for tests."""
        tmp = tempfile.mkdtemp()
        yield tmp
        try:
            shutil.rmtree(tmp)
        except PermissionError:
            pass

    def test_creates_output_dir_if_missing(self, temp_dir):
        """Test that storage creates output directory if it doesn't exist."""
        new_path = Path(temp_dir) / "nested" / "path"
        storage = SessionStorage(new_path)
        assert new_path.exists()
        assert storage.db_path.exists()

    def test_handles_special_characters_in_target(self, temp_dir):
        """Test handling special characters in target."""
        storage = SessionStorage(temp_dir)
        session = SessionState(
            session_id="special123", target="https://example.com/path?query=value&other=123"
        )
        storage.save_session(session)

        loaded = storage.load_session("special123")
        assert loaded.target == "https://example.com/path?query=value&other=123"

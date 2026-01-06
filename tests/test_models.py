"""
Tests for Pydantic models.
"""

import pytest
from datetime import datetime

from jagabaya.models.findings import Finding, FindingSeverity, FindingCategory, FindingSummary
from jagabaya.models.session import SessionState, SessionResult, ScanPhase, AIDecision, CompletedAction


class TestFinding:
    """Tests for Finding model."""
    
    def test_create_finding(self):
        finding = Finding(
            severity=FindingSeverity.HIGH,
            title="SQL Injection",
            description="SQL injection vulnerability found",
            target="example.com",
            tool="sqlmap",
        )
        assert finding.severity == FindingSeverity.HIGH
        assert finding.title == "SQL Injection"
        assert finding.id is not None
    
    def test_finding_summary(self):
        finding = Finding(
            severity=FindingSeverity.CRITICAL,
            title="RCE Vulnerability",
            description="Remote code execution",
            target="example.com",
            port=8080,
            tool="nuclei",
        )
        summary = finding.to_summary()
        assert "CRITICAL" in summary
        assert "RCE Vulnerability" in summary
        assert "8080" in summary
    
    def test_finding_to_markdown(self):
        finding = Finding(
            severity=FindingSeverity.MEDIUM,
            title="XSS Vulnerability",
            description="Cross-site scripting found",
            target="example.com",
            tool="dalfox",
            evidence="<script>alert(1)</script>",
        )
        md = finding.to_markdown()
        assert "### XSS Vulnerability" in md
        assert "MEDIUM" in md
        assert "evidence" in md.lower()


class TestFindingSummary:
    """Tests for FindingSummary model."""
    
    def test_from_findings(self):
        findings = [
            Finding(severity=FindingSeverity.CRITICAL, title="F1", description="D1", target="t1", tool="t"),
            Finding(severity=FindingSeverity.HIGH, title="F2", description="D2", target="t2", tool="t"),
            Finding(severity=FindingSeverity.HIGH, title="F3", description="D3", target="t3", tool="t"),
            Finding(severity=FindingSeverity.MEDIUM, title="F4", description="D4", target="t4", tool="t"),
        ]
        summary = FindingSummary.from_findings(findings)
        assert summary.critical == 1
        assert summary.high == 2
        assert summary.medium == 1
        assert summary.total == 4


class TestSessionState:
    """Tests for SessionState model."""
    
    def test_create_session(self):
        session = SessionState(target="example.com")
        assert session.target == "example.com"
        assert session.current_phase == ScanPhase.INITIALIZATION
        assert session.session_id is not None
    
    def test_add_finding(self):
        session = SessionState(target="example.com")
        finding = Finding(
            severity=FindingSeverity.HIGH,
            title="Test",
            description="Test finding",
            target="example.com",
            tool="test",
        )
        session.add_finding(finding)
        assert len(session.findings) == 1
    
    def test_add_asset(self):
        session = SessionState(target="example.com")
        session.add_asset("subdomain", "sub.example.com", "subfinder")
        assert "sub.example.com" in session.context["subdomains"]
    
    def test_update_phase(self):
        session = SessionState(target="example.com")
        session.update_phase(ScanPhase.RECONNAISSANCE)
        assert session.current_phase == ScanPhase.RECONNAISSANCE
        assert ScanPhase.INITIALIZATION in session.completed_phases
    
    def test_get_context_for_ai(self):
        session = SessionState(target="example.com")
        session.add_asset("subdomain", "sub.example.com", "subfinder")
        context = session.get_context_for_ai()
        assert "example.com" in context
        assert "sub.example.com" in context


class TestAIDecision:
    """Tests for AIDecision model."""
    
    def test_create_decision(self):
        decision = AIDecision(
            agent="planner",
            action="run_nmap",
            reasoning="Need to discover open ports",
        )
        assert decision.agent == "planner"
        assert decision.id is not None
    
    def test_decision_summary(self):
        decision = AIDecision(
            agent="executor",
            action="configure_tool",
            reasoning="Setting up nuclei scan",
        )
        summary = decision.to_summary()
        assert "executor" in summary
        assert "configure_tool" in summary


class TestCompletedAction:
    """Tests for CompletedAction model."""
    
    def test_create_action(self):
        action = CompletedAction(
            phase=ScanPhase.RECONNAISSANCE,
            action="subdomain_enumeration",
            tool="subfinder",
        )
        assert action.phase == ScanPhase.RECONNAISSANCE
        assert action.tool == "subfinder"
    
    def test_action_summary(self):
        action = CompletedAction(
            phase=ScanPhase.SCANNING,
            action="port_scan",
            tool="nmap",
        )
        summary = action.to_summary()
        assert "port_scan" in summary
        assert "nmap" in summary

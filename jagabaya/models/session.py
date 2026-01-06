"""
Session and state management models.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from jagabaya.models.findings import Finding, FindingSummary
from jagabaya.models.tools import ToolExecution


class ScanPhase(str, Enum):
    """Phases of a penetration test."""
    
    INITIALIZATION = "initialization"
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"  # Usually disabled in safe mode
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    
    @property
    def description(self) -> str:
        """Get description for the phase."""
        descriptions = {
            "initialization": "Setting up the scan environment",
            "reconnaissance": "Gathering initial information about the target",
            "scanning": "Identifying open ports and services",
            "enumeration": "Deep enumeration of discovered services",
            "vulnerability_analysis": "Scanning for vulnerabilities",
            "exploitation": "Attempting to exploit vulnerabilities",
            "post_exploitation": "Post-exploitation activities",
            "reporting": "Generating reports",
            "completed": "Scan completed",
        }
        return descriptions.get(self.value, "Unknown phase")


class AIDecision(BaseModel):
    """Record of an AI agent decision."""
    
    id: str = Field(default_factory=lambda: uuid4().hex[:8])
    timestamp: datetime = Field(default_factory=datetime.now)
    agent: str = Field(description="Agent that made the decision")
    action: str = Field(description="Action decided")
    reasoning: str = Field(description="Reasoning behind the decision")
    context: str = Field(default="", description="Context provided to the agent")
    parameters: dict[str, Any] = Field(default_factory=dict)
    tokens_used: int = Field(default=0, description="Tokens consumed")
    cost: float = Field(default=0.0, description="Estimated cost in USD")
    
    def to_summary(self) -> str:
        """Get a brief summary."""
        return f"[{self.agent}] {self.action}"


class CompletedAction(BaseModel):
    """Record of a completed action in the scan."""
    
    id: str = Field(default_factory=lambda: uuid4().hex[:8])
    timestamp: datetime = Field(default_factory=datetime.now)
    phase: "ScanPhase" = Field(description="Phase when action was completed")
    action: str = Field(description="Action that was completed")
    description: str = Field(default="", description="Description of what was done")
    tool: str | None = Field(default=None, description="Tool used for the action")
    target: str | None = Field(default=None, description="Target of the action")
    success: bool = Field(default=True, description="Whether the action succeeded")
    duration_seconds: float | None = Field(default=None, description="Duration in seconds")
    
    def to_summary(self) -> str:
        """Get a brief summary."""
        tool_str = f" ({self.tool})" if self.tool else ""
        return f"{self.action}{tool_str}"


class DiscoveredAsset(BaseModel):
    """An asset discovered during scanning."""
    
    type: str = Field(description="Asset type (subdomain, ip, port, service, etc.)")
    value: str = Field(description="Asset value")
    source: str = Field(description="Tool that discovered it")
    timestamp: datetime = Field(default_factory=datetime.now)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionState(BaseModel):
    """
    Maintains the state of a penetration testing session.
    
    This is the core state management class that tracks:
    - Current phase and progress
    - Discovered assets and findings
    - Tool execution history
    - AI decision history
    """
    
    # Session identity
    session_id: str = Field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))
    target: str = Field(description="Primary target")
    
    # Timing
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: datetime | None = Field(default=None)
    
    # Phase tracking
    current_phase: ScanPhase = Field(default=ScanPhase.INITIALIZATION)
    completed_phases: list[ScanPhase] = Field(default_factory=list)
    
    # Scope
    scope: list[str] = Field(default_factory=list, description="In-scope targets")
    blacklist: list[str] = Field(default_factory=list, description="Out-of-scope targets")
    
    # Action tracking
    completed_actions: list[CompletedAction] = Field(default_factory=list)
    pending_actions: list[str] = Field(default_factory=list)
    current_action: str | None = Field(default=None)
    
    # Discoveries
    findings: list[Finding] = Field(default_factory=list)
    discovered_assets: list[DiscoveredAsset] = Field(default_factory=list)
    
    # Context for AI
    context: dict[str, Any] = Field(default_factory=lambda: {
        "target": "",
        "scope": [],
        "subdomains": [],
        "ip_addresses": [],
        "open_ports": [],
        "services": [],
        "technologies": [],
        "urls": [],
    })
    
    # History
    tool_executions: list[ToolExecution] = Field(default_factory=list)
    ai_decisions: list[AIDecision] = Field(default_factory=list)
    
    # Cost tracking
    total_tokens: int = Field(default=0)
    total_cost: float = Field(default=0.0)
    
    # Status
    is_running: bool = Field(default=False)
    error: str | None = Field(default=None)
    
    def add_finding(self, finding: Finding) -> None:
        """Add a security finding."""
        self.findings.append(finding)
    
    def add_findings(self, findings: list[Finding]) -> None:
        """Add multiple findings."""
        self.findings.extend(findings)
    
    def add_asset(self, asset_type: str, value: str, source: str, **metadata: Any) -> None:
        """Add a discovered asset."""
        asset = DiscoveredAsset(
            type=asset_type,
            value=value,
            source=source,
            metadata=metadata,
        )
        self.discovered_assets.append(asset)
        
        # Also update context
        if asset_type == "subdomain" and value not in self.context.get("subdomains", []):
            self.context.setdefault("subdomains", []).append(value)
        elif asset_type == "ip" and value not in self.context.get("ip_addresses", []):
            self.context.setdefault("ip_addresses", []).append(value)
        elif asset_type == "port":
            port_info = {"port": value, **metadata}
            self.context.setdefault("open_ports", []).append(port_info)
        elif asset_type == "service":
            self.context.setdefault("services", []).append(value)
        elif asset_type == "technology":
            if value not in self.context.get("technologies", []):
                self.context.setdefault("technologies", []).append(value)
        elif asset_type == "url":
            if value not in self.context.get("urls", []):
                self.context.setdefault("urls", []).append(value)
    
    def add_tool_execution(self, execution: ToolExecution) -> None:
        """Record a tool execution."""
        self.tool_executions.append(execution)
    
    def add_ai_decision(
        self,
        agent: str,
        action: str,
        reasoning: str,
        context: str = "",
        parameters: dict | None = None,
        tokens: int = 0,
        cost: float = 0.0,
    ) -> None:
        """Record an AI decision."""
        decision = AIDecision(
            agent=agent,
            action=action,
            reasoning=reasoning,
            context=context,
            parameters=parameters or {},
            tokens_used=tokens,
            cost=cost,
        )
        self.ai_decisions.append(decision)
        self.total_tokens += tokens
        self.total_cost += cost
    
    def update_phase(self, phase: ScanPhase) -> None:
        """Update the current phase."""
        if self.current_phase != phase:
            if self.current_phase not in self.completed_phases:
                self.completed_phases.append(self.current_phase)
            self.current_phase = phase
    
    def mark_action_complete(self, action: str) -> None:
        """Mark an action as complete."""
        if action not in self.completed_actions:
            self.completed_actions.append(action)
        if action in self.pending_actions:
            self.pending_actions.remove(action)
        if self.current_action == action:
            self.current_action = None
    
    def get_findings_summary(self) -> FindingSummary:
        """Get summary of findings."""
        return FindingSummary.from_findings(self.findings)
    
    def get_context_for_ai(self) -> str:
        """
        Format the current state as context for AI agents.
        
        This provides a structured summary that helps the AI
        understand what has been discovered and done so far.
        """
        summary = self.get_findings_summary()
        
        context = f"""# Current Session State

## Target
- Primary Target: {self.target}
- Session ID: {self.session_id}
- Current Phase: {self.current_phase.value}

## Progress
- Completed Actions: {len(self.completed_actions)}
- Tool Executions: {len(self.tool_executions)}
- AI Decisions: {len(self.ai_decisions)}

## Findings Summary
- Critical: {summary.critical}
- High: {summary.high}
- Medium: {summary.medium}
- Low: {summary.low}
- Info: {summary.info}
- Total: {summary.total}

## Discovered Assets
"""
        # Add discovered context
        if self.context.get("subdomains"):
            context += f"\n### Subdomains ({len(self.context['subdomains'])})\n"
            for sub in self.context["subdomains"][:20]:
                context += f"- {sub}\n"
            if len(self.context["subdomains"]) > 20:
                context += f"- ... and {len(self.context['subdomains']) - 20} more\n"
        
        if self.context.get("open_ports"):
            context += f"\n### Open Ports ({len(self.context['open_ports'])})\n"
            for port_info in self.context["open_ports"][:20]:
                if isinstance(port_info, dict):
                    context += f"- {port_info.get('port', port_info)}\n"
                else:
                    context += f"- {port_info}\n"
        
        if self.context.get("technologies"):
            context += f"\n### Technologies\n"
            for tech in self.context["technologies"][:20]:
                context += f"- {tech}\n"
        
        if self.context.get("services"):
            context += f"\n### Services\n"
            for svc in self.context["services"][:20]:
                context += f"- {svc}\n"
        
        context += f"\n## Completed Actions\n"
        for action in self.completed_actions[-10:]:
            if isinstance(action, CompletedAction):
                context += f"- {action.to_summary()}\n"
            else:
                context += f"- {action}\n"
        
        return context.strip()
    
    def save(self, directory: Path) -> Path:
        """Save session state to file."""
        directory.mkdir(parents=True, exist_ok=True)
        filepath = directory / f"session_{self.session_id}.json"
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(mode="json"), f, indent=2, default=str)
        
        return filepath
    
    @classmethod
    def load(cls, filepath: Path) -> "SessionState":
        """Load session state from file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.model_validate(data)


class SessionResult(BaseModel):
    """Final result of a completed session."""
    
    session_id: str
    target: str
    status: str = Field(description="completed, failed, cancelled")
    
    # Timing
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    
    # Results
    findings: list[Finding] = Field(default_factory=list)
    findings_summary: FindingSummary
    total_findings: int
    total_tools_executed: int
    total_ai_decisions: int
    
    # Cost
    total_tokens: int
    total_cost: float
    
    # Files
    report_paths: list[str] = Field(default_factory=list)
    session_file: str | None = None
    
    @property
    def total_tools_run(self) -> int:
        """Alias for total_tools_executed for CLI compatibility."""
        return self.total_tools_executed
    
    @property
    def total_ai_calls(self) -> int:
        """Alias for total_ai_decisions for CLI compatibility."""
        return self.total_ai_decisions
    
    @classmethod
    def from_state(cls, state: SessionState, report_paths: list[str] | None = None) -> "SessionResult":
        """Create result from session state."""
        now = datetime.now()
        return cls(
            session_id=state.session_id,
            target=state.target,
            status="completed" if state.current_phase == ScanPhase.COMPLETED else "failed",
            started_at=state.started_at,
            completed_at=state.completed_at or now,
            duration_seconds=(state.completed_at or now).timestamp() - state.started_at.timestamp(),
            findings=state.findings,
            findings_summary=state.get_findings_summary(),
            total_findings=len(state.findings),
            total_tools_executed=len(state.tool_executions),
            total_ai_decisions=len(state.ai_decisions),
            total_tokens=state.total_tokens,
            total_cost=state.total_cost,
            report_paths=report_paths or [],
        )

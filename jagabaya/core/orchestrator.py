"""
Orchestrator for Jagabaya.

The Orchestrator is the main engine that drives the autonomous
penetration testing workflow, coordinating between agents and tools.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Callable

from jagabaya.agents.planner import PlannerAgent
from jagabaya.agents.executor import ExecutorAgent
from jagabaya.agents.analyst import AnalystAgent
from jagabaya.agents.reporter import ReporterAgent
from jagabaya.core.session import SessionManager
from jagabaya.core.scope import ScopeValidator
from jagabaya.models.config import JagabayaConfig, LLMConfig
from jagabaya.models.session import (
    SessionState,
    SessionResult,
    ScanPhase,
    CompletedAction,
    AIDecision,
    DiscoveredAsset,
)
from jagabaya.models.findings import Finding
from jagabaya.models.tools import ToolResult
from jagabaya.tools.registry import ToolRegistry


class Orchestrator:
    """
    Main orchestration engine for autonomous penetration testing.
    
    The Orchestrator coordinates the workflow by:
    1. Using the Planner to decide next actions
    2. Using the Executor to configure tools
    3. Running tools against targets
    4. Using the Analyst to extract findings
    5. Using the Reporter to generate reports
    
    Example:
        >>> config = JagabayaConfig.from_env()
        >>> orchestrator = Orchestrator(config)
        >>> result = await orchestrator.run("example.com")
        >>> print(f"Found {len(result.findings)} vulnerabilities")
    """
    
    def __init__(
        self,
        config: JagabayaConfig,
        on_action: Callable[[str, Any], None] | None = None,
        on_finding: Callable[[Finding], None] | None = None,
        on_progress: Callable[[str, float], None] | None = None,
        verbose: bool = False,
    ):
        """
        Initialize the Orchestrator.
        
        Args:
            config: Jagabaya configuration
            on_action: Callback for action events
            on_finding: Callback for new findings
            on_progress: Callback for progress updates
            verbose: Enable verbose output
        """
        self.config = config
        self.verbose = verbose
        
        # Callbacks
        self.on_action = on_action
        self.on_finding = on_finding
        self.on_progress = on_progress
        
        # Initialize components
        self.session_manager = SessionManager(
            output_dir=config.output.output_dir,
            auto_save=True,
        )
        
        self.tool_registry = ToolRegistry()
        self.tool_registry.register_all()
        
        # Initialize agents
        llm_config = config.llm
        
        self.planner = PlannerAgent(
            config=llm_config,
            available_tools=list(self.tool_registry.list_tools().keys()),
            safe_mode=config.scan.safe_mode,
            verbose=verbose,
        )
        
        self.executor = ExecutorAgent(
            config=llm_config,
            available_tools=list(self.tool_registry.list_tools().values()),
            safe_mode=config.scan.safe_mode,
            stealth_mode=config.scan.stealth_mode,
            max_timeout=config.scan.tool_timeout,
            verbose=verbose,
        )
        
        self.analyst = AnalystAgent(
            config=llm_config,
            verbose=verbose,
        )
        
        self.reporter = ReporterAgent(
            config=llm_config,
            verbose=verbose,
        )
        
        # State
        self._current_session: SessionState | None = None
        self._scope_validator: ScopeValidator | None = None
        self._running = False
        self._should_stop = False
    
    async def run(
        self,
        target: str,
        scope: list[str] | None = None,
        blacklist: list[str] | None = None,
        max_steps: int = 100,
        phases: list[ScanPhase] | None = None,
    ) -> SessionResult:
        """
        Run an autonomous penetration test.
        
        Args:
            target: Primary target to test
            scope: List of in-scope targets
            blacklist: List of out-of-scope targets
            max_steps: Maximum steps to execute
            phases: Phases to run (all if not specified)
        
        Returns:
            SessionResult with findings and summary
        """
        self._running = True
        self._should_stop = False
        
        # Create session
        session = self.session_manager.create_session(
            target=target,
            scope=scope,
            blacklist=blacklist,
        )
        self._current_session = session
        
        # Initialize scope validator
        self._scope_validator = ScopeValidator(
            scope=session.scope,
            blacklist=session.blacklist,
        )
        
        self._log(f"Starting autonomous scan of {target}")
        self._log(f"Session ID: {session.session_id}")
        self._progress("Initializing", 0.0)
        
        try:
            step = 0
            while step < max_steps and not self._should_stop:
                step += 1
                
                self._log(f"\n{'='*50}")
                self._log(f"Step {step}/{max_steps} - Phase: {session.current_phase.value}")
                self._progress(f"Step {step}", step / max_steps)
                
                # Get next action from planner
                decision = await self.planner.run(
                    session,
                    max_steps_remaining=max_steps - step,
                )
                
                # Record AI decision
                ai_decision = AIDecision(
                    agent="planner",
                    action=decision.next_action,
                    reasoning=decision.reasoning,
                    parameters=decision.parameters,
                )
                session.ai_decisions.append(ai_decision)
                
                # Check if we should stop
                if decision.should_stop:
                    self._log("Planner indicates assessment complete")
                    break
                
                # Handle phase transitions
                if decision.phase_transition:
                    try:
                        new_phase = ScanPhase(decision.phase_transition)
                        session.current_phase = new_phase
                        self._log(f"Transitioning to phase: {new_phase.value}")
                    except ValueError:
                        pass
                
                # Execute the planned action
                if decision.tool:
                    await self._execute_tool_action(
                        session,
                        decision.tool,
                        decision.target_override or target,
                        decision.parameters,
                    )
                
                # Record completed action
                action = CompletedAction(
                    phase=session.current_phase,
                    action=decision.next_action,
                    description=decision.expected_outcome,
                    tool=decision.tool,
                )
                session.completed_actions.append(action)
                
                # Auto-save
                self.session_manager.maybe_auto_save(session)
                
                # Callback
                if self.on_action:
                    self.on_action(decision.next_action, decision.model_dump())
            
            # Mark session as complete
            session.completed_at = datetime.now()
            self.session_manager.save_session(session)
            
            self._progress("Complete", 1.0)
            self._log(f"\nScan complete. Found {len(session.findings)} findings.")
            
        except Exception as e:
            self._log(f"Error during scan: {e}")
            session.completed_at = datetime.now()
            self.session_manager.save_session(session)
            raise
        finally:
            self._running = False
        
        return self.session_manager.create_result(session)
    
    async def _execute_tool_action(
        self,
        session: SessionState,
        tool_name: str,
        target: str,
        parameters: dict[str, Any],
    ) -> None:
        """
        Execute a tool action.
        
        Args:
            session: Current session
            tool_name: Name of the tool
            target: Target for the tool
            parameters: Tool parameters
        """
        # Validate target is in scope
        if self._scope_validator and not self._scope_validator.is_in_scope(target):
            self._log(f"Target {target} is out of scope, skipping")
            return
        
        # Get the tool
        tool = self.tool_registry.get_tool(tool_name)
        if not tool:
            self._log(f"Tool {tool_name} not found")
            return
        
        if not tool.is_available:
            self._log(f"Tool {tool_name} is not installed")
            return
        
        self._log(f"Executing {tool_name} on {target}")
        
        # Create execution record
        execution = tool.create_execution_record(target, **parameters)
        session.tool_executions.append(execution)
        
        # Execute the tool
        try:
            timeout = parameters.pop("timeout", self.config.scan.tool_timeout)
            result = await tool.execute(target, timeout=timeout, **parameters)
            
            # Update execution record
            execution.complete(result)
            
            if result.success:
                self._log(f"Tool completed successfully in {result.duration:.1f}s")
                
                # Analyze the output
                await self._analyze_result(session, result)
            else:
                self._log(f"Tool failed: {result.error_message}")
        
        except asyncio.TimeoutError:
            self._log(f"Tool {tool_name} timed out")
            execution.success = False
        except Exception as e:
            self._log(f"Error executing {tool_name}: {e}")
            execution.success = False
    
    async def _analyze_result(
        self,
        session: SessionState,
        result: ToolResult,
    ) -> None:
        """
        Analyze tool result and extract findings.
        
        Args:
            session: Current session
            result: Tool execution result
        """
        self._log(f"Analyzing output from {result.tool}")
        
        # Get analysis from analyst agent
        analysis = await self.analyst.run(session, tool_result=result)
        
        # Record AI decision
        ai_decision = AIDecision(
            agent="analyst",
            action="analyze_output",
            reasoning=analysis.summary,
        )
        session.ai_decisions.append(ai_decision)
        
        # Add discovered assets
        for asset in analysis.assets_discovered:
            # Validate asset is in scope
            if asset.type in ["subdomain", "ip", "url"]:
                if self._scope_validator and not self._scope_validator.is_in_scope(asset.value):
                    continue
            
            discovered = DiscoveredAsset(
                type=asset.type,
                value=asset.value,
                source=result.tool,
                metadata=asset.metadata,
            )
            session.discovered_assets.append(discovered)
        
        self._log(f"Discovered {len(analysis.assets_discovered)} new assets")
        
        # Add findings
        for finding_detail in analysis.findings:
            finding = Finding(
                title=finding_detail.title,
                description=finding_detail.description,
                severity=finding_detail.severity,
                target=finding_detail.target or result.target,
                port=finding_detail.port,
                tool=result.tool,
                evidence=finding_detail.evidence,
                remediation=finding_detail.remediation,
                cvss_score=finding_detail.cvss_score,
                cve_ids=finding_detail.cve_ids,
                false_positive_likelihood=finding_detail.false_positive_likelihood,
            )
            session.findings.append(finding)
            
            self._log(f"[{finding.severity.value.upper()}] {finding.title}")
            
            # Callback
            if self.on_finding:
                self.on_finding(finding)
        
        self._log(f"Extracted {len(analysis.findings)} findings")
    
    async def generate_report(
        self,
        session: SessionState | None = None,
        format: str = "markdown",
    ) -> str:
        """
        Generate a report from the session.
        
        Args:
            session: Session to report on (uses current if not provided)
            format: Report format (markdown, html)
        
        Returns:
            Generated report content
        """
        session = session or self._current_session
        if not session:
            raise ValueError("No session available for reporting")
        
        self._log("Generating report...")
        
        report = await self.reporter.run(session)
        
        return self.reporter.render_report(report, format)
    
    def stop(self) -> None:
        """Request the orchestrator to stop after the current step."""
        self._should_stop = True
        self._log("Stop requested")
    
    @property
    def is_running(self) -> bool:
        """Check if the orchestrator is currently running."""
        return self._running
    
    @property
    def current_session(self) -> SessionState | None:
        """Get the current session."""
        return self._current_session
    
    def _log(self, message: str) -> None:
        """Log a message if verbose mode is enabled."""
        if self.verbose:
            print(f"[ORCHESTRATOR] {message}")
    
    def _progress(self, stage: str, progress: float) -> None:
        """Report progress."""
        if self.on_progress:
            self.on_progress(stage, progress)
    
    def get_stats(self) -> dict[str, Any]:
        """
        Get statistics about the orchestrator and agents.
        
        Returns:
            Dictionary with statistics
        """
        return {
            "planner": self.planner.get_stats(),
            "executor": self.executor.get_stats(),
            "analyst": self.analyst.get_stats(),
            "reporter": self.reporter.get_stats(),
            "tools_available": len(self.tool_registry.get_available_tools()),
            "tools_total": len(self.tool_registry.list_tools()),
        }

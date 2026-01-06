"""
Orchestrator for Jagabaya.

The Orchestrator is the main engine that drives the autonomous
penetration testing workflow, coordinating between agents and tools.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Callable, TYPE_CHECKING

from jagabaya.agents.planner import PlannerAgent
from jagabaya.agents.executor import ExecutorAgent
from jagabaya.agents.analyst import AnalystAgent
from jagabaya.agents.reporter import ReporterAgent
from jagabaya.agents.validator import ValidatorAgent
from jagabaya.agents.correlator import CorrelatorAgent
from jagabaya.core.session import SessionManager
from jagabaya.core.scope import ScopeValidator
from jagabaya.core.storage import SessionStorage
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

if TYPE_CHECKING:
    from jagabaya.analysis.attack_paths import AttackPathResult


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
        >>> config = JagabayaConfig.load()
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
        validate_findings: bool = False,
    ):
        """
        Initialize the Orchestrator.

        Args:
            config: Jagabaya configuration
            on_action: Callback for action events
            on_finding: Callback for new findings
            on_progress: Callback for progress updates
            verbose: Enable verbose output
            validate_findings: Enable finding validation to reduce false positives
        """
        self.config = config
        self.verbose = verbose
        self.validate_findings = validate_findings

        # Callbacks
        self.on_action = on_action
        self.on_finding = on_finding
        self.on_progress = on_progress

        # Initialize components
        self.session_manager = SessionManager(
            output_dir=config.output.output_dir,
            auto_save=True,
        )

        # SQLite storage for resume capability
        self.storage = SessionStorage(config.output.output_dir)

        self.tool_registry = ToolRegistry()
        # Registry uses lazy initialization, no need to call register_all

        # Initialize agents
        llm_config = config.llm

        self.planner = PlannerAgent(
            config=llm_config,
            available_tools=list(self.tool_registry.get_all().keys()),
            safe_mode=config.scan.safe_mode,
            verbose=verbose,
        )

        self.executor = ExecutorAgent(
            config=llm_config,
            available_tools=list(self.tool_registry.get_all().values()),
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
        
        self.validator = ValidatorAgent(
            config=llm_config,
            verbose=verbose,
        )
        
        self.correlator = CorrelatorAgent(
            config=llm_config,
            verbose=verbose,
        )

        # State
        self._current_session: SessionState | None = None
        self._scope_validator: ScopeValidator | None = None
        self._running = False
        self._should_stop = False
        self._current_step = 0
        self._max_steps = 100

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
        self._max_steps = max_steps

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

        # Save initial state to SQLite
        self.storage.save_session(session, current_step=0, max_steps=max_steps, status="running")

        try:
            await self._run_scan_loop(session, max_steps, start_step=0)
        except Exception as e:
            self._log(f"Error during scan: {e}")
            session.error = str(e)
            session.completed_at = datetime.now()
            self.session_manager.save_session(session)
            self.storage.save_session(session, self._current_step, max_steps, status="failed")
            raise
        finally:
            self._running = False

        return self.session_manager.create_result(session)

    async def resume(
        self,
        session_id: str,
        max_steps: int | None = None,
    ) -> SessionResult:
        """
        Resume an interrupted session.

        Args:
            session_id: Session ID to resume
            max_steps: Override max steps (optional)

        Returns:
            SessionResult with findings and summary
        """
        # Load session from SQLite
        session = self.storage.load_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        # Get session info for step tracking
        info = self.storage.get_session_info(session_id)
        if not info:
            raise ValueError(f"Session info not found for {session_id}")

        if info["status"] not in ("running", "interrupted"):
            raise ValueError(f"Session {session_id} is not resumable (status: {info['status']})")

        start_step = info["current_step"]
        total_max_steps = max_steps or info["max_steps"]

        self._running = True
        self._should_stop = False
        self._current_session = session
        self._max_steps = total_max_steps

        # Clear any previous error
        session.error = None

        # Initialize scope validator
        self._scope_validator = ScopeValidator(
            scope=session.scope,
            blacklist=session.blacklist,
        )

        self._log(f"Resuming session {session_id} from step {start_step}")
        self._log(f"Target: {session.target}")
        self._progress("Resuming", start_step / total_max_steps)

        # Update status to running
        self.storage.save_session(session, start_step, total_max_steps, status="running")

        try:
            await self._run_scan_loop(session, total_max_steps, start_step=start_step)
        except Exception as e:
            self._log(f"Error during scan: {e}")
            session.error = str(e)
            session.completed_at = datetime.now()
            self.session_manager.save_session(session)
            self.storage.save_session(session, self._current_step, total_max_steps, status="failed")
            raise
        finally:
            self._running = False

        return self.session_manager.create_result(session)

    async def _run_scan_loop(
        self,
        session: SessionState,
        max_steps: int,
        start_step: int = 0,
    ) -> None:
        """
        Run the main scan loop.

        Args:
            session: Session state
            max_steps: Maximum steps
            start_step: Step to start from (for resume)
        """
        step = start_step
        try:
            while step < max_steps and not self._should_stop:
                step += 1
                self._current_step = step

                self._log(f"\n{'=' * 50}")
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
                        decision.target_override or session.target,
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

                # Save to SQLite after each step
                self.storage.save_session(session, step, max_steps, status="running")
                self.storage.add_action(
                    session.session_id,
                    step,
                    decision.next_action,
                    tool=decision.tool,
                    target=decision.target_override or session.target,
                )

                # Auto-save JSON
                self.session_manager.maybe_auto_save(session)

                # Callback
                if self.on_action:
                    self.on_action(decision.next_action, decision.model_dump())

            # Mark session as complete
            session.completed_at = datetime.now()
            
            # Run post-scan analysis
            await self._run_post_scan_analysis(session)
            
            self.session_manager.save_session(session)
            self.storage.mark_completed(session.session_id, "completed")

            self._progress("Complete", 1.0)
            self._log(f"\nScan complete. Found {len(session.findings)} findings.")

        except KeyboardInterrupt:
            # Handle graceful interrupt
            self._log("\nScan interrupted by user")
            self.storage.mark_interrupted(session.session_id, "User interrupted")
            self.session_manager.save_session(session)
            raise

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
        tool = self.tool_registry.get(tool_name)
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

    async def _run_post_scan_analysis(
        self,
        session: SessionState,
    ) -> None:
        """
        Run post-scan analysis including correlation and optional validation.

        Args:
            session: Current session
        """
        if not session.findings:
            self._log("No findings to analyze")
            return

        # Run correlation analysis
        self._log("Running correlation analysis...")
        self._progress("Correlating findings", 0.95)
        
        try:
            correlation = await self.correlator.run(session)
            
            # Store correlation results in session metadata
            session.metadata = session.metadata or {}
            session.metadata["correlation"] = {
                "attack_paths": [p.model_dump() for p in correlation.attack_paths],
                "risk_score": correlation.risk_score,
                "key_insights": correlation.key_insights,
                "priority_targets": [t.model_dump() for t in correlation.priority_targets],
            }
            
            self._log(f"Identified {len(correlation.attack_paths)} attack paths")
            self._log(f"Overall risk score: {correlation.risk_score}/10")
            
        except Exception as e:
            self._log(f"Correlation analysis failed: {e}")

        # Run validation if enabled
        if self.validate_findings:
            await self._validate_findings(session)

    async def _validate_findings(
        self,
        session: SessionState,
    ) -> None:
        """
        Validate findings to reduce false positives.

        Args:
            session: Current session
        """
        self._log(f"Validating {len(session.findings)} findings...")
        self._progress("Validating findings", 0.97)
        
        try:
            validation_result = await self.validator.validate_batch(session)
            
            # Apply validation results
            validated_count = 0
            fp_count = 0
            
            for result in validation_result.validated_findings:
                # Find the matching finding
                for finding in session.findings:
                    if finding.id == result.finding_id:
                        await self.validator.apply_validation(finding, result)
                        
                        if result.status == "verified":
                            validated_count += 1
                        elif result.status == "likely_false_positive":
                            fp_count += 1
                        break
            
            self._log(f"Validation complete: {validated_count} verified, {fp_count} likely false positives")
            
            # Store validation summary
            session.metadata = session.metadata or {}
            session.metadata["validation"] = {
                "verified_count": validation_result.verified_count,
                "false_positive_count": validation_result.false_positive_count,
                "needs_review_count": validation_result.needs_review_count,
                "summary": validation_result.summary,
            }
            
        except Exception as e:
            self._log(f"Validation failed: {e}")

    async def validate_session_findings(
        self,
        session: SessionState | None = None,
    ) -> dict:
        """
        Manually validate findings for a session.

        Args:
            session: Session to validate (uses current if not provided)

        Returns:
            Validation results dictionary
        """
        session = session or self._current_session
        if not session:
            raise ValueError("No session available for validation")

        self._log(f"Validating {len(session.findings)} findings...")
        
        result = await self.validator.validate_batch(session)
        
        # Apply results
        for validation in result.validated_findings:
            for finding in session.findings:
                if finding.id == validation.finding_id:
                    await self.validator.apply_validation(finding, validation)
                    break
        
        return {
            "verified": result.verified_count,
            "false_positives": result.false_positive_count,
            "needs_review": result.needs_review_count,
            "summary": result.summary,
        }

    async def correlate_findings(
        self,
        session: SessionState | None = None,
    ) -> dict:
        """
        Run correlation analysis on session findings.

        Args:
            session: Session to analyze (uses current if not provided)

        Returns:
            Correlation results dictionary
        """
        session = session or self._current_session
        if not session:
            raise ValueError("No session available for correlation")

        self._log("Running correlation analysis...")
        
        result = await self.correlator.run(session)
        
        return {
            "attack_paths": [p.model_dump() for p in result.attack_paths],
            "risk_score": result.risk_score,
            "risk_assessment": result.overall_risk_assessment,
            "key_insights": result.key_insights,
            "priority_targets": [t.model_dump() for t in result.priority_targets],
        }

    async def analyze_attack_paths(
        self,
        session: SessionState | None = None,
        use_llm: bool = True,
    ) -> "AttackPathResult":
        """
        Run hybrid attack path analysis on session findings.

        Combines rule-based pattern matching with LLM-enhanced discovery
        to identify exploitable attack chains.

        Args:
            session: Session to analyze (uses current if not provided)
            use_llm: Whether to use LLM for enhanced analysis

        Returns:
            AttackPathResult with discovered attack chains
        """
        from jagabaya.analysis.attack_paths import AttackPathResult
        
        session = session or self._current_session
        if not session:
            raise ValueError("No session available for attack path analysis")

        self._log("Running attack path analysis...")
        
        result = await self.correlator.analyze_attack_paths(session, use_llm=use_llm)
        
        # Store in session metadata
        session.metadata = getattr(session, 'metadata', None) or {}
        session.metadata["attack_paths"] = {
            "total_chains": result.total_chains,
            "critical_chains": result.critical_chains,
            "high_chains": result.high_chains,
            "medium_chains": result.medium_chains,
            "low_chains": result.low_chains,
            "top_risks": result.top_risks,
            "chains": [
                {
                    "id": c.id,
                    "name": c.name,
                    "score": c.score,
                    "risk_level": c.risk_level,
                    "attack_type": c.attack_type,
                    "impact": c.impact,
                    "nodes_count": len(c.nodes),
                }
                for c in result.get_top_chains(10)
            ],
        }
        
        self._log(f"Found {result.total_chains} attack paths")
        
        return result

    def render_attack_paths(
        self,
        result: "AttackPathResult",
        format: str = "ascii",
    ) -> str:
        """
        Render attack paths for display.

        Args:
            result: Attack path analysis result
            format: Output format ('ascii', 'mermaid', 'plain')

        Returns:
            Rendered attack paths string
        """
        from jagabaya.analysis.attack_paths import AttackPathResult
        
        if format == "mermaid":
            from jagabaya.analysis.renderers import MermaidRenderer
            renderer = MermaidRenderer()
            return renderer.render_result(result)
        elif format == "plain":
            from jagabaya.analysis.renderers import ASCIIRenderer
            renderer = ASCIIRenderer()
            return renderer.to_plain_text(result)
        else:
            from jagabaya.analysis.renderers import ASCIIRenderer
            renderer = ASCIIRenderer()
            return renderer.render_compact(result)

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

        # Save current state as interrupted
        if self._current_session:
            self.storage.mark_interrupted(
                self._current_session.session_id, "Stop requested by user"
            )
            self.session_manager.save_session(self._current_session)

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
            "validator": self.validator.get_stats(),
            "correlator": self.correlator.get_stats(),
            "tools_available": len(self.tool_registry.get_available()),
            "tools_total": len(self.tool_registry.get_all()),
        }

"""
Workflow executor for Jagabaya.

Executes workflow definitions, running tools and tracking progress.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Callable

from jagabaya.workflows.loader import Workflow, WorkflowPhase, WorkflowStep
from jagabaya.tools.registry import ToolRegistry
from jagabaya.models.session import SessionState, ScanPhase
from jagabaya.models.findings import Finding
from jagabaya.models.tools import ToolResult


class StepResult:
    """Result of executing a workflow step."""
    
    def __init__(
        self,
        step: WorkflowStep,
        success: bool,
        tool_result: ToolResult | None = None,
        error: str | None = None,
        duration: float = 0.0,
        skipped: bool = False,
    ):
        """Initialize step result."""
        self.step = step
        self.success = success
        self.tool_result = tool_result
        self.error = error
        self.duration = duration
        self.skipped = skipped
        self.timestamp = datetime.now()


class PhaseResult:
    """Result of executing a workflow phase."""
    
    def __init__(self, phase: WorkflowPhase):
        """Initialize phase result."""
        self.phase = phase
        self.step_results: list[StepResult] = []
        self.started_at: datetime | None = None
        self.completed_at: datetime | None = None
    
    @property
    def success(self) -> bool:
        """Check if all steps succeeded."""
        return all(r.success or r.skipped for r in self.step_results)
    
    @property
    def duration(self) -> float:
        """Get total duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return sum(r.duration for r in self.step_results)


class WorkflowResult:
    """Result of executing a workflow."""
    
    def __init__(self, workflow: Workflow):
        """Initialize workflow result."""
        self.workflow = workflow
        self.phase_results: list[PhaseResult] = []
        self.started_at: datetime | None = None
        self.completed_at: datetime | None = None
        self.findings: list[Finding] = []
        self.aborted: bool = False
        self.abort_reason: str | None = None
    
    @property
    def success(self) -> bool:
        """Check if workflow completed successfully."""
        return not self.aborted and all(p.success for p in self.phase_results)
    
    @property
    def duration(self) -> float:
        """Get total duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return sum(p.duration for p in self.phase_results)
    
    @property
    def total_steps(self) -> int:
        """Get total number of steps."""
        return sum(len(p.step_results) for p in self.phase_results)
    
    @property
    def successful_steps(self) -> int:
        """Get number of successful steps."""
        return sum(
            sum(1 for s in p.step_results if s.success)
            for p in self.phase_results
        )


class WorkflowExecutor:
    """
    Executes workflow definitions.
    
    Example:
        >>> executor = WorkflowExecutor(tool_registry)
        >>> result = await executor.execute(workflow, session, "example.com")
    """
    
    def __init__(
        self,
        tool_registry: ToolRegistry,
        on_step_start: Callable[[WorkflowStep], None] | None = None,
        on_step_complete: Callable[[StepResult], None] | None = None,
        on_finding: Callable[[Finding], None] | None = None,
        on_phase_start: Callable[[WorkflowPhase], None] | None = None,
        on_phase_complete: Callable[[PhaseResult], None] | None = None,
        verbose: bool = False,
    ):
        """
        Initialize the executor.
        
        Args:
            tool_registry: Tool registry instance
            on_step_start: Callback when step starts
            on_step_complete: Callback when step completes
            on_finding: Callback when finding is discovered
            on_phase_start: Callback when phase starts
            on_phase_complete: Callback when phase completes
            verbose: Enable verbose output
        """
        self.tool_registry = tool_registry
        self.on_step_start = on_step_start
        self.on_step_complete = on_step_complete
        self.on_finding = on_finding
        self.on_phase_start = on_phase_start
        self.on_phase_complete = on_phase_complete
        self.verbose = verbose
        
        self._should_stop = False
    
    async def execute(
        self,
        workflow: Workflow,
        session: SessionState,
        target: str,
        variables: dict[str, Any] | None = None,
    ) -> WorkflowResult:
        """
        Execute a workflow.
        
        Args:
            workflow: Workflow to execute
            session: Session state
            target: Primary target
            variables: Additional variables
        
        Returns:
            Workflow execution result
        """
        self._should_stop = False
        
        result = WorkflowResult(workflow)
        result.started_at = datetime.now()
        
        # Merge variables
        all_variables = {
            "target": target,
            **workflow.variables,
            **(variables or {}),
        }
        
        try:
            for phase in workflow.phases:
                # Check if should skip phase
                if phase.skip_if and self._evaluate_condition(phase.skip_if, session, all_variables):
                    self._log(f"Skipping phase: {phase.name}")
                    continue
                
                # Check for stop request
                if self._should_stop:
                    result.aborted = True
                    result.abort_reason = "Stopped by user"
                    break
                
                # Execute phase
                phase_result = await self._execute_phase(
                    phase=phase,
                    session=session,
                    variables=all_variables,
                    max_parallel=workflow.max_parallel,
                    default_timeout=workflow.default_timeout,
                )
                result.phase_results.append(phase_result)
                
                # Collect findings
                for step_result in phase_result.step_results:
                    if step_result.tool_result and step_result.tool_result.parsed_data:
                        # Extract findings from parsed data if present
                        findings = step_result.tool_result.parsed_data.get("findings", [])
                        for f in findings:
                            if isinstance(f, Finding):
                                result.findings.append(f)
                
                # Check if should abort
                if not phase_result.success and not phase.continue_on_error:
                    result.aborted = True
                    result.abort_reason = f"Phase '{phase.name}' failed"
                    break
        
        except Exception as e:
            result.aborted = True
            result.abort_reason = str(e)
        
        finally:
            result.completed_at = datetime.now()
        
        return result
    
    async def _execute_phase(
        self,
        phase: WorkflowPhase,
        session: SessionState,
        variables: dict[str, Any],
        max_parallel: int,
        default_timeout: int,
    ) -> PhaseResult:
        """Execute a single phase."""
        phase_result = PhaseResult(phase)
        phase_result.started_at = datetime.now()
        
        if self.on_phase_start:
            self.on_phase_start(phase)
        
        self._log(f"Starting phase: {phase.name}")
        
        # Group steps by dependencies
        completed_steps: set[str] = set()
        pending_steps = list(phase.steps)
        
        while pending_steps and not self._should_stop:
            # Find runnable steps
            runnable = [
                step for step in pending_steps
                if all(req in completed_steps for req in step.requires)
            ]
            
            if not runnable:
                if pending_steps:
                    # Deadlock - remaining steps have unmet dependencies
                    for step in pending_steps:
                        step_result = StepResult(
                            step=step,
                            success=False,
                            error="Unmet dependencies",
                            skipped=True,
                        )
                        phase_result.step_results.append(step_result)
                break
            
            # Separate parallel and sequential steps
            parallel_steps = [s for s in runnable if s.parallel][:max_parallel]
            sequential_steps = [s for s in runnable if not s.parallel]
            
            # Run parallel steps
            if parallel_steps:
                tasks = [
                    self._execute_step(step, session, variables, default_timeout)
                    for step in parallel_steps
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for step, result in zip(parallel_steps, results):
                    if isinstance(result, Exception):
                        step_result = StepResult(
                            step=step,
                            success=False,
                            error=str(result),
                        )
                    else:
                        step_result = result
                    
                    phase_result.step_results.append(step_result)
                    completed_steps.add(step.name)
                    pending_steps.remove(step)
                    
                    if self.on_step_complete:
                        self.on_step_complete(step_result)
            
            # Run one sequential step
            elif sequential_steps:
                step = sequential_steps[0]
                step_result = await self._execute_step(step, session, variables, default_timeout)
                
                phase_result.step_results.append(step_result)
                completed_steps.add(step.name)
                pending_steps.remove(step)
                
                if self.on_step_complete:
                    self.on_step_complete(step_result)
                
                # Handle failure
                if not step_result.success and step.on_failure == "abort":
                    break
        
        phase_result.completed_at = datetime.now()
        
        if self.on_phase_complete:
            self.on_phase_complete(phase_result)
        
        return phase_result
    
    async def _execute_step(
        self,
        step: WorkflowStep,
        session: SessionState,
        variables: dict[str, Any],
        default_timeout: int,
    ) -> StepResult:
        """Execute a single step."""
        start_time = datetime.now()
        
        if self.on_step_start:
            self.on_step_start(step)
        
        self._log(f"Executing step: {step.name} ({step.tool})")
        
        # Check condition
        if step.condition and not self._evaluate_condition(step.condition, session, variables):
            return StepResult(
                step=step,
                success=True,
                skipped=True,
            )
        
        # Get the tool
        tool = self.tool_registry.get_tool(step.tool)
        if not tool:
            return StepResult(
                step=step,
                success=False,
                error=f"Tool not found: {step.tool}",
            )
        
        if not tool.is_available:
            return StepResult(
                step=step,
                success=False,
                error=f"Tool not installed: {step.tool}",
            )
        
        # Resolve target
        target = self._resolve_variable(step.target, variables, session)
        
        # Resolve parameters
        params = {}
        for key, value in step.parameters.items():
            if isinstance(value, str):
                params[key] = self._resolve_variable(value, variables, session)
            else:
                params[key] = value
        
        # Execute
        try:
            timeout = step.timeout or default_timeout
            tool_result = await tool.execute(target, timeout=timeout, **params)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return StepResult(
                step=step,
                success=tool_result.success,
                tool_result=tool_result,
                error=tool_result.error_message if not tool_result.success else None,
                duration=duration,
            )
        
        except asyncio.TimeoutError:
            duration = (datetime.now() - start_time).total_seconds()
            return StepResult(
                step=step,
                success=False,
                error="Timeout",
                duration=duration,
            )
        
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return StepResult(
                step=step,
                success=False,
                error=str(e),
                duration=duration,
            )
    
    def _resolve_variable(
        self,
        value: str,
        variables: dict[str, Any],
        session: SessionState,
    ) -> str:
        """Resolve variable placeholders in a string."""
        result = value
        
        # Replace {variable} patterns
        for var_name, var_value in variables.items():
            result = result.replace(f"{{{var_name}}}", str(var_value))
        
        # Special session variables
        result = result.replace("{session.target}", session.target)
        result = result.replace("{session.id}", session.session_id)
        
        return result
    
    def _evaluate_condition(
        self,
        condition: str,
        session: SessionState,
        variables: dict[str, Any],
    ) -> bool:
        """
        Evaluate a condition string.
        
        Supports simple conditions like:
        - "has_subdomains" -> len(session.context.get("subdomains", [])) > 0
        - "findings > 0"
        - "phase == reconnaissance"
        """
        condition = condition.strip().lower()
        
        # Simple checks
        if condition == "has_subdomains":
            return len(session.context.get("subdomains", [])) > 0
        
        if condition == "has_open_ports":
            return len(session.context.get("open_ports", [])) > 0
        
        if condition == "has_findings":
            return len(session.findings) > 0
        
        if condition == "has_urls":
            return len(session.context.get("urls", [])) > 0
        
        if condition == "safe_mode":
            return variables.get("safe_mode", True)
        
        # Default to True for unknown conditions
        return True
    
    def stop(self) -> None:
        """Request the executor to stop."""
        self._should_stop = True
    
    def _log(self, message: str) -> None:
        """Log a message if verbose mode is enabled."""
        if self.verbose:
            print(f"[WORKFLOW] {message}")

"""
Planner agent.

The Planner is the strategic decision-maker that analyzes the current state
and determines the optimal next action in the penetration testing workflow.
"""

from __future__ import annotations

from typing import Any

from jagabaya.agents.base import BaseAgent
from jagabaya.llm.prompts.planner import (
    PLANNER_SYSTEM_PROMPT,
    PLANNER_DECISION_PROMPT,
)
from jagabaya.llm.structured import PlannerDecision
from jagabaya.models.session import SessionState, ScanPhase
from jagabaya.models.config import LLMConfig


class PlannerAgent(BaseAgent[PlannerDecision]):
    """
    Strategic planning agent for penetration testing.
    
    The Planner analyzes the current session state and decides:
    - What action to take next
    - Which tool to use
    - What parameters to configure
    - Whether to transition phases
    - When the assessment is complete
    
    Example:
        >>> planner = PlannerAgent(llm_config)
        >>> decision = await planner.run(session_state)
        >>> print(decision.next_action)
        "port_scan"
        >>> print(decision.tool)
        "nmap"
    """
    
    name = "planner"
    description = "Strategic decision-making for penetration testing workflow"
    
    def __init__(
        self,
        config: LLMConfig,
        available_tools: list[str] | None = None,
        safe_mode: bool = True,
        verbose: bool = False,
    ):
        """
        Initialize the Planner agent.
        
        Args:
            config: LLM configuration
            available_tools: List of available tool names
            safe_mode: Enable safe mode (no exploitation)
            verbose: Enable verbose logging
        """
        super().__init__(config, verbose)
        self.available_tools = available_tools or []
        self.safe_mode = safe_mode
    
    @property
    def system_prompt(self) -> str:
        return PLANNER_SYSTEM_PROMPT
    
    async def run(
        self,
        state: SessionState,
        max_steps_remaining: int = 100,
        **kwargs: Any,
    ) -> PlannerDecision:
        """
        Analyze the current state and decide the next action.
        
        Args:
            state: Current session state
            max_steps_remaining: Maximum steps remaining in the workflow
            **kwargs: Additional arguments
        
        Returns:
            PlannerDecision with the next action to take
        """
        self.log(f"Planning next action for phase: {state.current_phase}")
        
        # Build context from session state
        context = self._build_context(state)
        
        # Format the decision prompt
        prompt = PLANNER_DECISION_PROMPT.format(
            context=context,
            safe_mode="ENABLED - No exploitation allowed" if self.safe_mode else "DISABLED",
            available_tools=", ".join(self.available_tools) if self.available_tools else "All tools",
            max_steps_remaining=max_steps_remaining,
        )
        
        # Get structured decision from LLM
        decision = await self._complete_structured(
            prompt,
            PlannerDecision,
        )
        
        self.log(f"Decision: {decision.next_action} with {decision.tool}")
        self.log(f"Reasoning: {decision.reasoning}")
        
        return decision
    
    async def should_transition_phase(
        self,
        state: SessionState,
    ) -> ScanPhase | None:
        """
        Determine if we should transition to a new phase.
        
        Args:
            state: Current session state
        
        Returns:
            New phase to transition to, or None
        """
        decision = await self.run(state)
        
        if decision.phase_transition:
            try:
                return ScanPhase(decision.phase_transition)
            except ValueError:
                return None
        
        return None
    
    async def is_assessment_complete(
        self,
        state: SessionState,
    ) -> bool:
        """
        Check if the assessment should be considered complete.
        
        Args:
            state: Current session state
        
        Returns:
            True if assessment is complete
        """
        decision = await self.run(state)
        return decision.should_stop
    
    def _build_context(self, state: SessionState) -> str:
        """
        Build context string from session state.
        
        Args:
            state: Current session state
        
        Returns:
            Formatted context string
        """
        context_parts = []
        
        # Target information
        context_parts.append("## Target Information")
        context_parts.append(f"Primary Target: {state.target}")
        if state.scope:
            context_parts.append(f"Scope: {', '.join(state.scope)}")
        if state.blacklist:
            context_parts.append(f"Blacklist: {', '.join(state.blacklist)}")
        
        # Current phase
        context_parts.append(f"\n## Current Phase: {state.current_phase.value}")
        
        # Discovered assets
        if state.discovered_assets:
            context_parts.append("\n## Discovered Assets")
            
            # Group by type
            by_type: dict[str, list] = {}
            for asset in state.discovered_assets:
                asset_type = asset.type
                if asset_type not in by_type:
                    by_type[asset_type] = []
                by_type[asset_type].append(asset.value)
            
            for asset_type, assets in by_type.items():
                if len(assets) <= 10:
                    context_parts.append(f"- {asset_type}: {', '.join(assets)}")
                else:
                    context_parts.append(f"- {asset_type}: {', '.join(assets[:10])} ... ({len(assets)} total)")
        
        # Completed actions
        if state.completed_actions:
            context_parts.append("\n## Completed Actions")
            for action in state.completed_actions[-10:]:  # Last 10 actions
                context_parts.append(f"- [{action.timestamp}] {action.action}: {action.description}")
        
        # AI decisions history
        if state.ai_decisions:
            context_parts.append("\n## Recent AI Decisions")
            for decision in state.ai_decisions[-5:]:  # Last 5 decisions
                context_parts.append(f"- {decision.action}: {decision.reasoning[:100]}...")
        
        # Tool executions
        if state.tool_executions:
            context_parts.append("\n## Recent Tool Executions")
            for execution in state.tool_executions[-10:]:
                status = "SUCCESS" if execution.success else "FAILED"
                context_parts.append(
                    f"- [{status}] {execution.tool} on {execution.target} "
                    f"({execution.findings_count} findings)"
                )
        
        # Findings summary
        if state.findings:
            context_parts.append("\n## Findings Summary")
            summary = state.get_findings_summary()
            context_parts.append(f"- Critical: {summary.critical}")
            context_parts.append(f"- High: {summary.high}")
            context_parts.append(f"- Medium: {summary.medium}")
            context_parts.append(f"- Low: {summary.low}")
            context_parts.append(f"- Info: {summary.info}")
            context_parts.append(f"- Total: {summary.total}")
            
            # Top findings
            critical_high = [f for f in state.findings if f.severity.value in ["critical", "high"]]
            if critical_high:
                context_parts.append("\nTop Critical/High Findings:")
                for finding in critical_high[:5]:
                    context_parts.append(f"- [{finding.severity.value.upper()}] {finding.title}")
        
        return "\n".join(context_parts)
    
    def set_available_tools(self, tools: list[str]) -> None:
        """
        Update the list of available tools.
        
        Args:
            tools: List of available tool names
        """
        self.available_tools = tools
    
    def set_safe_mode(self, enabled: bool) -> None:
        """
        Enable or disable safe mode.
        
        Args:
            enabled: Whether safe mode is enabled
        """
        self.safe_mode = enabled

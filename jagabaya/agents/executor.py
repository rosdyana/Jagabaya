"""
Executor agent.

The Executor agent is responsible for selecting and configuring
security tools based on the planner's decisions.
"""

from __future__ import annotations

from typing import Any

from jagabaya.agents.base import BaseAgent
from jagabaya.llm.prompts.executor import (
    EXECUTOR_SYSTEM_PROMPT,
    TOOL_SELECTION_PROMPT,
)
from jagabaya.llm.structured import ToolSelection
from jagabaya.models.session import SessionState
from jagabaya.models.config import LLMConfig
from jagabaya.models.tools import ToolInfo


class ExecutorAgent(BaseAgent[ToolSelection]):
    """
    Tool selection and configuration agent.
    
    The Executor takes an objective from the Planner and selects
    the most appropriate tool with optimal configuration.
    
    Example:
        >>> executor = ExecutorAgent(llm_config)
        >>> selection = await executor.run(
        ...     state,
        ...     objective="Scan for open ports",
        ...     target="192.168.1.1",
        ... )
        >>> print(selection.tool)
        "nmap"
        >>> print(selection.command_args)
        ["-sV", "-sC", "-p", "1-1000"]
    """
    
    name = "executor"
    description = "Tool selection and configuration for security testing"
    
    def __init__(
        self,
        config: LLMConfig,
        available_tools: list[ToolInfo] | None = None,
        safe_mode: bool = True,
        stealth_mode: bool = False,
        max_timeout: int = 600,
        verbose: bool = False,
    ):
        """
        Initialize the Executor agent.
        
        Args:
            config: LLM configuration
            available_tools: List of available tool information
            safe_mode: Enable safe mode (no aggressive scans)
            stealth_mode: Enable stealth mode (slower, less detectable)
            max_timeout: Maximum execution timeout in seconds
            verbose: Enable verbose logging
        """
        super().__init__(config, verbose)
        self.available_tools = available_tools or []
        self.safe_mode = safe_mode
        self.stealth_mode = stealth_mode
        self.max_timeout = max_timeout
    
    @property
    def system_prompt(self) -> str:
        return EXECUTOR_SYSTEM_PROMPT
    
    async def run(
        self,
        state: SessionState,
        objective: str | None = None,
        target: str | None = None,
        suggested_tool: str | None = None,
        **kwargs: Any,
    ) -> ToolSelection:
        """
        Select and configure a tool for the given objective.
        
        Args:
            state: Current session state
            objective: The objective to achieve
            target: Specific target (defaults to session target)
            suggested_tool: Tool suggested by the planner
            **kwargs: Additional arguments
        
        Returns:
            ToolSelection with tool and configuration
        """
        target = target or state.target
        objective = objective or "Perform security testing"
        
        self.log(f"Selecting tool for: {objective}")
        self.log(f"Target: {target}")
        
        # Determine target type
        target_type = self._detect_target_type(target)
        
        # Get previously used tools
        previous_tools = [e.tool for e in state.tool_executions[-10:]]
        
        # Format available tools
        tools_info = self._format_available_tools()
        
        # Build the prompt
        prompt = TOOL_SELECTION_PROMPT.format(
            objective=objective,
            target=target,
            target_type=target_type,
            phase=state.current_phase.value,
            previous_tools=", ".join(previous_tools) if previous_tools else "None",
            safe_mode="ENABLED" if self.safe_mode else "DISABLED",
            stealth="REQUIRED" if self.stealth_mode else "Not required",
            max_timeout=self.max_timeout,
            available_tools=tools_info,
        )
        
        # If a tool is suggested, add it to the prompt
        if suggested_tool:
            prompt += f"\n\nNote: The planner suggested using '{suggested_tool}'. Consider this suggestion."
        
        # Get structured selection from LLM
        selection = await self._complete_structured(
            prompt,
            ToolSelection,
        )
        
        self.log(f"Selected tool: {selection.tool}")
        self.log(f"Reasoning: {selection.reasoning}")
        
        return selection
    
    async def get_tool_config(
        self,
        tool_name: str,
        target: str,
        objective: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Get configuration parameters for a specific tool.
        
        Args:
            tool_name: Name of the tool
            target: Target for the tool
            objective: Objective to achieve
            **kwargs: Additional configuration hints
        
        Returns:
            Dictionary of configuration parameters
        """
        prompt = f"""Configure the '{tool_name}' tool for this objective:

## Objective
{objective}

## Target
{target}

## Constraints
- Safe Mode: {"ENABLED" if self.safe_mode else "DISABLED"}
- Stealth Mode: {"ENABLED" if self.stealth_mode else "DISABLED"}
- Max Timeout: {self.max_timeout} seconds

Provide the optimal configuration parameters as a JSON object.
Include only parameters relevant to the objective.
"""
        
        config = await self._complete_json(prompt)
        
        return config
    
    def _detect_target_type(self, target: str) -> str:
        """
        Detect the type of target.
        
        Args:
            target: Target string
        
        Returns:
            Target type (domain, ip, url, cidr)
        """
        import re
        
        # URL
        if target.startswith(("http://", "https://")):
            return "url"
        
        # CIDR
        if "/" in target and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", target):
            return "cidr"
        
        # IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            return "ip"
        
        # Domain
        return "domain"
    
    def _format_available_tools(self) -> str:
        """
        Format available tools for the prompt.
        
        Returns:
            Formatted string of available tools
        """
        if not self.available_tools:
            return "All tools available"
        
        lines = []
        for tool in self.available_tools:
            status = "AVAILABLE" if tool.is_available else "NOT INSTALLED"
            lines.append(f"- {tool.name}: {tool.description} [{status}]")
        
        return "\n".join(lines)
    
    def set_available_tools(self, tools: list[ToolInfo]) -> None:
        """
        Update the list of available tools.
        
        Args:
            tools: List of available tool information
        """
        self.available_tools = tools
    
    def set_safe_mode(self, enabled: bool) -> None:
        """
        Enable or disable safe mode.
        
        Args:
            enabled: Whether safe mode is enabled
        """
        self.safe_mode = enabled
    
    def set_stealth_mode(self, enabled: bool) -> None:
        """
        Enable or disable stealth mode.
        
        Args:
            enabled: Whether stealth mode is enabled
        """
        self.stealth_mode = enabled

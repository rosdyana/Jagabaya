"""
Base agent class.

All AI agents inherit from this base class which provides common
functionality for LLM interaction and state management.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from jagabaya.llm.client import LLMClient
from jagabaya.models.config import LLMConfig
from jagabaya.models.session import SessionState

T = TypeVar("T", bound=BaseModel)


class BaseAgent(ABC, Generic[T]):
    """
    Base class for all AI agents in Jagabaya.
    
    Agents are responsible for specific aspects of the penetration testing
    workflow:
    - PlannerAgent: Strategic decision-making
    - ExecutorAgent: Tool selection and configuration
    - AnalystAgent: Result analysis and finding extraction
    - ReporterAgent: Report generation
    
    Example:
        >>> class MyAgent(BaseAgent[MyOutput]):
        ...     async def run(self, state, **kwargs) -> MyOutput:
        ...         return await self._complete_structured(messages, MyOutput)
    """
    
    # Agent metadata (set by subclasses)
    name: str = "base"
    description: str = "Base agent"
    
    def __init__(
        self,
        config: LLMConfig,
        verbose: bool = False,
    ):
        """
        Initialize the agent.
        
        Args:
            config: LLM configuration
            verbose: Enable verbose output
        """
        self.config = config
        self.verbose = verbose
        self.client = LLMClient(config)
        
        # Tracking
        self.call_count = 0
        self.total_tokens = 0
    
    @property
    def system_prompt(self) -> str:
        """
        Get the system prompt for this agent.
        
        Override in subclasses to provide agent-specific prompts.
        """
        return "You are a helpful AI assistant."
    
    @abstractmethod
    async def run(self, state: SessionState, **kwargs: Any) -> T:
        """
        Run the agent with the current session state.
        
        Args:
            state: Current session state
            **kwargs: Additional arguments
        
        Returns:
            Agent-specific output type
        """
        pass
    
    async def _complete(
        self,
        user_message: str,
        system_message: str | None = None,
        **kwargs: Any,
    ) -> str:
        """
        Get a text completion from the LLM.
        
        Args:
            user_message: User message content
            system_message: Optional system message override
            **kwargs: Additional completion arguments
        
        Returns:
            Generated text response
        """
        messages = [
            {"role": "system", "content": system_message or self.system_prompt},
            {"role": "user", "content": user_message},
        ]
        
        response = await self.client.complete(messages, **kwargs)
        
        self.call_count += 1
        self.total_tokens = self.client.total_tokens
        
        return response
    
    async def _complete_structured(
        self,
        user_message: str,
        response_model: type[T],
        system_message: str | None = None,
        **kwargs: Any,
    ) -> T:
        """
        Get a structured completion matching a Pydantic model.
        
        Args:
            user_message: User message content
            response_model: Pydantic model class for the response
            system_message: Optional system message override
            **kwargs: Additional completion arguments
        
        Returns:
            Instance of the response model
        """
        messages = [
            {"role": "system", "content": system_message or self.system_prompt},
            {"role": "user", "content": user_message},
        ]
        
        response = await self.client.complete_structured(
            messages, response_model, **kwargs
        )
        
        self.call_count += 1
        self.total_tokens = self.client.total_tokens
        
        return response
    
    async def _complete_json(
        self,
        user_message: str,
        system_message: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Get a JSON completion from the LLM.
        
        Args:
            user_message: User message content
            system_message: Optional system message override
            **kwargs: Additional completion arguments
        
        Returns:
            Parsed JSON dictionary
        """
        messages = [
            {"role": "system", "content": system_message or self.system_prompt},
            {"role": "user", "content": user_message},
        ]
        
        response = await self.client.complete_json(messages, **kwargs)
        
        self.call_count += 1
        self.total_tokens = self.client.total_tokens
        
        return response
    
    def get_stats(self) -> dict[str, Any]:
        """
        Get agent statistics.
        
        Returns:
            Dictionary with call count and token usage
        """
        return {
            "agent": self.name,
            "call_count": self.call_count,
            "total_tokens": self.total_tokens,
            "usage": self.client.get_usage_stats(),
        }
    
    def reset_stats(self) -> None:
        """Reset agent statistics."""
        self.call_count = 0
        self.total_tokens = 0
        self.client.reset_usage()
    
    def log(self, message: str, level: str = "info") -> None:
        """
        Log a message if verbose mode is enabled.
        
        Args:
            message: Message to log
            level: Log level (info, debug, warning, error)
        """
        if self.verbose:
            prefix = f"[{self.name.upper()}]"
            print(f"{prefix} {message}")
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model={self.config.model})"

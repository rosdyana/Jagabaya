"""
LiteLLM client wrapper for multi-provider LLM support.

Supports 100+ LLM providers including:
- OpenAI (GPT-4, GPT-4o, GPT-3.5)
- Anthropic (Claude 3.5 Sonnet, Claude 3 Opus)
- Google (Gemini Pro, Gemini Ultra)
- Azure OpenAI
- AWS Bedrock
- Ollama (local models)
- Groq, Together AI, Mistral, and many more
"""

from __future__ import annotations

import json
import os
from typing import Any, AsyncIterator, Type, TypeVar

import litellm
from pydantic import BaseModel
from tenacity import retry, stop_after_attempt, wait_exponential

from jagabaya.models.config import LLMConfig

# Suppress LiteLLM's verbose logging
litellm.suppress_debug_info = True

T = TypeVar("T", bound=BaseModel)


class LLMClient:
    """
    Multi-provider LLM client using LiteLLM.
    
    This client provides a unified interface to interact with 100+ LLM providers
    while tracking token usage and costs.
    
    Example:
        >>> config = LLMConfig(provider="openai", model="gpt-4o")
        >>> client = LLMClient(config)
        >>> response = await client.complete([{"role": "user", "content": "Hello!"}])
        >>> print(response)
        "Hello! How can I help you today?"
    """
    
    def __init__(self, config: LLMConfig):
        """
        Initialize the LLM client.
        
        Args:
            config: LLM configuration including provider, model, and settings
        """
        self.config = config
        self.model_string = config.get_model_string()
        
        # Token and cost tracking
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_tokens = 0
        self.total_cost = 0.0
        
        # Set up API keys from environment if not in config
        self._setup_api_keys()
    
    def _setup_api_keys(self) -> None:
        """Set up API keys from config or environment variables."""
        if self.config.api_key:
            # Map provider to environment variable
            env_map = {
                "openai": "OPENAI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
                "google": "GOOGLE_API_KEY",
                "groq": "GROQ_API_KEY",
                "together": "TOGETHER_API_KEY",
                "mistral": "MISTRAL_API_KEY",
                "deepseek": "DEEPSEEK_API_KEY",
            }
            env_var = env_map.get(self.config.provider)
            if env_var:
                os.environ[env_var] = self.config.api_key
        
        # Handle Azure-specific configuration
        if self.config.provider == "azure":
            if self.config.api_base:
                os.environ["AZURE_API_BASE"] = self.config.api_base
            if self.config.api_version:
                os.environ["AZURE_API_VERSION"] = self.config.api_version
    
    def _track_usage(self, response: Any) -> None:
        """Track token usage and cost from response."""
        if hasattr(response, "usage") and response.usage:
            usage = response.usage
            prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
            completion_tokens = getattr(usage, "completion_tokens", 0) or 0
            
            self.total_prompt_tokens += prompt_tokens
            self.total_completion_tokens += completion_tokens
            self.total_tokens += prompt_tokens + completion_tokens
            
            # Calculate cost using LiteLLM's cost tracking
            try:
                cost = litellm.completion_cost(completion_response=response)
                self.total_cost += cost
            except Exception:
                # Cost calculation not available for all models
                pass
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def complete(
        self,
        messages: list[dict[str, str]],
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> str:
        """
        Generate a completion from the LLM.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            temperature: Override default temperature
            max_tokens: Override default max tokens
            **kwargs: Additional arguments passed to LiteLLM
        
        Returns:
            The generated text response
        
        Example:
            >>> response = await client.complete([
            ...     {"role": "system", "content": "You are a security expert."},
            ...     {"role": "user", "content": "What is SQL injection?"}
            ... ])
        """
        response = await litellm.acompletion(
            model=self.model_string,
            messages=messages,
            temperature=temperature or self.config.temperature,
            max_tokens=max_tokens or self.config.max_tokens,
            timeout=self.config.timeout,
            **kwargs,
        )
        
        self._track_usage(response)
        
        return response.choices[0].message.content or ""
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def complete_json(
        self,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Generate a JSON response from the LLM.
        
        Args:
            messages: List of message dicts
            **kwargs: Additional arguments
        
        Returns:
            Parsed JSON dictionary
        """
        # Add JSON instruction to system message if not present
        has_json_instruction = any(
            "json" in msg.get("content", "").lower()
            for msg in messages
            if msg.get("role") == "system"
        )
        
        if not has_json_instruction:
            messages = [
                {"role": "system", "content": "You must respond with valid JSON only. No other text."},
                *messages,
            ]
        
        response = await litellm.acompletion(
            model=self.model_string,
            messages=messages,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            response_format={"type": "json_object"},
            timeout=self.config.timeout,
            **kwargs,
        )
        
        self._track_usage(response)
        
        content = response.choices[0].message.content or "{}"
        
        # Parse JSON, handling potential issues
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON from the response
            import re
            json_match = re.search(r"\{.*\}", content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            raise ValueError(f"Failed to parse JSON from response: {content[:200]}")
    
    async def complete_structured(
        self,
        messages: list[dict[str, str]],
        response_model: Type[T],
        **kwargs: Any,
    ) -> T:
        """
        Generate a structured response matching a Pydantic model.
        
        Args:
            messages: List of message dicts
            response_model: Pydantic model class for the response
            **kwargs: Additional arguments
        
        Returns:
            Instance of the response model
        
        Example:
            >>> class Analysis(BaseModel):
            ...     severity: str
            ...     description: str
            >>> result = await client.complete_structured(messages, Analysis)
            >>> print(result.severity)
            "high"
        """
        # Add schema information to the prompt
        schema = response_model.model_json_schema()
        schema_str = json.dumps(schema, indent=2)
        
        enhanced_messages = [
            {
                "role": "system",
                "content": f"""You must respond with valid JSON that matches this schema:

{schema_str}

Respond with ONLY the JSON object, no other text."""
            },
            *messages,
        ]
        
        json_response = await self.complete_json(enhanced_messages, **kwargs)
        
        return response_model.model_validate(json_response)
    
    async def stream(
        self,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """
        Stream a completion from the LLM.
        
        Args:
            messages: List of message dicts
            **kwargs: Additional arguments
        
        Yields:
            Text chunks as they are generated
        
        Example:
            >>> async for chunk in client.stream(messages):
            ...     print(chunk, end="", flush=True)
        """
        response = await litellm.acompletion(
            model=self.model_string,
            messages=messages,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            stream=True,
            timeout=self.config.timeout,
            **kwargs,
        )
        
        async for chunk in response:
            if chunk.choices and chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content
    
    def get_usage_stats(self) -> dict[str, Any]:
        """
        Get current usage statistics.
        
        Returns:
            Dictionary with token counts and cost
        """
        return {
            "prompt_tokens": self.total_prompt_tokens,
            "completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost, 6),
            "model": self.model_string,
        }
    
    def reset_usage(self) -> None:
        """Reset usage tracking counters."""
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_tokens = 0
        self.total_cost = 0.0
    
    @staticmethod
    def list_models(provider: str | None = None) -> list[str]:
        """
        List available models for a provider.
        
        Args:
            provider: Optional provider to filter by
        
        Returns:
            List of model names
        """
        try:
            models = litellm.model_list
            if provider:
                return [m for m in models if m.startswith(f"{provider}/")]
            return models
        except Exception:
            return []
    
    @staticmethod
    def get_model_info(model: str) -> dict[str, Any]:
        """
        Get information about a specific model.
        
        Args:
            model: Model name
        
        Returns:
            Model information dict
        """
        try:
            return litellm.get_model_info(model)
        except Exception:
            return {}

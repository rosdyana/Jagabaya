"""
Configuration models for Jagabaya.

Supports configuration via YAML file, environment variables, or programmatic setup.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMConfig(BaseModel):
    """LLM provider configuration.
    
    Supports 100+ providers via LiteLLM including:
    - openai: GPT-4o, GPT-4, GPT-3.5
    - anthropic: Claude 3.5 Sonnet, Claude 3 Opus
    - google: Gemini Pro, Gemini Ultra
    - azure: Azure OpenAI deployments
    - bedrock: AWS Bedrock models
    - ollama: Local models (llama3, mistral, etc.)
    - groq: Fast inference (llama, mixtral)
    - together: Together AI models
    - mistral: Mistral AI models
    - And many more...
    """
    
    provider: str = Field(
        default="openai",
        description="LLM provider (openai, anthropic, google, azure, ollama, groq, etc.)"
    )
    model: str = Field(
        default="gpt-4o",
        description="Model name for the provider"
    )
    temperature: float = Field(
        default=0.2,
        ge=0.0,
        le=2.0,
        description="Sampling temperature (0.0-2.0)"
    )
    max_tokens: int = Field(
        default=4096,
        ge=1,
        le=128000,
        description="Maximum tokens in response"
    )
    api_key: str | None = Field(
        default=None,
        description="API key (falls back to environment variable)"
    )
    api_base: str | None = Field(
        default=None,
        description="Custom API base URL (for Azure, Ollama, etc.)"
    )
    api_version: str | None = Field(
        default=None,
        description="API version (for Azure)"
    )
    timeout: int = Field(
        default=120,
        ge=1,
        description="Request timeout in seconds"
    )
    
    def get_model_string(self) -> str:
        """Get the full model string for LiteLLM."""
        # LiteLLM uses provider/model format for some providers
        if self.provider in ("openai", "anthropic", "google", "groq", "together", "mistral"):
            return f"{self.provider}/{self.model}"
        elif self.provider == "azure":
            return f"azure/{self.model}"
        elif self.provider == "ollama":
            return f"ollama/{self.model}"
        elif self.provider == "bedrock":
            return f"bedrock/{self.model}"
        else:
            # For custom or less common providers
            return f"{self.provider}/{self.model}"


class ScanConfig(BaseModel):
    """Scan execution configuration."""
    
    safe_mode: bool = Field(
        default=True,
        description="Prevent destructive or aggressive actions"
    )
    require_confirmation: bool = Field(
        default=True,
        description="Require user confirmation before tool execution"
    )
    max_parallel_tools: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum tools to run in parallel"
    )
    tool_timeout: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Default tool execution timeout in seconds"
    )
    max_steps: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Maximum steps in autonomous mode"
    )
    retry_failed_tools: bool = Field(
        default=True,
        description="Retry failed tool executions"
    )
    max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Maximum retries for failed tools"
    )


class ScopeConfig(BaseModel):
    """Target scope and safety configuration."""
    
    blacklist: list[str] = Field(
        default_factory=lambda: [
            "127.0.0.0/8",      # Localhost
            "10.0.0.0/8",       # Private Class A
            "172.16.0.0/12",    # Private Class B
            "192.168.0.0/16",   # Private Class C
            "169.254.0.0/16",   # Link-local
            "224.0.0.0/4",      # Multicast
            "240.0.0.0/4",      # Reserved
        ],
        description="IP ranges/domains to never scan"
    )
    whitelist: list[str] = Field(
        default_factory=list,
        description="Explicitly allowed targets (overrides blacklist)"
    )
    allowed_ports: list[int] | None = Field(
        default=None,
        description="Specific ports to scan (None = all common ports)"
    )
    excluded_ports: list[int] = Field(
        default_factory=list,
        description="Ports to exclude from scanning"
    )


class OutputConfig(BaseModel):
    """Output and reporting configuration."""
    
    directory: str = Field(
        default="./reports",
        description="Directory for output files"
    )
    formats: list[Literal["markdown", "html", "json"]] = Field(
        default_factory=lambda: ["markdown", "html"],
        description="Report formats to generate"
    )
    include_evidence: bool = Field(
        default=True,
        description="Include raw evidence in reports"
    )
    include_ai_reasoning: bool = Field(
        default=True,
        description="Include AI decision reasoning in reports"
    )
    session_retention_days: int = Field(
        default=30,
        ge=1,
        description="Days to retain session data"
    )


class LoggingConfig(BaseModel):
    """Logging configuration."""
    
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Log level"
    )
    file: str | None = Field(
        default=None,
        description="Log file path (None = console only)"
    )
    json_format: bool = Field(
        default=False,
        description="Use JSON format for logs"
    )


class JagabayaConfig(BaseSettings):
    """
    Main Jagabaya configuration.
    
    Configuration can be loaded from:
    1. YAML file (jagabaya.yaml or config.yaml)
    2. Environment variables (JAGABAYA_* prefix)
    3. Programmatic setup
    """
    
    model_config = SettingsConfigDict(
        env_prefix="JAGABAYA_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )
    
    llm: LLMConfig = Field(default_factory=LLMConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "JagabayaConfig":
        """
        Load configuration from file and environment.
        
        Priority (highest to lowest):
        1. Environment variables
        2. Specified config file
        3. Default config files (jagabaya.yaml, config.yaml)
        4. Default values
        """
        config_data: dict = {}
        
        # Try to load from file
        if config_path:
            config_file = Path(config_path)
            if config_file.exists():
                config_data = cls._load_yaml(config_file)
        else:
            # Try default locations
            for filename in ["jagabaya.yaml", "config.yaml", "jagabaya.yml", "config.yml"]:
                config_file = Path(filename)
                if config_file.exists():
                    config_data = cls._load_yaml(config_file)
                    break
        
        # Create config with file data as defaults, env vars override
        return cls(**config_data)
    
    @staticmethod
    def _load_yaml(path: Path) -> dict:
        """Load YAML configuration file."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data if data else {}
    
    def save(self, path: str | Path) -> None:
        """Save configuration to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(
                self.model_dump(exclude_none=True),
                f,
                default_flow_style=False,
                sort_keys=False,
            )
    
    def get_output_dir(self) -> Path:
        """Get the output directory, creating it if necessary."""
        output_dir = Path(self.output.directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir


# Supported LLM providers for documentation and validation
SUPPORTED_PROVIDERS = {
    "openai": {
        "name": "OpenAI",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"],
        "env_key": "OPENAI_API_KEY",
    },
    "anthropic": {
        "name": "Anthropic",
        "models": ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"],
        "env_key": "ANTHROPIC_API_KEY",
    },
    "google": {
        "name": "Google AI",
        "models": ["gemini-pro", "gemini-1.5-pro", "gemini-1.5-flash"],
        "env_key": "GOOGLE_API_KEY",
    },
    "azure": {
        "name": "Azure OpenAI",
        "models": ["gpt-4", "gpt-4o", "gpt-35-turbo"],
        "env_key": "AZURE_API_KEY",
    },
    "ollama": {
        "name": "Ollama (Local)",
        "models": ["llama3", "llama3.1", "mistral", "codellama", "mixtral"],
        "env_key": None,
    },
    "groq": {
        "name": "Groq",
        "models": ["llama-3.1-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
        "env_key": "GROQ_API_KEY",
    },
    "together": {
        "name": "Together AI",
        "models": ["meta-llama/Llama-3-70b-chat-hf", "mistralai/Mixtral-8x7B-Instruct-v0.1"],
        "env_key": "TOGETHER_API_KEY",
    },
    "mistral": {
        "name": "Mistral AI",
        "models": ["mistral-large-latest", "mistral-medium-latest", "mistral-small-latest"],
        "env_key": "MISTRAL_API_KEY",
    },
    "bedrock": {
        "name": "AWS Bedrock",
        "models": ["anthropic.claude-3-sonnet", "anthropic.claude-3-haiku", "meta.llama3-70b-instruct"],
        "env_key": None,  # Uses AWS credentials
    },
    "deepseek": {
        "name": "DeepSeek",
        "models": ["deepseek-chat", "deepseek-coder"],
        "env_key": "DEEPSEEK_API_KEY",
    },
}

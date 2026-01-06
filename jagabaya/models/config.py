"""
Configuration models for Jagabaya.

Supports configuration via YAML file, environment variables, or programmatic setup.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Provider to environment variable mapping
PROVIDER_ENV_KEYS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
    "azure": "AZURE_API_KEY",
    "groq": "GROQ_API_KEY",
    "together": "TOGETHER_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "cohere": "COHERE_API_KEY",
    "huggingface": "HUGGINGFACE_API_KEY",
    "replicate": "REPLICATE_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    # Ollama and Bedrock don't require API keys (local or AWS credentials)
    "ollama": None,
    "bedrock": None,
}

# Provider to API base environment variable mapping
PROVIDER_BASE_KEYS = {
    "azure": "AZURE_API_BASE",
    "ollama": "OLLAMA_API_BASE",
}

# Provider to API version environment variable mapping
PROVIDER_VERSION_KEYS = {
    "azure": "AZURE_API_VERSION",
}


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
        description="LLM provider (openai, anthropic, google, azure, ollama, groq, etc.)",
    )
    model: str = Field(default="gpt-4o", description="Model name for the provider")
    temperature: float = Field(
        default=0.2, ge=0.0, le=2.0, description="Sampling temperature (0.0-2.0)"
    )
    max_tokens: int = Field(default=4096, ge=1, le=128000, description="Maximum tokens in response")
    api_key: str | None = Field(
        default=None, description="API key (falls back to environment variable)"
    )
    api_base: str | None = Field(
        default=None, description="Custom API base URL (for Azure, Ollama, etc.)"
    )
    api_version: str | None = Field(default=None, description="API version (for Azure)")
    timeout: int = Field(default=120, ge=1, description="Request timeout in seconds")

    @model_validator(mode="after")
    def resolve_from_environment(self) -> "LLMConfig":
        """Resolve API key, base URL, and version from environment if not set."""
        # Resolve API key from provider-specific env var
        if self.api_key is None:
            env_key = PROVIDER_ENV_KEYS.get(self.provider)
            if env_key:
                self.api_key = os.environ.get(env_key)

        # Resolve API base from provider-specific env var
        if self.api_base is None:
            base_key = PROVIDER_BASE_KEYS.get(self.provider)
            if base_key:
                self.api_base = os.environ.get(base_key)

        # Resolve API version from provider-specific env var
        if self.api_version is None:
            version_key = PROVIDER_VERSION_KEYS.get(self.provider)
            if version_key:
                self.api_version = os.environ.get(version_key)

        return self

    def get_api_key(self) -> str | None:
        """Get the API key, resolving from environment if needed.

        Returns:
            The API key or None if not configured and not required.
        """
        if self.api_key:
            return self.api_key

        # Try to get from environment based on provider
        env_key = PROVIDER_ENV_KEYS.get(self.provider)
        if env_key:
            return os.environ.get(env_key)

        return None

    def get_api_base(self) -> str | None:
        """Get the API base URL, resolving from environment if needed."""
        if self.api_base:
            return self.api_base

        base_key = PROVIDER_BASE_KEYS.get(self.provider)
        if base_key:
            return os.environ.get(base_key)

        return None

    def get_api_version(self) -> str | None:
        """Get the API version, resolving from environment if needed."""
        if self.api_version:
            return self.api_version

        version_key = PROVIDER_VERSION_KEYS.get(self.provider)
        if version_key:
            return os.environ.get(version_key)

        return None

    def get_model_string(self) -> str:
        """Get the full model string for LiteLLM."""
        # LiteLLM uses provider/model format for some providers
        # For Google, LiteLLM expects "gemini/model-name" format
        if self.provider == "google":
            return f"gemini/{self.model}"
        elif self.provider in ("openai", "anthropic", "groq", "together", "mistral"):
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

    def is_configured(self) -> bool:
        """Check if this LLM config has required credentials.

        Returns:
            True if the provider is properly configured.
        """
        # Providers that don't require API keys
        if self.provider in ("ollama", "bedrock"):
            return True

        return self.get_api_key() is not None


class ScanConfig(BaseModel):
    """Scan execution configuration."""

    safe_mode: bool = Field(default=True, description="Prevent destructive or aggressive actions")
    stealth_mode: bool = Field(
        default=False, description="Enable stealth mode (slower, less detectable)"
    )
    require_confirmation: bool = Field(
        default=True, description="Require user confirmation before tool execution"
    )
    max_parallel_tools: int = Field(
        default=3, ge=1, le=10, description="Maximum tools to run in parallel"
    )
    tool_timeout: int = Field(
        default=300, ge=30, le=3600, description="Default tool execution timeout in seconds"
    )
    max_steps: int = Field(default=50, ge=1, le=200, description="Maximum steps in autonomous mode")
    retry_failed_tools: bool = Field(default=True, description="Retry failed tool executions")
    max_retries: int = Field(default=2, ge=0, le=5, description="Maximum retries for failed tools")
    rate_limit: int = Field(
        default=10, ge=1, le=100, description="Rate limit for requests per second"
    )


class ScopeConfig(BaseModel):
    """Target scope and safety configuration."""

    blacklist: list[str] = Field(
        default_factory=lambda: [
            "127.0.0.0/8",  # Localhost
            "10.0.0.0/8",  # Private Class A
            "172.16.0.0/12",  # Private Class B
            "192.168.0.0/16",  # Private Class C
            "169.254.0.0/16",  # Link-local
            "224.0.0.0/4",  # Multicast
            "240.0.0.0/4",  # Reserved
        ],
        description="IP ranges/domains to never scan",
    )
    whitelist: list[str] = Field(
        default_factory=list, description="Explicitly allowed targets (overrides blacklist)"
    )
    allowed_ports: list[int] | None = Field(
        default=None, description="Specific ports to scan (None = all common ports)"
    )
    excluded_ports: list[int] = Field(
        default_factory=list, description="Ports to exclude from scanning"
    )


class OutputConfig(BaseModel):
    """Output and reporting configuration."""

    directory: str = Field(default="./reports", description="Directory for output files")
    formats: list[Literal["markdown", "html", "json"]] = Field(
        default_factory=lambda: ["markdown", "html"], description="Report formats to generate"
    )
    report_format: Literal["markdown", "html", "json"] = Field(
        default="markdown", description="Default report format"
    )
    include_evidence: bool = Field(default=True, description="Include raw evidence in reports")
    include_ai_reasoning: bool = Field(
        default=True, description="Include AI decision reasoning in reports"
    )
    session_retention_days: int = Field(default=30, ge=1, description="Days to retain session data")
    save_raw_output: bool = Field(default=True, description="Save raw tool output")

    @property
    def output_dir(self) -> str:
        """Alias for directory for backwards compatibility."""
        return self.directory


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", description="Log level"
    )
    file: str | None = Field(default=None, description="Log file path (None = console only)")
    json_format: bool = Field(default=False, description="Use JSON format for logs")


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

        Environment variables are loaded from .env file if present.

        Supported environment variables:
        - JAGABAYA_LLM__PROVIDER: LLM provider (openai, anthropic, google, azure, etc.)
        - JAGABAYA_LLM__MODEL: Model name
        - JAGABAYA_LLM__TEMPERATURE: Temperature (0.0-2.0)
        - JAGABAYA_LLM__MAX_TOKENS: Max tokens
        - JAGABAYA_LLM__API_KEY: API key (or use provider-specific: OPENAI_API_KEY, etc.)
        - JAGABAYA_LLM__API_BASE: API base URL
        - JAGABAYA_LLM__API_VERSION: API version (for Azure)
        - JAGABAYA_SCAN__SAFE_MODE: Enable safe mode (true/false)
        - JAGABAYA_SCAN__TOOL_TIMEOUT: Tool timeout in seconds
        - JAGABAYA_OUTPUT__DIRECTORY: Output directory
        """
        # Load .env file if it exists (doesn't override existing env vars)
        # Try multiple locations: current dir, home dir
        env_locations = [
            Path(".env"),
            Path.home() / ".jagabaya" / ".env",
            Path.home() / ".config" / "jagabaya" / ".env",
        ]

        for env_path in env_locations:
            if env_path.exists():
                load_dotenv(env_path)
                break
        else:
            # Try default load_dotenv which searches current and parent dirs
            load_dotenv()

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

        # Parse environment variables for nested config
        config_data = cls._apply_env_overrides(config_data)

        # Create config with file data as defaults, env vars override
        return cls(**config_data)

    @classmethod
    def _apply_env_overrides(cls, config_data: dict) -> dict:
        """Apply environment variable overrides to config data.

        Parses JAGABAYA_* environment variables and applies them to the config.

        Supports multiple formats:
        - Nested with __: JAGABAYA_LLM__PROVIDER=google
        - Nested with _: JAGABAYA_LLM_PROVIDER=google
        - Flat shortcuts: JAGABAYA_SAFE_MODE=true -> scan.safe_mode
        """
        prefix = "JAGABAYA_"

        # Mapping of flat env var names to their nested config paths
        flat_mappings = {
            "safe_mode": ["scan", "safe_mode"],
            "require_confirmation": ["scan", "require_confirmation"],
            "output_dir": ["output", "directory"],
            "log_level": ["logging", "level"],
        }

        for key, value in os.environ.items():
            if not key.startswith(prefix):
                continue

            # Remove prefix
            suffix = key[len(prefix) :].lower()

            if not suffix:
                continue

            # Convert value to appropriate type
            typed_value = cls._parse_env_value(value)

            # Check if it's a flat mapping first
            if suffix in flat_mappings:
                key_path = flat_mappings[suffix]
            # Check for __ delimiter (explicit nested)
            elif "__" in suffix:
                key_path = suffix.split("__")
            # Check for known section prefixes with single _ (e.g., llm_provider)
            elif suffix.startswith(("llm_", "scan_", "scope_", "output_", "logging_")):
                # Split at first underscore only for section name
                parts = suffix.split("_", 1)
                if len(parts) == 2:
                    key_path = parts
                else:
                    continue
            else:
                # Unknown format, skip
                continue

            # Apply to config_data
            current = config_data
            for part in key_path[:-1]:
                if part not in current:
                    current[part] = {}
                elif not isinstance(current[part], dict):
                    current[part] = {}
                current = current[part]

            # Set the final value
            current[key_path[-1]] = typed_value

        return config_data

    @staticmethod
    def _parse_env_value(value: str):
        """Parse environment variable value to appropriate Python type."""
        # Boolean
        if value.lower() in ("true", "yes", "1", "on"):
            return True
        if value.lower() in ("false", "no", "0", "off"):
            return False

        # Integer
        try:
            return int(value)
        except ValueError:
            pass

        # Float
        try:
            return float(value)
        except ValueError:
            pass

        # String
        return value

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
        "models": [
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229",
            "claude-3-haiku-20240307",
        ],
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
        "models": [
            "anthropic.claude-3-sonnet",
            "anthropic.claude-3-haiku",
            "meta.llama3-70b-instruct",
        ],
        "env_key": None,  # Uses AWS credentials
    },
    "deepseek": {
        "name": "DeepSeek",
        "models": ["deepseek-chat", "deepseek-coder"],
        "env_key": "DEEPSEEK_API_KEY",
    },
}

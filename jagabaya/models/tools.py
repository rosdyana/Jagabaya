"""
Tool execution models.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ToolCategory(str, Enum):
    """Categories of security tools."""
    
    NETWORK = "network"
    WEB_RECON = "web_recon"
    SUBDOMAIN = "subdomain"
    VULNERABILITY = "vulnerability"
    SSL_TLS = "ssl_tls"
    CONTENT_DISCOVERY = "content_discovery"
    PARAMETER_DISCOVERY = "parameter_discovery"
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    SECRET_SCANNING = "secret_scanning"
    CMS = "cms"
    DNS = "dns"
    FUZZING = "fuzzing"
    OTHER = "other"


class ToolInfo(BaseModel):
    """Information about a security tool."""
    
    name: str = Field(description="Tool name")
    description: str = Field(description="Brief description")
    category: ToolCategory = Field(description="Tool category")
    binary: str = Field(description="Binary/command name")
    is_available: bool = Field(default=False, description="Whether tool is installed")
    version: str | None = Field(default=None, description="Installed version")
    homepage: str | None = Field(default=None, description="Tool homepage URL")
    install_command: str | None = Field(default=None, description="Installation command")


class ToolResult(BaseModel):
    """Result from a tool execution."""
    
    success: bool = Field(description="Whether execution succeeded")
    tool: str = Field(description="Tool name")
    command: str = Field(description="Full command executed")
    target: str = Field(description="Target scanned")
    
    # Output
    raw_output: str = Field(default="", description="Raw stdout output")
    error_output: str = Field(default="", description="Raw stderr output")
    parsed: dict[str, Any] = Field(default_factory=dict, description="Parsed/structured output")
    
    # Execution details
    exit_code: int = Field(default=0, description="Process exit code")
    duration: float = Field(default=0.0, description="Execution duration in seconds")
    timestamp: datetime = Field(default_factory=datetime.now)
    
    # Error information
    error_message: str | None = Field(default=None, description="Error message if failed")
    timed_out: bool = Field(default=False, description="Whether execution timed out")
    
    def get_summary(self) -> str:
        """Get a brief summary of the result."""
        status = "SUCCESS" if self.success else "FAILED"
        return f"[{status}] {self.tool} on {self.target} ({self.duration:.1f}s)"


class ToolExecution(BaseModel):
    """Record of a tool execution for session history."""
    
    id: str = Field(description="Unique execution ID")
    tool: str = Field(description="Tool name")
    command: str = Field(description="Full command")
    target: str = Field(description="Target")
    
    # Timing
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: datetime | None = Field(default=None)
    duration: float = Field(default=0.0)
    
    # Results
    success: bool = Field(default=False)
    exit_code: int = Field(default=0)
    output_summary: str = Field(default="")
    findings_count: int = Field(default=0)
    
    # Parameters
    parameters: dict[str, Any] = Field(default_factory=dict)
    
    def complete(self, result: ToolResult, findings_count: int = 0) -> None:
        """Mark execution as complete with result."""
        self.completed_at = datetime.now()
        self.duration = result.duration
        self.success = result.success
        self.exit_code = result.exit_code
        self.output_summary = result.raw_output[:500] if result.raw_output else ""
        self.findings_count = findings_count


class ToolParameters(BaseModel):
    """Common parameters for tool execution."""
    
    # Targeting
    target: str = Field(description="Target to scan")
    ports: str | None = Field(default=None, description="Port specification")
    
    # Timing
    timeout: int = Field(default=300, description="Timeout in seconds")
    rate_limit: int | None = Field(default=None, description="Rate limit")
    
    # Output
    output_format: str | None = Field(default=None, description="Preferred output format")
    
    # Behavior
    aggressive: bool = Field(default=False, description="Use aggressive mode")
    stealth: bool = Field(default=False, description="Use stealth mode")
    
    # Extra
    extra_args: list[str] = Field(default_factory=list, description="Additional arguments")
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in self.model_dump().items() if v is not None}

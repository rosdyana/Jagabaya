"""
Base tool class for security tool wrappers.

All security tools inherit from BaseTool and implement the
build_command and parse_output methods.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import uuid4

from jagabaya.models.tools import ToolCategory, ToolInfo, ToolResult, ToolExecution


class BaseTool(ABC):
    """
    Base class for all security tool wrappers.
    
    Subclasses must implement:
    - build_command(): Build the command-line arguments
    - parse_output(): Parse the raw output into structured data
    
    Example:
        >>> class NmapTool(BaseTool):
        ...     name = "nmap"
        ...     description = "Network port scanner"
        ...     category = ToolCategory.NETWORK
        ...     binary = "nmap"
        ...     
        ...     def build_command(self, target, **kwargs):
        ...         return ["-sV", "-sC", "-oX", "-", target]
        ...     
        ...     def parse_output(self, output):
        ...         # Parse XML output
        ...         return {"ports": [...]}
    """
    
    # Tool metadata (must be set by subclasses)
    name: str
    description: str
    category: ToolCategory
    binary: str
    
    # Optional metadata
    homepage: str | None = None
    install_command: str | None = None
    output_format: str = "text"  # text, json, xml
    
    def __init__(self):
        """Initialize the tool wrapper."""
        self._version: str | None = None
    
    @property
    def is_available(self) -> bool:
        """Check if the tool binary is available in PATH."""
        return shutil.which(self.binary) is not None
    
    @property
    def version(self) -> str | None:
        """Get the installed version of the tool."""
        if self._version is None and self.is_available:
            self._version = self._get_version()
        return self._version
    
    def _get_version(self) -> str | None:
        """
        Get the tool version. Override in subclasses for specific parsing.
        """
        try:
            import subprocess
            result = subprocess.run(
                [self.binary, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Return first line of output
            output = result.stdout or result.stderr
            if output:
                return output.strip().split("\n")[0][:100]
        except Exception:
            pass
        return None
    
    def get_info(self) -> ToolInfo:
        """Get tool information."""
        return ToolInfo(
            name=self.name,
            description=self.description,
            category=self.category,
            binary=self.binary,
            is_available=self.is_available,
            version=self.version,
            homepage=self.homepage,
            install_command=self.install_command,
        )
    
    @abstractmethod
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build the command-line arguments for the tool.
        
        Args:
            target: The target to scan
            **kwargs: Tool-specific parameters
        
        Returns:
            List of command-line arguments (without the binary name)
        
        Example:
            >>> tool.build_command("example.com", ports="80,443")
            ["-sV", "-p", "80,443", "example.com"]
        """
        pass
    
    @abstractmethod
    def parse_output(self, output: str) -> dict[str, Any]:
        """
        Parse the raw output from the tool into structured data.
        
        Args:
            output: Raw stdout from the tool
        
        Returns:
            Parsed data as a dictionary
        
        Example:
            >>> tool.parse_output(xml_output)
            {"ports": [{"port": 80, "service": "http", "state": "open"}]}
        """
        pass
    
    async def execute(
        self,
        target: str,
        timeout: int = 300,
        **kwargs: Any,
    ) -> ToolResult:
        """
        Execute the tool asynchronously.
        
        Args:
            target: Target to scan
            timeout: Execution timeout in seconds
            **kwargs: Tool-specific parameters
        
        Returns:
            ToolResult with execution details and parsed output
        
        Raises:
            asyncio.TimeoutError: If execution exceeds timeout
            FileNotFoundError: If tool binary is not found
        """
        if not self.is_available:
            return ToolResult(
                success=False,
                tool=self.name,
                command=f"{self.binary} (not installed)",
                target=target,
                error_message=f"Tool '{self.binary}' is not installed or not in PATH",
            )
        
        # Build command
        args = self.build_command(target, **kwargs)
        command = [self.binary] + args
        command_str = " ".join(command)
        
        start_time = time.time()
        
        try:
            # Create subprocess
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
            
            duration = time.time() - start_time
            
            # Decode output
            raw_output = stdout.decode("utf-8", errors="replace")
            error_output = stderr.decode("utf-8", errors="replace")
            
            # Parse output
            try:
                parsed = self.parse_output(raw_output)
            except Exception as e:
                parsed = {"parse_error": str(e)}
            
            return ToolResult(
                success=proc.returncode == 0,
                tool=self.name,
                command=command_str,
                target=target,
                raw_output=raw_output,
                error_output=error_output,
                parsed=parsed,
                exit_code=proc.returncode or 0,
                duration=duration,
                timestamp=datetime.now(),
            )
            
        except asyncio.TimeoutError:
            duration = time.time() - start_time
            return ToolResult(
                success=False,
                tool=self.name,
                command=command_str,
                target=target,
                error_message=f"Execution timed out after {timeout} seconds",
                timed_out=True,
                duration=duration,
                timestamp=datetime.now(),
            )
            
        except FileNotFoundError:
            return ToolResult(
                success=False,
                tool=self.name,
                command=command_str,
                target=target,
                error_message=f"Tool binary '{self.binary}' not found",
                timestamp=datetime.now(),
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return ToolResult(
                success=False,
                tool=self.name,
                command=command_str,
                target=target,
                error_message=str(e),
                duration=duration,
                timestamp=datetime.now(),
            )
    
    def create_execution_record(self, target: str, **kwargs: Any) -> ToolExecution:
        """Create an execution record for tracking."""
        args = self.build_command(target, **kwargs) if self.is_available else []
        command = f"{self.binary} {' '.join(args)}" if args else self.binary
        
        return ToolExecution(
            id=uuid4().hex[:12],
            tool=self.name,
            command=command,
            target=target,
            parameters=kwargs,
        )

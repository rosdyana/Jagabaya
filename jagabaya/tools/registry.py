"""
Tool registry for discovering and managing security tools.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from jagabaya.models.tools import ToolCategory, ToolInfo

if TYPE_CHECKING:
    from jagabaya.tools.base import BaseTool


class ToolRegistry:
    """
    Registry for security tools.
    
    The registry maintains a collection of all available tool wrappers
    and provides methods for discovery and lookup.
    
    Example:
        >>> registry = ToolRegistry()
        >>> registry.register(NmapTool())
        >>> tool = registry.get("nmap")
        >>> available = registry.get_available_tools()
    """
    
    def __init__(self):
        """Initialize an empty registry."""
        self._tools: dict[str, BaseTool] = {}
        self._initialized = False
    
    def register(self, tool: BaseTool) -> None:
        """
        Register a tool in the registry.
        
        Args:
            tool: Tool instance to register
        """
        self._tools[tool.name] = tool
    
    def get(self, name: str) -> BaseTool | None:
        """
        Get a tool by name.
        
        Args:
            name: Tool name
        
        Returns:
            Tool instance or None if not found
        """
        self._ensure_initialized()
        return self._tools.get(name)
    
    def get_all(self) -> dict[str, BaseTool]:
        """Get all registered tools."""
        self._ensure_initialized()
        return self._tools.copy()
    
    def get_by_category(self, category: ToolCategory) -> list[BaseTool]:
        """
        Get all tools in a category.
        
        Args:
            category: Tool category
        
        Returns:
            List of tools in the category
        """
        self._ensure_initialized()
        return [t for t in self._tools.values() if t.category == category]
    
    def get_available(self) -> dict[str, BaseTool]:
        """Get all tools that are installed and available."""
        self._ensure_initialized()
        return {n: t for n, t in self._tools.items() if t.is_available}
    
    def get_unavailable(self) -> dict[str, BaseTool]:
        """Get all tools that are not installed."""
        self._ensure_initialized()
        return {n: t for n, t in self._tools.items() if not t.is_available}
    
    def get_tool_info(self) -> list[ToolInfo]:
        """Get information about all registered tools."""
        self._ensure_initialized()
        return [t.get_info() for t in self._tools.values()]
    
    def get_availability_summary(self) -> dict[str, bool]:
        """Get a summary of tool availability."""
        self._ensure_initialized()
        return {n: t.is_available for n, t in self._tools.items()}
    
    def list_names(self) -> list[str]:
        """Get list of all tool names."""
        self._ensure_initialized()
        return list(self._tools.keys())
    
    def _ensure_initialized(self) -> None:
        """Ensure all tools are registered."""
        if not self._initialized:
            self._register_all_tools()
            self._initialized = True
    
    def _register_all_tools(self) -> None:
        """Register all built-in tools."""
        from jagabaya.tools.wrappers.nmap import NmapTool
        from jagabaya.tools.wrappers.masscan import MasscanTool
        from jagabaya.tools.wrappers.httpx import HttpxTool
        from jagabaya.tools.wrappers.subfinder import SubfinderTool
        from jagabaya.tools.wrappers.amass import AmassTool
        from jagabaya.tools.wrappers.nuclei import NucleiTool
        from jagabaya.tools.wrappers.nikto import NiktoTool
        from jagabaya.tools.wrappers.whatweb import WhatWebTool
        from jagabaya.tools.wrappers.wafw00f import Wafw00fTool
        from jagabaya.tools.wrappers.testssl import TestSSLTool
        from jagabaya.tools.wrappers.sslyze import SSLyzeTool
        from jagabaya.tools.wrappers.gobuster import GobusterTool
        from jagabaya.tools.wrappers.ffuf import FfufTool
        from jagabaya.tools.wrappers.feroxbuster import FeroxbusterTool
        from jagabaya.tools.wrappers.sqlmap import SQLMapTool
        from jagabaya.tools.wrappers.wpscan import WPScanTool
        from jagabaya.tools.wrappers.xsstrike import XSStrikeTool
        from jagabaya.tools.wrappers.dalfox import DalfoxTool
        from jagabaya.tools.wrappers.gitleaks import GitleaksTool
        from jagabaya.tools.wrappers.trufflehog import TrufflehogTool
        from jagabaya.tools.wrappers.cmseek import CMSeekTool
        from jagabaya.tools.wrappers.dnsrecon import DnsReconTool
        from jagabaya.tools.wrappers.dnsx import DnsxTool
        from jagabaya.tools.wrappers.arjun import ArjunTool
        
        # Network scanning
        self.register(NmapTool())
        self.register(MasscanTool())
        
        # Web reconnaissance
        self.register(HttpxTool())
        self.register(WhatWebTool())
        self.register(Wafw00fTool())
        
        # Subdomain discovery
        self.register(SubfinderTool())
        self.register(AmassTool())
        
        # Vulnerability scanning
        self.register(NucleiTool())
        self.register(NiktoTool())
        
        # SSL/TLS
        self.register(TestSSLTool())
        self.register(SSLyzeTool())
        
        # Content discovery
        self.register(GobusterTool())
        self.register(FfufTool())
        self.register(FeroxbusterTool())
        
        # SQL Injection
        self.register(SQLMapTool())
        
        # CMS
        self.register(WPScanTool())
        self.register(CMSeekTool())
        
        # XSS
        self.register(XSStrikeTool())
        self.register(DalfoxTool())
        
        # Secret scanning
        self.register(GitleaksTool())
        self.register(TrufflehogTool())
        
        # DNS
        self.register(DnsReconTool())
        self.register(DnsxTool())
        
        # Parameter discovery
        self.register(ArjunTool())


# Global registry instance
_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    """Get the global tool registry instance."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry

"""
Subfinder - Subdomain discovery tool.
"""

from __future__ import annotations

from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory
from jagabaya.tools.parsers.common import parse_json_lines, parse_plain_lines


class SubfinderTool(BaseTool):
    """
    Subfinder wrapper - Fast passive subdomain enumeration tool.
    
    Discovers subdomains using various passive sources like
    certificate transparency, search engines, and APIs.
    
    Example:
        >>> tool = SubfinderTool()
        >>> result = await tool.execute("example.com")
    """
    
    name = "subfinder"
    description = "Fast passive subdomain enumeration tool"
    category = ToolCategory.SUBDOMAIN
    binary = "subfinder"
    homepage = "https://github.com/projectdiscovery/subfinder"
    install_command = "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build subfinder command.
        
        Args:
            target: Target domain
            recursive: Enable recursive subdomain discovery
            all_sources: Use all sources
            sources: Specific sources to use
            exclude_sources: Sources to exclude
            max_time: Maximum time to run (minutes)
            threads: Number of threads
            rate_limit: Rate limit per second
        """
        args = []
        
        # Output format - JSON
        args.extend(["-json", "-silent"])
        
        # Target domain
        args.extend(["-d", target])
        
        # Recursive discovery
        if kwargs.get("recursive"):
            args.append("-recursive")
        
        # Use all sources
        if kwargs.get("all_sources"):
            args.append("-all")
        
        # Specific sources
        sources = kwargs.get("sources")
        if sources:
            if isinstance(sources, list):
                sources = ",".join(sources)
            args.extend(["-sources", sources])
        
        # Exclude sources
        exclude = kwargs.get("exclude_sources")
        if exclude:
            if isinstance(exclude, list):
                exclude = ",".join(exclude)
            args.extend(["-exclude-sources", exclude])
        
        # Max enumeration time
        max_time = kwargs.get("max_time")
        if max_time:
            args.extend(["-max-time", str(max_time)])
        
        # Threads
        threads = kwargs.get("threads")
        if threads:
            args.extend(["-t", str(threads)])
        
        # Rate limit
        rate_limit = kwargs.get("rate_limit")
        if rate_limit:
            args.extend(["-rate-limit", str(rate_limit)])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse subfinder output."""
        result = {
            "subdomains": [],
            "sources": {},
            "total": 0,
        }
        
        # Try JSON format first
        entries = parse_json_lines(output)
        
        if entries:
            for entry in entries:
                subdomain = entry.get("host")
                source = entry.get("source")
                
                if subdomain and subdomain not in result["subdomains"]:
                    result["subdomains"].append(subdomain)
                
                if source:
                    if source not in result["sources"]:
                        result["sources"][source] = []
                    if subdomain not in result["sources"][source]:
                        result["sources"][source].append(subdomain)
        else:
            # Fallback to plain text
            lines = parse_plain_lines(output)
            result["subdomains"] = list(set(lines))
        
        result["total"] = len(result["subdomains"])
        
        return result

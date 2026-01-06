"""
Feroxbuster - Fast content discovery tool.
"""

from __future__ import annotations

from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory
from jagabaya.tools.parsers.common import parse_json_lines


class FeroxbusterTool(BaseTool):
    """
    Feroxbuster wrapper - A fast, simple, recursive content discovery tool.
    
    Written in Rust, feroxbuster is designed to perform forced browsing
    using wordlists and recursion.
    
    Example:
        >>> tool = FeroxbusterTool()
        >>> result = await tool.execute("https://example.com", wordlist="/path/to/wordlist.txt")
    """
    
    name = "feroxbuster"
    description = "Fast content discovery tool written in Rust"
    category = ToolCategory.CONTENT_DISCOVERY
    binary = "feroxbuster"
    homepage = "https://github.com/epi052/feroxbuster"
    install_command = "cargo install feroxbuster"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build feroxbuster command.
        
        Args:
            target: Target URL
            wordlist: Path to wordlist
            extensions: File extensions to search
            status_codes: Status codes to include
            filter_status: Status codes to filter
            threads: Number of threads
            depth: Recursion depth
            timeout: Request timeout
            auto_tune: Enable auto-tuning
            smart: Enable smart mode
            extract_links: Extract links from responses
            collect_words: Collect words from responses
        """
        args = []
        
        # Target URL
        args.extend(["-u", target])
        
        # Wordlist
        wordlist = kwargs.get("wordlist")
        if wordlist:
            args.extend(["-w", wordlist])
        
        # Output format - JSON to stdout
        args.extend(["--json", "-o", "-"])
        
        # Quiet mode
        args.append("-q")
        
        # No recursion status message
        args.append("--no-state")
        
        # Extensions
        extensions = kwargs.get("extensions")
        if extensions:
            if isinstance(extensions, list):
                extensions = ",".join(extensions)
            args.extend(["-x", extensions])
        
        # Status codes to include
        status_codes = kwargs.get("status_codes")
        if status_codes:
            if isinstance(status_codes, list):
                for code in status_codes:
                    args.extend(["-s", str(code)])
            else:
                args.extend(["-s", str(status_codes)])
        
        # Filter status codes
        filter_status = kwargs.get("filter_status")
        if filter_status:
            if isinstance(filter_status, list):
                for code in filter_status:
                    args.extend(["-C", str(code)])
            else:
                args.extend(["-C", str(filter_status)])
        
        # Filter size
        filter_size = kwargs.get("filter_size")
        if filter_size:
            if isinstance(filter_size, list):
                for size in filter_size:
                    args.extend(["-S", str(size)])
            else:
                args.extend(["-S", str(filter_size)])
        
        # Filter words
        filter_words = kwargs.get("filter_words")
        if filter_words:
            if isinstance(filter_words, list):
                for words in filter_words:
                    args.extend(["-W", str(words)])
            else:
                args.extend(["-W", str(filter_words)])
        
        # Threads
        threads = kwargs.get("threads", 50)
        args.extend(["-t", str(threads)])
        
        # Recursion depth
        depth = kwargs.get("depth", 2)
        args.extend(["-d", str(depth)])
        
        # No recursion
        if kwargs.get("no_recursion"):
            args.append("-n")
        
        # Timeout
        timeout = kwargs.get("timeout", 7)
        args.extend(["--timeout", str(timeout)])
        
        # Auto-tune
        if kwargs.get("auto_tune"):
            args.append("--auto-tune")
        
        # Smart mode
        if kwargs.get("smart"):
            args.append("--smart")
        
        # Extract links
        if kwargs.get("extract_links", True):
            args.append("-e")
        
        # Collect words
        if kwargs.get("collect_words"):
            args.append("--collect-words")
        
        # Follow redirects
        if kwargs.get("follow_redirects"):
            args.append("-r")
        
        # Insecure (skip TLS verification)
        if kwargs.get("insecure"):
            args.append("-k")
        
        # Headers
        headers = kwargs.get("headers")
        if headers:
            if isinstance(headers, dict):
                for key, value in headers.items():
                    args.extend(["-H", f"{key}: {value}"])
            elif isinstance(headers, list):
                for header in headers:
                    args.extend(["-H", header])
        
        # User agent
        user_agent = kwargs.get("user_agent")
        if user_agent:
            args.extend(["-a", user_agent])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse feroxbuster JSON output."""
        result = {
            "results": [],
            "by_status": {},
            "statistics": {},
            "total": 0,
        }
        
        entries = parse_json_lines(output)
        
        for entry in entries:
            entry_type = entry.get("type")
            
            if entry_type == "response":
                item = {
                    "url": entry.get("url"),
                    "original_url": entry.get("original_url"),
                    "path": entry.get("path"),
                    "status": entry.get("status"),
                    "content_length": entry.get("content_length"),
                    "line_count": entry.get("line_count"),
                    "word_count": entry.get("word_count"),
                    "redirect_to": entry.get("redirect_to"),
                    "is_directory": entry.get("is_directory"),
                    "wildcard": entry.get("wildcard"),
                }
                result["results"].append(item)
                
                # Group by status
                status = str(entry.get("status", "unknown"))
                if status not in result["by_status"]:
                    result["by_status"][status] = []
                result["by_status"][status].append(item)
            
            elif entry_type == "statistics":
                result["statistics"] = {
                    "requests": entry.get("requests"),
                    "expected_per_scan": entry.get("expected_per_scan"),
                    "total_scans": entry.get("total_scans"),
                    "initial_targets": entry.get("initial_targets"),
                    "links_extracted": entry.get("links_extracted"),
                    "errors": entry.get("errors"),
                    "rate": entry.get("rate"),
                }
        
        result["total"] = len(result["results"])
        
        return result

"""
ffuf - Fast web fuzzer.
"""

from __future__ import annotations

from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory
from jagabaya.tools.parsers.common import parse_json_lines


class FfufTool(BaseTool):
    """
    ffuf wrapper - Fast web fuzzer written in Go.
    
    A fast web fuzzer used for directory discovery, virtual host discovery,
    parameter fuzzing, and more.
    
    Example:
        >>> tool = FfufTool()
        >>> result = await tool.execute("https://example.com/FUZZ", wordlist="/path/to/wordlist.txt")
    """
    
    name = "ffuf"
    description = "Fast web fuzzer for content and parameter discovery"
    category = ToolCategory.CONTENT_DISCOVERY
    binary = "ffuf"
    homepage = "https://github.com/ffuf/ffuf"
    install_command = "go install github.com/ffuf/ffuf/v2@latest"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build ffuf command.
        
        Args:
            target: Target URL with FUZZ keyword
            wordlist: Path to wordlist
            extensions: File extensions to append
            method: HTTP method
            data: POST data
            headers: Custom headers
            filter_status: Status codes to filter out
            match_status: Status codes to match
            filter_size: Response sizes to filter out
            filter_words: Word counts to filter out
            threads: Number of threads
            rate: Requests per second
            timeout: Request timeout
            recursion: Enable recursion
            recursion_depth: Recursion depth
        """
        args = []
        
        # Target URL (must contain FUZZ keyword)
        if "FUZZ" not in target:
            target = target.rstrip("/") + "/FUZZ"
        args.extend(["-u", target])
        
        # Wordlist
        wordlist = kwargs.get("wordlist")
        if wordlist:
            args.extend(["-w", wordlist])
        else:
            import os
            default_wordlists = [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
            ]
            for wl in default_wordlists:
                if os.path.exists(wl):
                    args.extend(["-w", wl])
                    break
        
        # Output format - JSON
        args.extend(["-of", "json", "-o", "-"])
        
        # Silent mode
        args.append("-s")
        
        # Extensions
        extensions = kwargs.get("extensions")
        if extensions:
            if isinstance(extensions, list):
                extensions = ",".join(extensions)
            args.extend(["-e", extensions])
        
        # HTTP method
        method = kwargs.get("method")
        if method:
            args.extend(["-X", method.upper()])
        
        # POST data
        data = kwargs.get("data")
        if data:
            args.extend(["-d", data])
        
        # Headers
        headers = kwargs.get("headers")
        if headers:
            if isinstance(headers, dict):
                for key, value in headers.items():
                    args.extend(["-H", f"{key}: {value}"])
            elif isinstance(headers, list):
                for header in headers:
                    args.extend(["-H", header])
        
        # Cookies
        cookies = kwargs.get("cookies")
        if cookies:
            args.extend(["-b", cookies])
        
        # Match status codes
        match_status = kwargs.get("match_status")
        if match_status:
            if isinstance(match_status, list):
                match_status = ",".join(map(str, match_status))
            args.extend(["-mc", match_status])
        else:
            args.extend(["-mc", "all"])
        
        # Filter status codes
        filter_status = kwargs.get("filter_status")
        if filter_status:
            if isinstance(filter_status, list):
                filter_status = ",".join(map(str, filter_status))
            args.extend(["-fc", filter_status])
        else:
            args.extend(["-fc", "404"])
        
        # Filter size
        filter_size = kwargs.get("filter_size")
        if filter_size:
            if isinstance(filter_size, list):
                filter_size = ",".join(map(str, filter_size))
            args.extend(["-fs", filter_size])
        
        # Filter words
        filter_words = kwargs.get("filter_words")
        if filter_words:
            if isinstance(filter_words, list):
                filter_words = ",".join(map(str, filter_words))
            args.extend(["-fw", filter_words])
        
        # Filter lines
        filter_lines = kwargs.get("filter_lines")
        if filter_lines:
            if isinstance(filter_lines, list):
                filter_lines = ",".join(map(str, filter_lines))
            args.extend(["-fl", filter_lines])
        
        # Threads
        threads = kwargs.get("threads", 40)
        args.extend(["-t", str(threads)])
        
        # Rate limit
        rate = kwargs.get("rate")
        if rate:
            args.extend(["-rate", str(rate)])
        
        # Timeout
        timeout = kwargs.get("timeout", 10)
        args.extend(["-timeout", str(timeout)])
        
        # Recursion
        if kwargs.get("recursion"):
            args.append("-recursion")
            depth = kwargs.get("recursion_depth", 2)
            args.extend(["-recursion-depth", str(depth)])
        
        # Follow redirects
        if kwargs.get("follow_redirects"):
            args.append("-r")
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse ffuf JSON output."""
        import json
        
        result = {
            "results": [],
            "by_status": {},
            "config": {},
            "total": 0,
        }
        
        try:
            data = json.loads(output)
            
            # Parse config
            result["config"] = {
                "url": data.get("config", {}).get("url"),
                "method": data.get("config", {}).get("method"),
                "wordlist": data.get("config", {}).get("inputproviders", [{}])[0].get("value") if data.get("config", {}).get("inputproviders") else None,
            }
            
            # Parse results
            for entry in data.get("results", []):
                item = {
                    "input": entry.get("input", {}).get("FUZZ") or entry.get("input"),
                    "url": entry.get("url"),
                    "status": entry.get("status"),
                    "length": entry.get("length"),
                    "words": entry.get("words"),
                    "lines": entry.get("lines"),
                    "content_type": entry.get("content-type"),
                    "redirect_location": entry.get("redirectlocation"),
                    "duration": entry.get("duration"),
                }
                result["results"].append(item)
                
                # Group by status
                status = str(entry.get("status", "unknown"))
                if status not in result["by_status"]:
                    result["by_status"][status] = []
                result["by_status"][status].append(item)
            
        except json.JSONDecodeError:
            # Fallback to line parsing
            entries = parse_json_lines(output)
            for entry in entries:
                result["results"].append(entry)
        
        result["total"] = len(result["results"])
        
        return result

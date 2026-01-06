"""
Arjun - HTTP parameter discovery tool.
"""

from __future__ import annotations

import json
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class ArjunTool(BaseTool):
    """
    Arjun wrapper - HTTP parameter discovery suite.
    
    Arjun finds hidden HTTP parameters in web applications using
    various techniques including bruteforce, comparing responses, etc.
    
    Example:
        >>> tool = ArjunTool()
        >>> result = await tool.execute("https://example.com/page")
    """
    
    name = "arjun"
    description = "HTTP parameter discovery tool"
    category = ToolCategory.PARAMETER_DISCOVERY
    binary = "arjun"
    homepage = "https://github.com/s0md3v/Arjun"
    install_command = "pip install arjun"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build arjun command.
        
        Args:
            target: Target URL
            method: HTTP method (GET, POST, JSON, XML)
            data: POST data
            headers: Custom headers
            wordlist: Custom wordlist
            chunks: Number of parameter chunks
            threads: Number of threads
            delay: Delay between requests
            timeout: Request timeout
            stable: Stability check
            include: Parameters to include in every request
            quiet: Quiet mode
        """
        args = []
        
        # Target URL
        args.extend(["-u", target])
        
        # Output format - JSON to stdout
        args.extend(["-o", "/dev/stdout", "-oJ"])
        
        # Quiet mode
        if kwargs.get("quiet", True):
            args.append("-q")
        
        # HTTP method
        method = kwargs.get("method", "GET")
        args.extend(["-m", method.upper()])
        
        # POST data
        data = kwargs.get("data")
        if data:
            args.extend(["-d", data])
        
        # Headers
        headers = kwargs.get("headers")
        if headers:
            if isinstance(headers, dict):
                for key, value in headers.items():
                    args.extend(["--headers", f"{key}: {value}"])
            elif isinstance(headers, list):
                for header in headers:
                    args.extend(["--headers", header])
        
        # Wordlist
        wordlist = kwargs.get("wordlist")
        if wordlist:
            args.extend(["-w", wordlist])
        
        # Chunks
        chunks = kwargs.get("chunks")
        if chunks:
            args.extend(["-c", str(chunks)])
        
        # Threads
        threads = kwargs.get("threads", 5)
        args.extend(["-t", str(threads)])
        
        # Delay
        delay = kwargs.get("delay")
        if delay:
            args.extend(["--delay", str(delay)])
        
        # Timeout
        timeout = kwargs.get("timeout", 10)
        args.extend(["--timeout", str(timeout)])
        
        # Stability check
        if kwargs.get("stable"):
            args.append("--stable")
        
        # Include parameters
        include = kwargs.get("include")
        if include:
            if isinstance(include, list):
                include = ",".join(include)
            args.extend(["--include", include])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse arjun JSON output."""
        result = {
            "parameters_found": [],
            "by_url": {},
            "by_method": {
                "GET": [],
                "POST": [],
                "JSON": [],
                "XML": [],
            },
            "total": 0,
        }
        
        try:
            data = json.loads(output)
            
            if isinstance(data, dict):
                for url, params in data.items():
                    if isinstance(params, list):
                        url_params = []
                        for param in params:
                            if isinstance(param, dict):
                                param_data = {
                                    "name": param.get("name") or param.get("param"),
                                    "type": param.get("type"),
                                    "reason": param.get("reason"),
                                    "method": param.get("method", "GET"),
                                }
                            else:
                                param_data = {
                                    "name": param,
                                    "type": "unknown",
                                    "method": "GET",
                                }
                            
                            url_params.append(param_data)
                            result["parameters_found"].append(param_data)
                            
                            # Group by method
                            method = param_data.get("method", "GET")
                            if method in result["by_method"]:
                                result["by_method"][method].append(param_data)
                        
                        result["by_url"][url] = url_params
                    
                    elif isinstance(params, dict):
                        # Different JSON structure
                        for method, method_params in params.items():
                            for param in method_params:
                                param_data = {
                                    "name": param,
                                    "method": method.upper(),
                                    "url": url,
                                }
                                result["parameters_found"].append(param_data)
                                
                                if method.upper() in result["by_method"]:
                                    result["by_method"][method.upper()].append(param_data)
            
            elif isinstance(data, list):
                for param in data:
                    if isinstance(param, str):
                        result["parameters_found"].append({"name": param})
                    elif isinstance(param, dict):
                        result["parameters_found"].append(param)
            
        except json.JSONDecodeError:
            # Parse text output
            import re
            for line in output.strip().split("\n"):
                param_match = re.search(r'Parameter:\s*(\S+)', line)
                if param_match:
                    result["parameters_found"].append({
                        "name": param_match.group(1),
                    })
        
        result["total"] = len(result["parameters_found"])
        
        return result

"""
WhatWeb - Web fingerprinting tool.
"""

from __future__ import annotations

import json
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class WhatWebTool(BaseTool):
    """
    WhatWeb wrapper - Web technology fingerprinting.
    
    Identifies websites - content management systems, blogging platforms,
    statistic packages, JavaScript libraries, web servers, and more.
    
    Example:
        >>> tool = WhatWebTool()
        >>> result = await tool.execute("https://example.com")
    """
    
    name = "whatweb"
    description = "Web technology fingerprinting tool"
    category = ToolCategory.WEB_RECON
    binary = "whatweb"
    homepage = "https://github.com/urbanadventurer/WhatWeb"
    install_command = "apt install whatweb / gem install whatweb"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build whatweb command.
        
        Args:
            target: Target URL
            aggression: Aggression level (1-4)
            plugins: Specific plugins to use
            color: Never use colors
            verbose: Verbose output
            user_agent: Custom user agent
            cookie: Cookies to send
            header: Custom headers
        """
        args = []
        
        # Output format - JSON
        args.extend(["--log-json=-"])
        
        # Aggression level
        aggression = kwargs.get("aggression", 1)
        args.extend(["-a", str(aggression)])
        
        # No colors
        args.append("--color=never")
        
        # Quiet mode
        args.append("-q")
        
        # Plugins
        plugins = kwargs.get("plugins")
        if plugins:
            if isinstance(plugins, list):
                plugins = ",".join(plugins)
            args.extend(["-p", plugins])
        
        # User agent
        user_agent = kwargs.get("user_agent")
        if user_agent:
            args.extend(["-U", user_agent])
        
        # Cookie
        cookie = kwargs.get("cookie")
        if cookie:
            args.extend(["--cookie", cookie])
        
        # Headers
        headers = kwargs.get("headers")
        if headers:
            if isinstance(headers, dict):
                for key, value in headers.items():
                    args.extend(["--header", f"{key}:{value}"])
            elif isinstance(headers, list):
                for header in headers:
                    args.extend(["--header", header])
        
        # Max threads
        max_threads = kwargs.get("max_threads", 25)
        args.extend(["-t", str(max_threads)])
        
        # Follow redirects
        if kwargs.get("follow_redirects", True):
            args.append("--follow-redirect=always")
        
        # Max redirects
        max_redirects = kwargs.get("max_redirects", 5)
        args.extend(["--max-redirects", str(max_redirects)])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        # Target
        args.append(target)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse whatweb JSON output."""
        result = {
            "targets": [],
            "technologies": [],
            "plugins": {},
            "total": 0,
        }
        
        try:
            # WhatWeb outputs JSON array
            data = json.loads(output)
            
            if isinstance(data, list):
                for entry in data:
                    target_data = {
                        "target": entry.get("target"),
                        "http_status": entry.get("http_status"),
                        "request_config": entry.get("request_config", {}),
                        "plugins": {},
                    }
                    
                    plugins = entry.get("plugins", {})
                    for plugin_name, plugin_data in plugins.items():
                        target_data["plugins"][plugin_name] = plugin_data
                        
                        # Aggregate technologies
                        if plugin_name not in result["technologies"]:
                            result["technologies"].append(plugin_name)
                        
                        # Aggregate plugin info
                        if plugin_name not in result["plugins"]:
                            result["plugins"][plugin_name] = []
                        result["plugins"][plugin_name].append({
                            "target": entry.get("target"),
                            "data": plugin_data,
                        })
                    
                    result["targets"].append(target_data)
            
        except json.JSONDecodeError:
            # Fallback - try to parse line by line
            for line in output.strip().split("\n"):
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        target_data = {
                            "target": entry.get("target"),
                            "plugins": entry.get("plugins", {}),
                        }
                        result["targets"].append(target_data)
                    except json.JSONDecodeError:
                        continue
        
        result["total"] = len(result["targets"])
        
        return result

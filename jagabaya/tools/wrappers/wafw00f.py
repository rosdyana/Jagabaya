"""
wafw00f - Web Application Firewall detection tool.
"""

from __future__ import annotations

import json
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class Wafw00fTool(BaseTool):
    """
    wafw00f wrapper - Web Application Firewall detection.
    
    Identifies and fingerprints Web Application Firewall (WAF) products
    protecting a website.
    
    Example:
        >>> tool = Wafw00fTool()
        >>> result = await tool.execute("https://example.com")
    """
    
    name = "wafw00f"
    description = "Web Application Firewall detection tool"
    category = ToolCategory.WEB_RECON
    binary = "wafw00f"
    homepage = "https://github.com/EnableSecurity/wafw00f"
    install_command = "pip install wafw00f"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build wafw00f command.
        
        Args:
            target: Target URL
            all_wafs: Test for all known WAFs
            list_wafs: List all known WAFs
            proxy: Use proxy
            headers: Custom headers
            verbose: Verbose output
        """
        args = []
        
        # Output format - JSON
        args.extend(["-o-", "-f", "json"])
        
        # Test all WAFs
        if kwargs.get("all_wafs"):
            args.append("-a")
        
        # Proxy
        proxy = kwargs.get("proxy")
        if proxy:
            args.extend(["-p", proxy])
        
        # Custom headers
        headers = kwargs.get("headers")
        if headers:
            if isinstance(headers, dict):
                for key, value in headers.items():
                    args.extend(["-H", f"{key}: {value}"])
            elif isinstance(headers, list):
                for header in headers:
                    args.extend(["-H", header])
        
        # Verbose
        if kwargs.get("verbose"):
            args.append("-v")
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        # Target URL
        args.append(target)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse wafw00f JSON output."""
        result = {
            "targets": [],
            "detected_wafs": [],
            "has_waf": False,
            "total": 0,
        }
        
        try:
            data = json.loads(output)
            
            if isinstance(data, list):
                for entry in data:
                    target_data = {
                        "url": entry.get("url"),
                        "detected": entry.get("detected", False),
                        "firewall": entry.get("firewall"),
                        "manufacturer": entry.get("manufacturer"),
                    }
                    
                    result["targets"].append(target_data)
                    
                    if entry.get("detected") and entry.get("firewall"):
                        waf_name = entry.get("firewall")
                        if waf_name not in result["detected_wafs"]:
                            result["detected_wafs"].append(waf_name)
                        result["has_waf"] = True
            
            elif isinstance(data, dict):
                # Single target response
                target_data = {
                    "url": data.get("url"),
                    "detected": data.get("detected", False),
                    "firewall": data.get("firewall"),
                    "manufacturer": data.get("manufacturer"),
                }
                result["targets"].append(target_data)
                
                if data.get("detected") and data.get("firewall"):
                    result["detected_wafs"].append(data.get("firewall"))
                    result["has_waf"] = True
            
        except json.JSONDecodeError:
            # Fallback to text parsing
            for line in output.strip().split("\n"):
                line = line.strip()
                if "is behind" in line.lower():
                    result["has_waf"] = True
                    # Try to extract WAF name
                    if "is behind" in line:
                        parts = line.split("is behind")
                        if len(parts) > 1:
                            waf_name = parts[1].strip()
                            if waf_name not in result["detected_wafs"]:
                                result["detected_wafs"].append(waf_name)
                elif "no waf" in line.lower():
                    result["has_waf"] = False
        
        result["total"] = len(result["targets"])
        
        return result

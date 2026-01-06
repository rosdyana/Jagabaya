"""
XSStrike - XSS scanner.
"""

from __future__ import annotations

import re
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class XSStrikeTool(BaseTool):
    """
    XSStrike wrapper - Advanced XSS detection and exploitation.
    
    XSStrike is an advanced XSS detection suite with handcrafted payloads,
    intelligent context analysis, and fuzzing capabilities.
    
    Example:
        >>> tool = XSStrikeTool()
        >>> result = await tool.execute("https://example.com/page?input=test")
    """
    
    name = "xsstrike"
    description = "Advanced XSS detection suite"
    category = ToolCategory.XSS
    binary = "xsstrike"
    homepage = "https://github.com/s0md3v/XSStrike"
    install_command = "pip install xsstrike / git clone https://github.com/s0md3v/XSStrike"
    output_format = "text"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build xsstrike command.
        
        Args:
            target: Target URL with parameters
            data: POST data
            param: Parameter to test
            crawl: Crawl and test
            blind: Blind XSS testing
            fuzzer: Use fuzzer mode
            skip_dom: Skip DOM checking
            headers: Custom headers
            timeout: Request timeout
            seeds: Seed URL file
            skip: Skip confirmation prompts
        """
        args = []
        
        # Target URL
        args.extend(["-u", target])
        
        # POST data
        data = kwargs.get("data")
        if data:
            args.extend(["--data", data])
        
        # Specific parameter
        param = kwargs.get("param")
        if param:
            args.extend(["--param", param])
        
        # Crawl mode
        if kwargs.get("crawl"):
            args.append("--crawl")
        
        # Blind XSS
        blind = kwargs.get("blind")
        if blind:
            args.extend(["--blind", blind])
        
        # Fuzzer mode
        if kwargs.get("fuzzer"):
            args.append("--fuzzer")
        
        # Skip DOM
        if kwargs.get("skip_dom"):
            args.append("--skip-dom")
        
        # Headers
        headers = kwargs.get("headers")
        if headers:
            if isinstance(headers, dict):
                header_str = "\n".join([f"{k}: {v}" for k, v in headers.items()])
                args.extend(["--headers", header_str])
            elif isinstance(headers, str):
                args.extend(["--headers", headers])
        
        # Timeout
        timeout = kwargs.get("timeout", 10)
        args.extend(["-t", str(timeout)])
        
        # Delay
        delay = kwargs.get("delay")
        if delay:
            args.extend(["-d", str(delay)])
        
        # Seeds file
        seeds = kwargs.get("seeds")
        if seeds:
            args.extend(["--seeds", seeds])
        
        # Skip confirmation
        if kwargs.get("skip", True):
            args.append("--skip")
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse xsstrike text output."""
        result = {
            "vulnerable": False,
            "vulnerabilities": [],
            "payloads": [],
            "parameters_tested": [],
            "reflections": [],
            "waf_detected": None,
            "total": 0,
        }
        
        lines = output.strip().split("\n")
        
        for line in lines:
            line = line.strip()
            
            # Check for vulnerability confirmation
            if "vulnerable" in line.lower() or "payload" in line.lower():
                result["vulnerable"] = True
            
            # Parse vulnerability findings
            if "Vulnerable" in line:
                result["vulnerabilities"].append({
                    "text": line,
                    "type": "reflected_xss",
                })
            
            # Parse payloads
            payload_match = re.search(r'Payload:\s*(.+)', line)
            if payload_match:
                payload = payload_match.group(1).strip()
                result["payloads"].append(payload)
            
            # Parse reflections
            if "Reflection" in line:
                result["reflections"].append(line)
            
            # Parse parameters
            param_match = re.search(r'Testing parameter:\s*(\S+)', line)
            if param_match:
                result["parameters_tested"].append(param_match.group(1))
            
            # WAF detection
            if "WAF" in line:
                waf_match = re.search(r'WAF detected:\s*(.+)', line, re.IGNORECASE)
                if waf_match:
                    result["waf_detected"] = waf_match.group(1).strip()
                elif "WAF" in line and "detected" in line.lower():
                    result["waf_detected"] = "Unknown WAF"
        
        result["total"] = len(result["vulnerabilities"])
        
        return result

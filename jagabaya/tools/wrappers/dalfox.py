"""
Dalfox - XSS scanning and parameter analysis tool.
"""

from __future__ import annotations

from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory
from jagabaya.tools.parsers.common import parse_json_lines


class DalfoxTool(BaseTool):
    """
    Dalfox wrapper - Powerful XSS scanning tool.
    
    DalFox is a fast, powerful parameter analysis and XSS scanner,
    based on a Go runtime. It supports DOM XSS, blind XSS, and stored XSS.
    
    Example:
        >>> tool = DalfoxTool()
        >>> result = await tool.execute("https://example.com/page?input=test")
    """
    
    name = "dalfox"
    description = "Fast parameter analysis and XSS scanner"
    category = ToolCategory.XSS
    binary = "dalfox"
    homepage = "https://github.com/hahwul/dalfox"
    install_command = "go install github.com/hahwul/dalfox/v2@latest"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build dalfox command.
        
        Args:
            target: Target URL with parameters
            data: POST data
            param: Specific parameter to test
            blind: Blind XSS callback URL
            custom_payload: Custom payloads file
            mining_dict: Mining dictionary words
            waf_evasion: Enable WAF evasion
            follow_redirects: Follow HTTP redirects
            skip_bav: Skip BAV (basic all vectors)
            only_discovery: Only run discovery mode
            only_poc: Only print POC code
            workers: Number of workers
            delay: Delay between requests
        """
        args = []
        
        # Mode - url for single URL
        args.append("url")
        
        # Target URL
        args.append(target)
        
        # Output format - JSON
        args.extend(["--format", "json"])
        
        # Silence banner
        args.append("--silence")
        
        # POST data
        data = kwargs.get("data")
        if data:
            args.extend(["-d", data])
        
        # Specific parameter
        param = kwargs.get("param")
        if param:
            args.extend(["-p", param])
        
        # Blind XSS
        blind = kwargs.get("blind")
        if blind:
            args.extend(["--blind", blind])
        
        # Custom payloads
        custom_payload = kwargs.get("custom_payload")
        if custom_payload:
            args.extend(["--custom-payload", custom_payload])
        
        # Mining dictionary
        mining_dict = kwargs.get("mining_dict")
        if mining_dict:
            args.extend(["--mining-dict-word", mining_dict])
        
        # Mining all
        if kwargs.get("mining_all"):
            args.append("--mining-dom")
            args.append("--mining-dict")
        
        # WAF evasion
        if kwargs.get("waf_evasion"):
            args.append("--waf-evasion")
        
        # Follow redirects
        if kwargs.get("follow_redirects"):
            args.append("--follow-redirects")
        
        # Skip BAV
        if kwargs.get("skip_bav"):
            args.append("--skip-bav")
        
        # Only discovery
        if kwargs.get("only_discovery"):
            args.append("--only-discovery")
        
        # Only POC
        if kwargs.get("only_poc"):
            args.append("--only-poc")
        
        # Workers
        workers = kwargs.get("workers", 10)
        args.extend(["-w", str(workers)])
        
        # Delay
        delay = kwargs.get("delay")
        if delay:
            args.extend(["--delay", str(delay)])
        
        # Timeout
        timeout = kwargs.get("timeout", 10)
        args.extend(["--timeout", str(timeout)])
        
        # Headers
        headers = kwargs.get("headers")
        if headers:
            if isinstance(headers, dict):
                for key, value in headers.items():
                    args.extend(["-H", f"{key}: {value}"])
            elif isinstance(headers, list):
                for header in headers:
                    args.extend(["-H", header])
        
        # Cookie
        cookie = kwargs.get("cookie")
        if cookie:
            args.extend(["-C", cookie])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse dalfox JSON output."""
        result = {
            "vulnerable": False,
            "vulnerabilities": [],
            "pocs": [],
            "params_found": [],
            "reflected_params": [],
            "total": 0,
        }
        
        entries = parse_json_lines(output)
        
        for entry in entries:
            msg_type = entry.get("type")
            
            if msg_type == "POC":
                result["vulnerable"] = True
                vuln = {
                    "url": entry.get("data"),
                    "param": entry.get("param"),
                    "payload": entry.get("payload"),
                    "type": entry.get("poc_type", "xss"),
                    "method": entry.get("method"),
                    "evidence": entry.get("evidence"),
                    "cwe": entry.get("cwe"),
                    "severity": entry.get("severity", "high"),
                }
                result["vulnerabilities"].append(vuln)
                result["pocs"].append(entry.get("data"))
            
            elif msg_type == "PARAM":
                result["params_found"].append({
                    "param": entry.get("param"),
                    "type": entry.get("param_type"),
                })
            
            elif msg_type == "REFLECTED":
                result["reflected_params"].append({
                    "param": entry.get("param"),
                    "url": entry.get("data"),
                })
            
            elif msg_type == "WEAK":
                result["vulnerabilities"].append({
                    "url": entry.get("data"),
                    "param": entry.get("param"),
                    "type": "weak_xss",
                    "severity": "low",
                    "evidence": entry.get("evidence"),
                })
        
        result["total"] = len(result["vulnerabilities"])
        
        return result

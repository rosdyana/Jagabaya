"""
testssl.sh - SSL/TLS testing tool.
"""

from __future__ import annotations

import json
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class TestSSLTool(BaseTool):
    """
    testssl.sh wrapper - SSL/TLS server testing.
    
    Tests a server's TLS/SSL implementation for vulnerabilities,
    cipher suites, protocols, and configuration issues.
    
    Example:
        >>> tool = TestSSLTool()
        >>> result = await tool.execute("example.com:443")
    """
    
    name = "testssl"
    description = "SSL/TLS server testing tool"
    category = ToolCategory.SSL_TLS
    binary = "testssl.sh"
    homepage = "https://testssl.sh"
    install_command = "apt install testssl.sh / git clone https://github.com/drwetter/testssl.sh"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build testssl.sh command.
        
        Args:
            target: Target host:port
            full: Run full tests
            protocols: Test protocols only
            ciphers: Test ciphers only
            vulnerabilities: Test vulnerabilities only
            headers: Test HTTP headers
            quiet: Quiet mode
            sneaky: Use low frequency mode
        """
        args = []
        
        # Output format - JSON
        args.extend(["--jsonfile=-"])
        
        # Quiet mode
        if kwargs.get("quiet", True):
            args.append("--quiet")
        
        # Color mode
        args.append("--color=0")
        
        # Full test
        if kwargs.get("full"):
            args.append("--full")
        
        # Protocol tests
        if kwargs.get("protocols"):
            args.append("-p")
        
        # Cipher tests
        if kwargs.get("ciphers"):
            args.append("-E")
        
        # Vulnerability tests
        if kwargs.get("vulnerabilities"):
            args.extend([
                "-U",  # All vulnerabilities
            ])
        
        # Specific vulnerability tests
        if kwargs.get("heartbleed"):
            args.append("-H")
        if kwargs.get("ccs"):
            args.append("-I")
        if kwargs.get("renegotiation"):
            args.append("-R")
        if kwargs.get("crime"):
            args.append("-C")
        if kwargs.get("breach"):
            args.append("-B")
        if kwargs.get("poodle"):
            args.append("-O")
        if kwargs.get("robot"):
            args.append("-BB")
        
        # Server defaults
        if kwargs.get("server_defaults"):
            args.append("-S")
        
        # Server preference
        if kwargs.get("server_preference"):
            args.append("-P")
        
        # HTTP headers
        if kwargs.get("headers"):
            args.append("-h")
        
        # Certificate info
        if kwargs.get("cert"):
            args.append("-c")
        
        # Sneaky mode (low frequency)
        if kwargs.get("sneaky"):
            args.append("--sneaky")
        
        # Warning - not suppressing
        if not kwargs.get("show_warnings"):
            args.append("--warnings=off")
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        # Target
        args.append(target)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse testssl.sh JSON output."""
        result = {
            "target": {},
            "protocols": [],
            "ciphers": [],
            "vulnerabilities": [],
            "certificates": [],
            "findings": [],
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "ok": 0,
            },
            "total": 0,
        }
        
        try:
            data = json.loads(output)
            
            if isinstance(data, list):
                for entry in data:
                    entry_id = entry.get("id", "")
                    severity = entry.get("severity", "INFO").lower()
                    finding_text = entry.get("finding", "")
                    
                    finding = {
                        "id": entry_id,
                        "severity": severity,
                        "finding": finding_text,
                        "cve": entry.get("cve"),
                        "cwe": entry.get("cwe"),
                    }
                    
                    result["findings"].append(finding)
                    
                    # Count by severity
                    if severity in result["severity_counts"]:
                        result["severity_counts"][severity] += 1
                    
                    # Categorize findings
                    if entry_id.startswith("protocol_"):
                        result["protocols"].append(finding)
                    elif entry_id.startswith("cipher_") or "cipher" in entry_id.lower():
                        result["ciphers"].append(finding)
                    elif entry_id.startswith("cert_") or "certificate" in entry_id.lower():
                        result["certificates"].append(finding)
                    elif any(vuln in entry_id.lower() for vuln in [
                        "heartbleed", "ccs", "crime", "breach", "poodle",
                        "freak", "drown", "logjam", "beast", "robot",
                        "ticketbleed", "lucky13", "sweet32"
                    ]):
                        result["vulnerabilities"].append(finding)
                    elif entry_id == "service":
                        result["target"]["service"] = finding_text
                    elif entry_id == "hostname":
                        result["target"]["hostname"] = finding_text
                    elif entry_id == "ip":
                        result["target"]["ip"] = finding_text
                    elif entry_id == "port":
                        result["target"]["port"] = finding_text
            
        except json.JSONDecodeError:
            result["error"] = "Failed to parse JSON output"
            result["raw"] = output[:1000]
        
        result["total"] = len(result["findings"])
        
        return result
    
    def _get_version(self) -> str | None:
        """Get testssl.sh version."""
        try:
            import subprocess
            result = subprocess.run(
                [self.binary, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout or result.stderr
            if output:
                for line in output.split("\n"):
                    if "testssl" in line.lower():
                        return line.strip()[:100]
        except Exception:
            pass
        return None

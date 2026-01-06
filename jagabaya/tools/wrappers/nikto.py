"""
Nikto - Web server scanner.
"""

from __future__ import annotations

import re
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class NiktoTool(BaseTool):
    """
    Nikto wrapper - Web server scanner.
    
    Nikto is an open source web server scanner which performs comprehensive
    tests against web servers for multiple items, including dangerous files,
    outdated server versions, and version-specific problems.
    
    Example:
        >>> tool = NiktoTool()
        >>> result = await tool.execute("https://example.com")
    """
    
    name = "nikto"
    description = "Web server scanner for vulnerabilities and misconfigurations"
    category = ToolCategory.VULNERABILITY
    binary = "nikto"
    homepage = "https://cirt.net/Nikto2"
    install_command = "apt install nikto / brew install nikto"
    output_format = "text"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build nikto command.
        
        Args:
            target: Target URL or host
            port: Port to scan
            ssl: Use SSL
            tuning: Tuning options
            plugins: Specific plugins to run
            timeout: Timeout per request
            pause: Pause between requests
            no_ssl_check: Disable SSL certificate checks
        """
        args = []
        
        # Target
        args.extend(["-h", target])
        
        # Port
        port = kwargs.get("port")
        if port:
            args.extend(["-p", str(port)])
        
        # SSL
        if kwargs.get("ssl"):
            args.append("-ssl")
        
        # Disable SSL check
        if kwargs.get("no_ssl_check", True):
            args.append("-nossl")
        
        # Tuning
        tuning = kwargs.get("tuning")
        if tuning:
            args.extend(["-Tuning", str(tuning)])
        
        # Plugins
        plugins = kwargs.get("plugins")
        if plugins:
            if isinstance(plugins, list):
                plugins = ",".join(plugins)
            args.extend(["-Plugins", plugins])
        
        # Timeout
        timeout = kwargs.get("timeout", 10)
        args.extend(["-timeout", str(timeout)])
        
        # Pause between requests
        pause = kwargs.get("pause")
        if pause:
            args.extend(["-Pause", str(pause)])
        
        # Max time to scan
        max_time = kwargs.get("max_time")
        if max_time:
            args.extend(["-maxtime", str(max_time)])
        
        # No 404 guessing
        if kwargs.get("no_404"):
            args.append("-no404")
        
        # Display options
        args.extend(["-Display", "V"])  # Verbose output
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse nikto text output."""
        result = {
            "target": {},
            "findings": [],
            "server": None,
            "headers": [],
            "total": 0,
        }
        
        lines = output.strip().split("\n")
        
        for line in lines:
            line = line.strip()
            
            # Parse target info
            if line.startswith("+ Target IP:"):
                result["target"]["ip"] = line.split(":", 1)[1].strip()
            elif line.startswith("+ Target Hostname:"):
                result["target"]["hostname"] = line.split(":", 1)[1].strip()
            elif line.startswith("+ Target Port:"):
                result["target"]["port"] = line.split(":", 1)[1].strip()
            elif line.startswith("+ Server:"):
                result["server"] = line.split(":", 1)[1].strip()
            
            # Parse findings
            elif line.startswith("+ ") and ":" in line:
                # This is a finding line
                finding_text = line[2:]  # Remove "+ "
                
                # Try to extract OSVDB or other IDs
                osvdb_match = re.search(r'OSVDB-(\d+)', finding_text)
                osvdb_id = f"OSVDB-{osvdb_match.group(1)}" if osvdb_match else None
                
                # Extract path if present
                path_match = re.search(r'^(/[^\s:]+)', finding_text)
                path = path_match.group(1) if path_match else None
                
                finding = {
                    "text": finding_text,
                    "osvdb_id": osvdb_id,
                    "path": path,
                }
                
                # Determine severity based on content
                lower_text = finding_text.lower()
                if any(word in lower_text for word in ["critical", "remote code", "rce", "sql injection"]):
                    finding["severity"] = "critical"
                elif any(word in lower_text for word in ["vulnerability", "vulnerable", "xss", "csrf"]):
                    finding["severity"] = "high"
                elif any(word in lower_text for word in ["outdated", "default", "disclosure"]):
                    finding["severity"] = "medium"
                elif any(word in lower_text for word in ["information", "header", "cookie"]):
                    finding["severity"] = "low"
                else:
                    finding["severity"] = "info"
                
                result["findings"].append(finding)
            
            # Parse interesting headers
            elif "header" in line.lower() and ":" in line:
                result["headers"].append(line)
        
        result["total"] = len(result["findings"])
        
        return result
    
    def _get_version(self) -> str | None:
        """Get nikto version."""
        try:
            import subprocess
            result = subprocess.run(
                [self.binary, "-Version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout or result.stderr
            if output:
                return output.strip().split("\n")[0][:100]
        except Exception:
            pass
        return None

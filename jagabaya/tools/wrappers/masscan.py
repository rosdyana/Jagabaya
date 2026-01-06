"""
Masscan - Fast port scanner.
"""

from __future__ import annotations

import json
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class MasscanTool(BaseTool):
    """
    Masscan wrapper - the fastest Internet port scanner.
    
    Masscan can scan the entire Internet in under 5 minutes,
    transmitting 10 million packets per second.
    
    Example:
        >>> tool = MasscanTool()
        >>> result = await tool.execute("192.168.1.0/24", ports="80,443,8080")
    """
    
    name = "masscan"
    description = "Fast port scanner for large-scale scans"
    category = ToolCategory.NETWORK
    binary = "masscan"
    homepage = "https://github.com/robertdavidgraham/masscan"
    install_command = "apt install masscan / brew install masscan"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build masscan command.
        
        Args:
            target: Target IP or CIDR range
            ports: Port specification (e.g., "80,443" or "0-65535")
            rate: Packets per second (default: 1000)
            banners: Enable banner grabbing
            adapter: Network adapter to use
        """
        args = []
        
        # Output format - JSON for parsing
        args.extend(["-oJ", "-"])
        
        # Ports
        ports = kwargs.get("ports", "80,443,8080")
        args.extend(["-p", str(ports)])
        
        # Rate limiting
        rate = kwargs.get("rate", 1000)
        args.extend(["--rate", str(rate)])
        
        # Banner grabbing
        if kwargs.get("banners"):
            args.append("--banners")
        
        # Network adapter
        adapter = kwargs.get("adapter")
        if adapter:
            args.extend(["--adapter", adapter])
        
        # Wait time after scan
        wait = kwargs.get("wait", 3)
        args.extend(["--wait", str(wait)])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        # Target
        args.append(target)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse masscan JSON output."""
        result = {
            "hosts": [],
            "ports": [],
            "total_hosts": 0,
            "total_ports": 0,
        }
        
        try:
            # Masscan outputs JSON array or JSON lines
            # Try parsing as JSON array first
            if output.strip().startswith("["):
                data = json.loads(output)
            else:
                # Parse as JSON lines
                data = []
                for line in output.strip().split("\n"):
                    line = line.strip().rstrip(",")
                    if line and line not in ["[", "]", "{", "}"]:
                        try:
                            data.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            
            hosts_seen = set()
            
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                
                ip = entry.get("ip")
                if not ip:
                    continue
                
                if ip not in hosts_seen:
                    hosts_seen.add(ip)
                    result["hosts"].append({
                        "ip": ip,
                        "timestamp": entry.get("timestamp"),
                    })
                
                for port_info in entry.get("ports", []):
                    result["ports"].append({
                        "host": ip,
                        "port": port_info.get("port"),
                        "protocol": port_info.get("proto", "tcp"),
                        "status": port_info.get("status", "open"),
                        "service": port_info.get("service", {}).get("name"),
                        "banner": port_info.get("service", {}).get("banner"),
                    })
            
            result["total_hosts"] = len(hosts_seen)
            result["total_ports"] = len(result["ports"])
            
        except json.JSONDecodeError as e:
            result["error"] = f"JSON parse error: {e}"
            result["raw"] = output[:1000]
        
        return result

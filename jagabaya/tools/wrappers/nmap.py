"""
Nmap - Network port scanner and service detector.
"""

from __future__ import annotations

from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory
from jagabaya.tools.parsers.nmap import parse_nmap_xml


class NmapTool(BaseTool):
    """
    Nmap network scanner wrapper.
    
    Nmap is a powerful network discovery and security auditing tool.
    It can detect open ports, running services, OS versions, and more.
    
    Example:
        >>> tool = NmapTool()
        >>> result = await tool.execute("192.168.1.1", ports="1-1000")
    """
    
    name = "nmap"
    description = "Network port scanner and service detector"
    category = ToolCategory.NETWORK
    binary = "nmap"
    homepage = "https://nmap.org"
    install_command = "apt install nmap / brew install nmap"
    output_format = "xml"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build nmap command.
        
        Args:
            target: Target IP, hostname, or CIDR range
            ports: Port specification (e.g., "80,443" or "1-1000")
            scan_type: Scan type (syn, connect, udp, etc.)
            service_version: Enable service version detection
            os_detection: Enable OS detection
            scripts: NSE scripts to run
            timing: Timing template (0-5)
            aggressive: Enable aggressive mode (-A)
            stealth: Enable stealth scan
            top_ports: Scan top N ports
        """
        args = []
        
        # Output format - always XML for parsing
        args.extend(["-oX", "-"])
        
        # Scan type
        scan_type = kwargs.get("scan_type")
        if scan_type == "syn":
            args.append("-sS")
        elif scan_type == "connect":
            args.append("-sT")
        elif scan_type == "udp":
            args.append("-sU")
        elif scan_type == "ack":
            args.append("-sA")
        elif scan_type == "fin":
            args.append("-sF")
        
        # Port specification
        ports = kwargs.get("ports")
        top_ports = kwargs.get("top_ports")
        if ports:
            args.extend(["-p", str(ports)])
        elif top_ports:
            args.extend(["--top-ports", str(top_ports)])
        
        # Service version detection
        if kwargs.get("service_version", True):
            args.append("-sV")
        
        # OS detection
        if kwargs.get("os_detection"):
            args.append("-O")
        
        # Aggressive mode
        if kwargs.get("aggressive"):
            args.append("-A")
        
        # Stealth mode
        if kwargs.get("stealth"):
            args.extend(["-T2", "--scan-delay", "1s"])
        
        # Timing template
        timing = kwargs.get("timing")
        if timing is not None:
            args.append(f"-T{timing}")
        
        # NSE scripts
        scripts = kwargs.get("scripts")
        if scripts:
            if isinstance(scripts, list):
                scripts = ",".join(scripts)
            args.extend(["--script", scripts])
        elif kwargs.get("default_scripts", True):
            args.append("-sC")
        
        # Disable ping (useful for firewalled hosts)
        if kwargs.get("no_ping"):
            args.append("-Pn")
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        # Target
        args.append(target)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse nmap XML output."""
        return parse_nmap_xml(output)
    
    def _get_version(self) -> str | None:
        """Get nmap version."""
        try:
            import subprocess
            result = subprocess.run(
                [self.binary, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Parse "Nmap version X.XX"
            for line in result.stdout.split("\n"):
                if "Nmap version" in line:
                    return line.strip()
        except Exception:
            pass
        return None

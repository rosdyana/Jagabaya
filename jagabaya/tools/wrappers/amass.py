"""
Amass - In-depth Attack Surface Mapping and Asset Discovery.
"""

from __future__ import annotations

from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory
from jagabaya.tools.parsers.common import parse_json_lines, parse_plain_lines


class AmassTool(BaseTool):
    """
    Amass wrapper - OWASP Amass attack surface mapper.
    
    Performs network mapping of attack surfaces and external asset discovery
    using open source information gathering and active reconnaissance.
    
    Example:
        >>> tool = AmassTool()
        >>> result = await tool.execute("example.com")
    """
    
    name = "amass"
    description = "In-depth attack surface mapping and asset discovery"
    category = ToolCategory.SUBDOMAIN
    binary = "amass"
    homepage = "https://github.com/owasp-amass/amass"
    install_command = "go install github.com/owasp-amass/amass/v4/...@master"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build amass command.
        
        Args:
            target: Target domain
            mode: Scan mode (passive, active)
            brute: Enable brute force
            alts: Enable alterations
            timeout: Timeout in minutes
            max_dns_queries: Max DNS queries per minute
            sources: Data sources to use
        """
        args = []
        
        # Subcommand - enum for enumeration
        args.append("enum")
        
        # Output format - JSON
        args.append("-json")
        args.append("-")
        
        # Silent mode
        args.append("-silent")
        
        # Target domain
        args.extend(["-d", target])
        
        # Mode
        mode = kwargs.get("mode", "passive")
        if mode == "passive":
            args.append("-passive")
        elif mode == "active":
            args.append("-active")
        
        # Brute force
        if kwargs.get("brute"):
            args.append("-brute")
        
        # Alterations/permutations
        if kwargs.get("alts"):
            args.append("-alts")
        
        # Timeout
        timeout = kwargs.get("timeout")
        if timeout:
            args.extend(["-timeout", str(timeout)])
        
        # Max DNS queries
        max_dns = kwargs.get("max_dns_queries")
        if max_dns:
            args.extend(["-max-dns-queries", str(max_dns)])
        
        # Minimum for recursive brute forcing
        min_for_recursive = kwargs.get("min_for_recursive")
        if min_for_recursive:
            args.extend(["-min-for-recursive", str(min_for_recursive)])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse amass output."""
        result = {
            "subdomains": [],
            "addresses": [],
            "asns": [],
            "sources": {},
            "total": 0,
        }
        
        # Try JSON format first
        entries = parse_json_lines(output)
        
        if entries:
            seen_subdomains = set()
            
            for entry in entries:
                name = entry.get("name")
                
                if name and name not in seen_subdomains:
                    seen_subdomains.add(name)
                    
                    subdomain_data = {
                        "name": name,
                        "domain": entry.get("domain"),
                        "addresses": entry.get("addresses", []),
                        "sources": entry.get("sources", []),
                    }
                    result["subdomains"].append(subdomain_data)
                    
                    # Collect addresses
                    for addr in entry.get("addresses", []):
                        ip = addr.get("ip")
                        if ip and ip not in [a["ip"] for a in result["addresses"]]:
                            result["addresses"].append({
                                "ip": ip,
                                "asn": addr.get("asn"),
                                "cidr": addr.get("cidr"),
                                "desc": addr.get("desc"),
                            })
                    
                    # Collect sources
                    for source in entry.get("sources", []):
                        if source not in result["sources"]:
                            result["sources"][source] = []
                        result["sources"][source].append(name)
        else:
            # Fallback to plain text
            lines = parse_plain_lines(output)
            result["subdomains"] = [{"name": line} for line in set(lines)]
        
        result["total"] = len(result["subdomains"])
        
        return result
    
    def _get_version(self) -> str | None:
        """Get amass version."""
        try:
            import subprocess
            result = subprocess.run(
                [self.binary, "-version"],
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

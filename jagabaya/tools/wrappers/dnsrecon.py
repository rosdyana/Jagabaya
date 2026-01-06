"""
DNSRecon - DNS enumeration tool.
"""

from __future__ import annotations

import json
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class DnsReconTool(BaseTool):
    """
    DNSRecon wrapper - DNS enumeration tool.
    
    DNSRecon is a Python script that provides the ability to perform
    DNS zone transfers, enumeration, and record lookups.
    
    Example:
        >>> tool = DnsReconTool()
        >>> result = await tool.execute("example.com")
    """
    
    name = "dnsrecon"
    description = "DNS enumeration and zone transfer tool"
    category = ToolCategory.DNS
    binary = "dnsrecon"
    homepage = "https://github.com/darkoperator/dnsrecon"
    install_command = "pip install dnsrecon"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build dnsrecon command.
        
        Args:
            target: Target domain
            type: Enumeration type (std, rvl, brt, srv, axfr, goo, snoop, tld, zonewalk)
            nameserver: Nameserver to use
            wordlist: Wordlist for brute force
            threads: Number of threads
            lifetime: Query lifetime
            tcp: Use TCP instead of UDP
            whois: Perform WHOIS lookup
        """
        args = []
        
        # Target domain
        args.extend(["-d", target])
        
        # Output format - JSON to stdout
        args.extend(["-j", "/dev/stdout"])
        
        # Enumeration type
        enum_type = kwargs.get("type", "std")
        args.extend(["-t", enum_type])
        
        # Nameserver
        nameserver = kwargs.get("nameserver")
        if nameserver:
            args.extend(["-n", nameserver])
        
        # Wordlist for brute force
        wordlist = kwargs.get("wordlist")
        if wordlist:
            args.extend(["-D", wordlist])
        
        # Threads
        threads = kwargs.get("threads")
        if threads:
            args.extend(["--threads", str(threads)])
        
        # Query lifetime
        lifetime = kwargs.get("lifetime")
        if lifetime:
            args.extend(["--lifetime", str(lifetime)])
        
        # TCP mode
        if kwargs.get("tcp"):
            args.append("--tcp")
        
        # WHOIS
        if kwargs.get("whois"):
            args.append("-w")
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse dnsrecon JSON output."""
        result = {
            "records": [],
            "by_type": {},
            "nameservers": [],
            "mail_servers": [],
            "hosts": [],
            "zone_transfer": None,
            "total": 0,
        }
        
        try:
            data = json.loads(output)
            
            if isinstance(data, list):
                for record in data:
                    record_type = record.get("type", "")
                    
                    parsed_record = {
                        "type": record_type,
                        "name": record.get("name"),
                        "address": record.get("address"),
                        "target": record.get("target"),
                        "mname": record.get("mname"),
                        "port": record.get("port"),
                        "text": record.get("text"),
                    }
                    result["records"].append(parsed_record)
                    
                    # Group by type
                    if record_type not in result["by_type"]:
                        result["by_type"][record_type] = []
                    result["by_type"][record_type].append(parsed_record)
                    
                    # Categorize special records
                    if record_type == "NS":
                        result["nameservers"].append(record.get("target"))
                    elif record_type in ["MX", "mx"]:
                        result["mail_servers"].append(record.get("target") or record.get("address"))
                    elif record_type in ["A", "AAAA"]:
                        result["hosts"].append({
                            "name": record.get("name"),
                            "address": record.get("address"),
                        })
                    elif record_type == "AXFR":
                        result["zone_transfer"] = True
            
        except json.JSONDecodeError:
            # Parse text output
            for line in output.strip().split("\n"):
                if "[*]" in line:
                    result["records"].append({"raw": line})
        
        result["total"] = len(result["records"])
        
        return result

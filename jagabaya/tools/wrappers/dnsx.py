"""
dnsx - Fast DNS toolkit.
"""

from __future__ import annotations

from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory
from jagabaya.tools.parsers.common import parse_json_lines


class DnsxTool(BaseTool):
    """
    dnsx wrapper - Fast and multi-purpose DNS toolkit.
    
    dnsx is a fast and multi-purpose DNS toolkit designed for running
    multiple DNS queries with various record types.
    
    Example:
        >>> tool = DnsxTool()
        >>> result = await tool.execute("example.com")
    """
    
    name = "dnsx"
    description = "Fast DNS toolkit for multiple record queries"
    category = ToolCategory.DNS
    binary = "dnsx"
    homepage = "https://github.com/projectdiscovery/dnsx"
    install_command = "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build dnsx command.
        
        Args:
            target: Target domain or file with domains
            record_types: DNS record types to query (a, aaaa, ns, mx, txt, cname, soa, ptr)
            resolver: Custom resolvers
            wildcard: Perform wildcard filtering
            trace: Perform DNS trace
            resp: Include response
            resp_only: Output only responses
            threads: Number of concurrent threads
            rate_limit: Rate limit per second
            retries: Number of retries
        """
        args = []
        
        # Input domain
        args.extend(["-d", target])
        
        # Output format - JSON
        args.append("-json")
        
        # Silent mode
        args.append("-silent")
        
        # Record types
        record_types = kwargs.get("record_types")
        if record_types:
            if isinstance(record_types, list):
                for rt in record_types:
                    args.append(f"-{rt.lower()}")
            else:
                args.append(f"-{record_types.lower()}")
        else:
            # Default: query A records
            args.append("-a")
        
        # All record types
        if kwargs.get("all_records"):
            args.extend(["-a", "-aaaa", "-ns", "-mx", "-txt", "-cname", "-soa"])
        
        # Resolver
        resolver = kwargs.get("resolver")
        if resolver:
            if isinstance(resolver, list):
                args.extend(["-r", ",".join(resolver)])
            else:
                args.extend(["-r", resolver])
        
        # Wildcard filtering
        if kwargs.get("wildcard"):
            args.append("-wd")
        
        # DNS trace
        if kwargs.get("trace"):
            args.append("-trace")
        
        # Include response
        if kwargs.get("resp", True):
            args.append("-resp")
        
        # Response only
        if kwargs.get("resp_only"):
            args.append("-ro")
        
        # Threads
        threads = kwargs.get("threads", 100)
        args.extend(["-t", str(threads)])
        
        # Rate limit
        rate_limit = kwargs.get("rate_limit")
        if rate_limit:
            args.extend(["-rl", str(rate_limit)])
        
        # Retries
        retries = kwargs.get("retries", 2)
        args.extend(["-retry", str(retries)])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse dnsx JSON output."""
        result = {
            "hosts": [],
            "records": [],
            "by_type": {
                "a": [],
                "aaaa": [],
                "ns": [],
                "mx": [],
                "txt": [],
                "cname": [],
                "soa": [],
            },
            "total": 0,
        }
        
        entries = parse_json_lines(output)
        
        for entry in entries:
            host = entry.get("host")
            
            host_data = {
                "host": host,
                "resolver": entry.get("resolver"),
                "status_code": entry.get("status_code"),
            }
            
            # Parse A records
            a_records = entry.get("a", [])
            if a_records:
                host_data["a"] = a_records
                for ip in a_records:
                    result["by_type"]["a"].append({"host": host, "address": ip})
                    result["records"].append({"type": "A", "host": host, "address": ip})
            
            # Parse AAAA records
            aaaa_records = entry.get("aaaa", [])
            if aaaa_records:
                host_data["aaaa"] = aaaa_records
                for ip in aaaa_records:
                    result["by_type"]["aaaa"].append({"host": host, "address": ip})
                    result["records"].append({"type": "AAAA", "host": host, "address": ip})
            
            # Parse NS records
            ns_records = entry.get("ns", [])
            if ns_records:
                host_data["ns"] = ns_records
                for ns in ns_records:
                    result["by_type"]["ns"].append({"host": host, "nameserver": ns})
                    result["records"].append({"type": "NS", "host": host, "target": ns})
            
            # Parse MX records
            mx_records = entry.get("mx", [])
            if mx_records:
                host_data["mx"] = mx_records
                for mx in mx_records:
                    result["by_type"]["mx"].append({"host": host, "mail_server": mx})
                    result["records"].append({"type": "MX", "host": host, "target": mx})
            
            # Parse TXT records
            txt_records = entry.get("txt", [])
            if txt_records:
                host_data["txt"] = txt_records
                for txt in txt_records:
                    result["by_type"]["txt"].append({"host": host, "text": txt})
                    result["records"].append({"type": "TXT", "host": host, "text": txt})
            
            # Parse CNAME records
            cname_records = entry.get("cname", [])
            if cname_records:
                host_data["cname"] = cname_records
                for cname in cname_records:
                    result["by_type"]["cname"].append({"host": host, "target": cname})
                    result["records"].append({"type": "CNAME", "host": host, "target": cname})
            
            # Parse SOA records
            soa_records = entry.get("soa", [])
            if soa_records:
                host_data["soa"] = soa_records
                for soa in soa_records:
                    result["by_type"]["soa"].append({"host": host, "soa": soa})
                    result["records"].append({"type": "SOA", "host": host, "soa": soa})
            
            result["hosts"].append(host_data)
        
        result["total"] = len(result["records"])
        
        return result

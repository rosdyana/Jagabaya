"""
httpx - Fast HTTP toolkit for probing web servers.
"""

from __future__ import annotations

from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory
from jagabaya.tools.parsers.common import parse_json_lines


class HttpxTool(BaseTool):
    """
    httpx wrapper - Fast and multi-purpose HTTP toolkit.
    
    Probes web servers to extract status codes, titles, technologies,
    and other useful metadata.
    
    Example:
        >>> tool = HttpxTool()
        >>> result = await tool.execute("example.com")
    """
    
    name = "httpx"
    description = "Fast HTTP toolkit for web server probing"
    category = ToolCategory.WEB_RECON
    binary = "httpx"
    homepage = "https://github.com/projectdiscovery/httpx"
    install_command = "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build httpx command.
        
        Args:
            target: Target URL or domain
            ports: Ports to probe (e.g., "80,443,8080")
            paths: Paths to check
            threads: Number of threads
            timeout: Request timeout
            follow_redirects: Follow HTTP redirects
            status_code: Show status codes
            title: Extract page titles
            tech_detect: Detect technologies
            content_length: Show content length
            web_server: Show web server
            extract_fqdn: Extract FQDNs from response
        """
        args = []
        
        # Output format - JSON
        args.append("-json")
        
        # Silent mode (no banner)
        args.append("-silent")
        
        # Input target
        args.extend(["-u", target])
        
        # Ports
        ports = kwargs.get("ports")
        if ports:
            args.extend(["-p", str(ports)])
        
        # Probes
        if kwargs.get("status_code", True):
            args.append("-status-code")
        
        if kwargs.get("title", True):
            args.append("-title")
        
        if kwargs.get("tech_detect", True):
            args.append("-tech-detect")
        
        if kwargs.get("content_length"):
            args.append("-content-length")
        
        if kwargs.get("web_server", True):
            args.append("-web-server")
        
        if kwargs.get("extract_fqdn"):
            args.append("-efqdn")
        
        if kwargs.get("favicon"):
            args.append("-favicon")
        
        if kwargs.get("jarm"):
            args.append("-jarm")
        
        # Follow redirects
        if kwargs.get("follow_redirects", True):
            args.append("-follow-redirects")
        
        # Max redirects
        max_redirects = kwargs.get("max_redirects")
        if max_redirects:
            args.extend(["-max-redirects", str(max_redirects)])
        
        # Threads
        threads = kwargs.get("threads", 50)
        args.extend(["-threads", str(threads)])
        
        # Timeout
        timeout = kwargs.get("timeout", 10)
        args.extend(["-timeout", str(timeout)])
        
        # Rate limit
        rate_limit = kwargs.get("rate_limit")
        if rate_limit:
            args.extend(["-rate-limit", str(rate_limit)])
        
        # Retries
        retries = kwargs.get("retries", 2)
        args.extend(["-retries", str(retries)])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse httpx JSON output."""
        result = {
            "hosts": [],
            "technologies": [],
            "web_servers": [],
            "status_codes": {},
        }
        
        entries = parse_json_lines(output)
        
        for entry in entries:
            host_data = {
                "url": entry.get("url"),
                "input": entry.get("input"),
                "scheme": entry.get("scheme"),
                "host": entry.get("host"),
                "port": entry.get("port"),
                "path": entry.get("path"),
                "status_code": entry.get("status_code"),
                "title": entry.get("title"),
                "web_server": entry.get("webserver"),
                "content_type": entry.get("content_type"),
                "content_length": entry.get("content_length"),
                "final_url": entry.get("final_url"),
                "failed": entry.get("failed", False),
            }
            
            # Technologies
            techs = entry.get("tech", [])
            if techs:
                host_data["technologies"] = techs
                result["technologies"].extend(techs)
            
            # TLS info
            if entry.get("tls"):
                host_data["tls"] = entry.get("tls")
            
            # Hash values
            if entry.get("hash"):
                host_data["hash"] = entry.get("hash")
            
            # JARM fingerprint
            if entry.get("jarm"):
                host_data["jarm"] = entry.get("jarm")
            
            # Favicon hash
            if entry.get("favicon"):
                host_data["favicon_hash"] = entry.get("favicon")
            
            result["hosts"].append(host_data)
            
            # Aggregate status codes
            status = entry.get("status_code")
            if status:
                result["status_codes"][status] = result["status_codes"].get(status, 0) + 1
            
            # Aggregate web servers
            webserver = entry.get("webserver")
            if webserver and webserver not in result["web_servers"]:
                result["web_servers"].append(webserver)
        
        # Deduplicate technologies
        result["technologies"] = list(set(result["technologies"]))
        result["total_hosts"] = len(result["hosts"])
        
        return result

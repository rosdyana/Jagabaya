"""
Gobuster - Directory/file brute-force tool.
"""

from __future__ import annotations

from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory
from jagabaya.tools.parsers.common import parse_json_lines


class GobusterTool(BaseTool):
    """
    Gobuster wrapper - Directory/file brute-force tool.
    
    Gobuster is a tool used to brute-force URIs, DNS subdomains,
    virtual host names, and S3 buckets.
    
    Example:
        >>> tool = GobusterTool()
        >>> result = await tool.execute("https://example.com", wordlist="/path/to/wordlist.txt")
    """
    
    name = "gobuster"
    description = "Directory/file brute-force tool"
    category = ToolCategory.CONTENT_DISCOVERY
    binary = "gobuster"
    homepage = "https://github.com/OJ/gobuster"
    install_command = "go install github.com/OJ/gobuster/v3@latest"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build gobuster command.
        
        Args:
            target: Target URL
            mode: Scan mode (dir, dns, vhost, fuzz, s3)
            wordlist: Path to wordlist
            extensions: File extensions to search
            status_codes: Status codes to include
            exclude_status: Status codes to exclude
            threads: Number of threads
            timeout: Request timeout
            follow_redirect: Follow redirects
            no_error: Don't show errors
            expanded: Expanded mode (full URLs)
            add_slash: Add trailing slash
        """
        args = []
        
        # Mode
        mode = kwargs.get("mode", "dir")
        args.append(mode)
        
        # Target URL
        args.extend(["-u", target])
        
        # Wordlist
        wordlist = kwargs.get("wordlist")
        if wordlist:
            args.extend(["-w", wordlist])
        else:
            # Default wordlist locations
            import os
            default_wordlists = [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
            ]
            for wl in default_wordlists:
                if os.path.exists(wl):
                    args.extend(["-w", wl])
                    break
        
        # Output format - JSON for parsing (if supported by version)
        args.extend(["-o", "-", "--no-progress"])
        
        # Quiet mode
        args.append("-q")
        
        # Extensions
        extensions = kwargs.get("extensions")
        if extensions:
            if isinstance(extensions, list):
                extensions = ",".join(extensions)
            args.extend(["-x", extensions])
        
        # Status codes
        status_codes = kwargs.get("status_codes")
        if status_codes:
            if isinstance(status_codes, list):
                status_codes = ",".join(map(str, status_codes))
            args.extend(["-s", status_codes])
        
        # Exclude status codes
        exclude_status = kwargs.get("exclude_status")
        if exclude_status:
            if isinstance(exclude_status, list):
                exclude_status = ",".join(map(str, exclude_status))
            args.extend(["-b", exclude_status])
        
        # Threads
        threads = kwargs.get("threads", 10)
        args.extend(["-t", str(threads)])
        
        # Timeout
        timeout = kwargs.get("timeout", 10)
        args.extend(["--timeout", f"{timeout}s"])
        
        # Follow redirects
        if kwargs.get("follow_redirect"):
            args.append("-r")
        
        # No error display
        if kwargs.get("no_error", True):
            args.append("--no-error")
        
        # Expanded mode
        if kwargs.get("expanded"):
            args.append("-e")
        
        # Add slash
        if kwargs.get("add_slash"):
            args.append("-f")
        
        # User agent
        user_agent = kwargs.get("user_agent")
        if user_agent:
            args.extend(["-a", user_agent])
        
        # Cookies
        cookies = kwargs.get("cookies")
        if cookies:
            args.extend(["-c", cookies])
        
        # Headers
        headers = kwargs.get("headers")
        if headers:
            if isinstance(headers, dict):
                for key, value in headers.items():
                    args.extend(["-H", f"{key}: {value}"])
            elif isinstance(headers, list):
                for header in headers:
                    args.extend(["-H", header])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse gobuster output."""
        result = {
            "discovered": [],
            "by_status": {},
            "directories": [],
            "files": [],
            "total": 0,
        }
        
        # Try JSON first
        entries = parse_json_lines(output)
        
        if entries:
            for entry in entries:
                discovered = {
                    "path": entry.get("path") or entry.get("url"),
                    "status": entry.get("status"),
                    "length": entry.get("length") or entry.get("size"),
                    "redirect": entry.get("redirect") or entry.get("redirectlocation"),
                }
                result["discovered"].append(discovered)
        else:
            # Parse text output
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("="):
                    continue
                
                # Parse lines like: /admin (Status: 200) [Size: 1234]
                import re
                match = re.match(
                    r'^(/[^\s]*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?',
                    line
                )
                if match:
                    discovered = {
                        "path": match.group(1),
                        "status": int(match.group(2)),
                        "length": int(match.group(3)) if match.group(3) else None,
                    }
                    result["discovered"].append(discovered)
                elif line.startswith("/"):
                    # Simple path output
                    result["discovered"].append({"path": line.split()[0]})
        
        # Categorize results
        for item in result["discovered"]:
            status = item.get("status")
            path = item.get("path", "")
            
            # By status code
            if status:
                status_key = str(status)
                if status_key not in result["by_status"]:
                    result["by_status"][status_key] = []
                result["by_status"][status_key].append(item)
            
            # Directories vs files
            if path.endswith("/") or "." not in path.split("/")[-1]:
                result["directories"].append(item)
            else:
                result["files"].append(item)
        
        result["total"] = len(result["discovered"])
        
        return result

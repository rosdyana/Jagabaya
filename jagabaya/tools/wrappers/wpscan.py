"""
WPScan - WordPress vulnerability scanner.
"""

from __future__ import annotations

import json
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class WPScanTool(BaseTool):
    """
    WPScan wrapper - WordPress security scanner.
    
    WPScan scans WordPress installations for known vulnerabilities,
    enumerates users, plugins, themes, and more.
    
    Example:
        >>> tool = WPScanTool()
        >>> result = await tool.execute("https://example.com")
    """
    
    name = "wpscan"
    description = "WordPress vulnerability scanner"
    category = ToolCategory.CMS
    binary = "wpscan"
    homepage = "https://wpscan.com"
    install_command = "gem install wpscan"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build wpscan command.
        
        Args:
            target: Target WordPress URL
            api_token: WPScan API token
            enumerate: Enumeration options (u, p, t, etc.)
            plugins_detection: Plugin detection mode (passive, aggressive, mixed)
            themes_detection: Theme detection mode
            users_detection: User detection mode
            passwords: Password file for brute force
            usernames: Username file for brute force
            max_threads: Maximum threads
            stealthy: Stealthy mode
            random_user_agent: Use random User-Agent
        """
        args = []
        
        # Target URL
        args.extend(["--url", target])
        
        # Output format - JSON
        args.extend(["-f", "json", "-o", "-"])
        
        # No banner
        args.append("--no-banner")
        
        # API token
        api_token = kwargs.get("api_token")
        if api_token:
            args.extend(["--api-token", api_token])
        
        # Enumeration
        enumerate = kwargs.get("enumerate")
        if enumerate:
            if isinstance(enumerate, list):
                enumerate = ",".join(enumerate)
            args.extend(["-e", enumerate])
        
        # Detection modes
        plugins_detection = kwargs.get("plugins_detection")
        if plugins_detection:
            args.extend(["--plugins-detection", plugins_detection])
        
        themes_detection = kwargs.get("themes_detection")
        if themes_detection:
            args.extend(["--themes-detection", themes_detection])
        
        # Password brute force
        passwords = kwargs.get("passwords")
        if passwords:
            args.extend(["-P", passwords])
        
        usernames = kwargs.get("usernames")
        if usernames:
            args.extend(["-U", usernames])
        
        # Max threads
        max_threads = kwargs.get("max_threads", 5)
        args.extend(["-t", str(max_threads)])
        
        # Stealthy
        if kwargs.get("stealthy"):
            args.append("--stealthy")
        
        # Random User-Agent
        if kwargs.get("random_user_agent"):
            args.append("--random-user-agent")
        
        # Force (skip prompt)
        args.append("--force")
        
        # Disable TLS checks
        if kwargs.get("disable_tls_checks"):
            args.append("--disable-tls-checks")
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse wpscan JSON output."""
        result = {
            "target": {},
            "version": None,
            "theme": None,
            "plugins": [],
            "users": [],
            "vulnerabilities": [],
            "interesting_findings": [],
            "total_vulnerabilities": 0,
        }
        
        try:
            data = json.loads(output)
            
            # Target info
            if "target_url" in data:
                result["target"]["url"] = data["target_url"]
            if "target_ip" in data:
                result["target"]["ip"] = data["target_ip"]
            if "effective_url" in data:
                result["target"]["effective_url"] = data["effective_url"]
            
            # WordPress version
            version_info = data.get("version", {})
            if version_info:
                result["version"] = {
                    "number": version_info.get("number"),
                    "status": version_info.get("status"),
                    "found_by": version_info.get("found_by"),
                    "interesting_entries": version_info.get("interesting_entries", []),
                }
                
                # Version vulnerabilities
                for vuln in version_info.get("vulnerabilities", []):
                    result["vulnerabilities"].append({
                        "title": vuln.get("title"),
                        "type": "core",
                        "fixed_in": vuln.get("fixed_in"),
                        "references": vuln.get("references", {}),
                        "cvss": vuln.get("cvss"),
                    })
            
            # Theme
            main_theme = data.get("main_theme", {})
            if main_theme:
                result["theme"] = {
                    "slug": main_theme.get("slug"),
                    "location": main_theme.get("location"),
                    "version": main_theme.get("version", {}).get("number"),
                    "style_uri": main_theme.get("style_uri"),
                    "author": main_theme.get("author"),
                }
                
                # Theme vulnerabilities
                for vuln in main_theme.get("vulnerabilities", []):
                    result["vulnerabilities"].append({
                        "title": vuln.get("title"),
                        "type": "theme",
                        "component": main_theme.get("slug"),
                        "fixed_in": vuln.get("fixed_in"),
                        "references": vuln.get("references", {}),
                    })
            
            # Plugins
            plugins = data.get("plugins", {})
            for plugin_slug, plugin_info in plugins.items():
                plugin_data = {
                    "slug": plugin_slug,
                    "location": plugin_info.get("location"),
                    "version": plugin_info.get("version", {}).get("number"),
                    "found_by": plugin_info.get("found_by"),
                    "vulnerability_count": len(plugin_info.get("vulnerabilities", [])),
                }
                result["plugins"].append(plugin_data)
                
                # Plugin vulnerabilities
                for vuln in plugin_info.get("vulnerabilities", []):
                    result["vulnerabilities"].append({
                        "title": vuln.get("title"),
                        "type": "plugin",
                        "component": plugin_slug,
                        "fixed_in": vuln.get("fixed_in"),
                        "references": vuln.get("references", {}),
                    })
            
            # Users
            users = data.get("users", {})
            for username, user_info in users.items():
                result["users"].append({
                    "username": username,
                    "id": user_info.get("id"),
                    "found_by": user_info.get("found_by"),
                })
            
            # Interesting findings
            for finding in data.get("interesting_findings", []):
                result["interesting_findings"].append({
                    "url": finding.get("url"),
                    "type": finding.get("type"),
                    "to_s": finding.get("to_s"),
                    "found_by": finding.get("found_by"),
                    "interesting_entries": finding.get("interesting_entries", []),
                })
            
            result["total_vulnerabilities"] = len(result["vulnerabilities"])
            
        except json.JSONDecodeError as e:
            result["error"] = f"Failed to parse JSON: {e}"
            result["raw"] = output[:1000]
        
        return result

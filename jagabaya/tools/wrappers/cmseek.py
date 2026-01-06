"""
CMSeeK - CMS detection and exploitation tool.
"""

from __future__ import annotations

import json
import os
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class CMSeekTool(BaseTool):
    """
    CMSeeK wrapper - CMS Detection and Exploitation suite.
    
    CMSeeK detects CMS (Content Management System) and enumerates
    users, plugins, themes, and more.
    
    Example:
        >>> tool = CMSeekTool()
        >>> result = await tool.execute("https://example.com")
    """
    
    name = "cmseek"
    description = "CMS detection and exploitation tool"
    category = ToolCategory.CMS
    binary = "cmseek"
    homepage = "https://github.com/Tuhinshubhra/CMSeeK"
    install_command = "pip install cmseek / git clone https://github.com/Tuhinshubhra/CMSeeK"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build cmseek command.
        
        Args:
            target: Target URL
            follow_redirect: Follow redirects
            no_redirect: Don't follow redirects
            user_agent: Custom User-Agent
            random_agent: Use random User-Agent
            verbosity: Verbosity level (1-4)
            batch: Batch mode (no prompts)
        """
        args = []
        
        # Target URL
        args.extend(["-u", target])
        
        # Follow redirects
        if kwargs.get("follow_redirect"):
            args.append("--follow-redirect")
        elif kwargs.get("no_redirect"):
            args.append("--no-redirect")
        
        # User agent
        user_agent = kwargs.get("user_agent")
        if user_agent:
            args.extend(["--user-agent", user_agent])
        elif kwargs.get("random_agent"):
            args.append("--random-agent")
        
        # Verbosity
        verbosity = kwargs.get("verbosity")
        if verbosity:
            args.extend(["--verbose", str(verbosity)])
        
        # Batch mode
        if kwargs.get("batch", True):
            args.append("--batch")
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse cmseek output."""
        result = {
            "cms_detected": None,
            "cms_name": None,
            "cms_version": None,
            "cms_url": None,
            "detection_method": None,
            "plugins": [],
            "themes": [],
            "users": [],
            "vulnerabilities": [],
            "deep_scan": {},
            "total": 0,
        }
        
        # CMSeeK outputs JSON to a result file, but we'll try to parse console output
        lines = output.strip().split("\n")
        
        for line in lines:
            line = line.strip()
            
            # CMS Detection
            if "CMS Detected" in line or "detected" in line.lower():
                if "WordPress" in line:
                    result["cms_detected"] = True
                    result["cms_name"] = "WordPress"
                elif "Joomla" in line:
                    result["cms_detected"] = True
                    result["cms_name"] = "Joomla"
                elif "Drupal" in line:
                    result["cms_detected"] = True
                    result["cms_name"] = "Drupal"
                elif "Magento" in line:
                    result["cms_detected"] = True
                    result["cms_name"] = "Magento"
                elif "Shopify" in line:
                    result["cms_detected"] = True
                    result["cms_name"] = "Shopify"
            
            # Version detection
            if "Version" in line:
                import re
                version_match = re.search(r'Version[:\s]+([0-9.]+)', line, re.IGNORECASE)
                if version_match:
                    result["cms_version"] = version_match.group(1)
            
            # Plugin detection
            if "Plugin" in line or "plugin" in line:
                result["plugins"].append(line)
            
            # Theme detection
            if "Theme" in line or "theme" in line:
                result["themes"].append(line)
            
            # User detection
            if "User" in line or "user" in line:
                result["users"].append(line)
            
            # Vulnerabilities
            if "vulnerable" in line.lower() or "CVE-" in line:
                result["vulnerabilities"].append(line)
        
        # Try to read JSON result file if it exists
        try:
            # CMSeeK typically saves results in Result/<domain>/cms.json
            result_files = []
            result_dir = os.path.expanduser("~/.cmseek/Result")
            if os.path.exists(result_dir):
                for root, dirs, files in os.walk(result_dir):
                    for f in files:
                        if f == "cms.json":
                            result_files.append(os.path.join(root, f))
            
            if result_files:
                # Get most recent file
                result_files.sort(key=os.path.getmtime, reverse=True)
                with open(result_files[0]) as f:
                    json_data = json.load(f)
                    result["cms_detected"] = json_data.get("cms_detected", result["cms_detected"])
                    result["cms_name"] = json_data.get("cms_name") or json_data.get("cms_id", result["cms_name"])
                    result["cms_version"] = json_data.get("cms_version", result["cms_version"])
                    result["cms_url"] = json_data.get("cms_url", result["cms_url"])
                    result["detection_method"] = json_data.get("detection_method")
                    result["deep_scan"] = json_data.get("deep_scan", {})
        except Exception:
            pass
        
        result["total"] = len(result["vulnerabilities"])
        
        return result

"""
Nuclei - Fast vulnerability scanner.
"""

from __future__ import annotations

from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory
from jagabaya.tools.parsers.common import parse_json_lines


class NucleiTool(BaseTool):
    """
    Nuclei wrapper - Fast and customizable vulnerability scanner.
    
    Nuclei is a fast scanner that sends requests based on templates
    to detect security vulnerabilities.
    
    Example:
        >>> tool = NucleiTool()
        >>> result = await tool.execute("https://example.com", templates=["cves"])
    """
    
    name = "nuclei"
    description = "Fast template-based vulnerability scanner"
    category = ToolCategory.VULNERABILITY
    binary = "nuclei"
    homepage = "https://github.com/projectdiscovery/nuclei"
    install_command = "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build nuclei command.
        
        Args:
            target: Target URL
            templates: Template directories or files
            tags: Tags to include
            exclude_tags: Tags to exclude
            severity: Severity levels (info, low, medium, high, critical)
            rate_limit: Requests per second
            bulk_size: Bulk size for parallel requests
            concurrency: Number of concurrent templates
            headless: Enable headless browser
            new_templates: Only run new templates
            automatic_scan: Enable automatic web scan
        """
        args = []
        
        # Output format - JSON
        args.extend(["-json", "-silent"])
        
        # Target
        args.extend(["-u", target])
        
        # Templates
        templates = kwargs.get("templates")
        if templates:
            if isinstance(templates, list):
                for t in templates:
                    args.extend(["-t", t])
            else:
                args.extend(["-t", templates])
        
        # Template tags
        tags = kwargs.get("tags")
        if tags:
            if isinstance(tags, list):
                tags = ",".join(tags)
            args.extend(["-tags", tags])
        
        # Exclude tags
        exclude_tags = kwargs.get("exclude_tags")
        if exclude_tags:
            if isinstance(exclude_tags, list):
                exclude_tags = ",".join(exclude_tags)
            args.extend(["-exclude-tags", exclude_tags])
        
        # Severity filter
        severity = kwargs.get("severity")
        if severity:
            if isinstance(severity, list):
                severity = ",".join(severity)
            args.extend(["-severity", severity])
        
        # Rate limiting
        rate_limit = kwargs.get("rate_limit", 150)
        args.extend(["-rate-limit", str(rate_limit)])
        
        # Bulk size
        bulk_size = kwargs.get("bulk_size")
        if bulk_size:
            args.extend(["-bulk-size", str(bulk_size)])
        
        # Concurrency
        concurrency = kwargs.get("concurrency")
        if concurrency:
            args.extend(["-c", str(concurrency)])
        
        # Headless
        if kwargs.get("headless"):
            args.append("-headless")
        
        # New templates only
        if kwargs.get("new_templates"):
            args.append("-new-templates")
        
        # Automatic scan mode
        if kwargs.get("automatic_scan"):
            args.append("-automatic-scan")
        
        # Follow redirects
        if kwargs.get("follow_redirects", True):
            args.append("-follow-redirects")
        
        # Timeout
        timeout = kwargs.get("timeout", 10)
        args.extend(["-timeout", str(timeout)])
        
        # Retries
        retries = kwargs.get("retries", 1)
        args.extend(["-retries", str(retries)])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse nuclei JSON output."""
        result = {
            "findings": [],
            "by_severity": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": [],
                "unknown": [],
            },
            "by_template": {},
            "templates_matched": [],
            "total": 0,
        }
        
        entries = parse_json_lines(output)
        
        for entry in entries:
            finding = {
                "template_id": entry.get("template-id") or entry.get("templateID"),
                "template_name": entry.get("info", {}).get("name"),
                "severity": entry.get("info", {}).get("severity", "unknown"),
                "type": entry.get("type"),
                "host": entry.get("host"),
                "matched_at": entry.get("matched-at") or entry.get("matched"),
                "matcher_name": entry.get("matcher-name") or entry.get("matcher_name"),
                "extracted_results": entry.get("extracted-results", []),
                "curl_command": entry.get("curl-command"),
                "description": entry.get("info", {}).get("description"),
                "reference": entry.get("info", {}).get("reference", []),
                "tags": entry.get("info", {}).get("tags", []),
                "timestamp": entry.get("timestamp"),
            }
            
            # CVE and CWE info
            classification = entry.get("info", {}).get("classification", {})
            if classification:
                finding["cve_id"] = classification.get("cve-id")
                finding["cwe_id"] = classification.get("cwe-id")
                finding["cvss_score"] = classification.get("cvss-score")
                finding["cvss_metrics"] = classification.get("cvss-metrics")
            
            result["findings"].append(finding)
            
            # Categorize by severity
            severity = finding["severity"].lower()
            if severity in result["by_severity"]:
                result["by_severity"][severity].append(finding)
            else:
                result["by_severity"]["unknown"].append(finding)
            
            # Categorize by template
            template_id = finding["template_id"]
            if template_id:
                if template_id not in result["by_template"]:
                    result["by_template"][template_id] = []
                    result["templates_matched"].append(template_id)
                result["by_template"][template_id].append(finding)
        
        result["total"] = len(result["findings"])
        
        return result

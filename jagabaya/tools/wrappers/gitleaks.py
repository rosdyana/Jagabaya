"""
Gitleaks - Secret scanning tool.
"""

from __future__ import annotations

import json
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class GitleaksTool(BaseTool):
    """
    Gitleaks wrapper - Detect secrets in code repositories.
    
    Gitleaks is a SAST tool for detecting and preventing hardcoded secrets
    like passwords, API keys, and tokens in git repos.
    
    Example:
        >>> tool = GitleaksTool()
        >>> result = await tool.execute("/path/to/repo")
    """
    
    name = "gitleaks"
    description = "Secret detection tool for git repositories"
    category = ToolCategory.SECRET_SCANNING
    binary = "gitleaks"
    homepage = "https://github.com/gitleaks/gitleaks"
    install_command = "go install github.com/gitleaks/gitleaks/v8@latest"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build gitleaks command.
        
        Args:
            target: Target directory or URL
            mode: Scan mode (detect, protect)
            source: Source path (if different from target)
            config: Custom config file
            baseline: Baseline file for comparison
            redact: Redact secrets in output
            no_git: Scan without git context
            log_level: Log level (debug, info, warn, error)
            verbose: Verbose output
            max_target_megabytes: Maximum target size
        """
        args = []
        
        # Mode
        mode = kwargs.get("mode", "detect")
        args.append(mode)
        
        # Source path
        args.extend(["--source", target])
        
        # Output format - JSON to stdout
        args.extend(["--report-format", "json"])
        args.extend(["--report-path", "/dev/stdout"])
        
        # No banner
        args.append("--no-banner")
        
        # Config file
        config = kwargs.get("config")
        if config:
            args.extend(["--config", config])
        
        # Baseline
        baseline = kwargs.get("baseline")
        if baseline:
            args.extend(["--baseline-path", baseline])
        
        # Redact
        if kwargs.get("redact"):
            args.append("--redact")
        
        # No git
        if kwargs.get("no_git"):
            args.append("--no-git")
        
        # Log level
        log_level = kwargs.get("log_level")
        if log_level:
            args.extend(["--log-level", log_level])
        
        # Verbose
        if kwargs.get("verbose"):
            args.append("--verbose")
        
        # Max target size
        max_size = kwargs.get("max_target_megabytes")
        if max_size:
            args.extend(["--max-target-megabytes", str(max_size)])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse gitleaks JSON output."""
        result = {
            "secrets_found": False,
            "findings": [],
            "by_rule": {},
            "by_file": {},
            "total": 0,
        }
        
        try:
            data = json.loads(output)
            
            if isinstance(data, list):
                for finding in data:
                    secret = {
                        "description": finding.get("Description"),
                        "rule_id": finding.get("RuleID"),
                        "file": finding.get("File"),
                        "secret": finding.get("Secret"),
                        "match": finding.get("Match"),
                        "start_line": finding.get("StartLine"),
                        "end_line": finding.get("EndLine"),
                        "start_column": finding.get("StartColumn"),
                        "end_column": finding.get("EndColumn"),
                        "commit": finding.get("Commit"),
                        "author": finding.get("Author"),
                        "email": finding.get("Email"),
                        "date": finding.get("Date"),
                        "message": finding.get("Message"),
                        "fingerprint": finding.get("Fingerprint"),
                    }
                    result["findings"].append(secret)
                    result["secrets_found"] = True
                    
                    # Group by rule
                    rule_id = finding.get("RuleID", "unknown")
                    if rule_id not in result["by_rule"]:
                        result["by_rule"][rule_id] = []
                    result["by_rule"][rule_id].append(secret)
                    
                    # Group by file
                    file_path = finding.get("File", "unknown")
                    if file_path not in result["by_file"]:
                        result["by_file"][file_path] = []
                    result["by_file"][file_path].append(secret)
            
        except json.JSONDecodeError:
            # Empty output usually means no findings
            if not output.strip():
                result["secrets_found"] = False
            else:
                result["error"] = "Failed to parse output"
                result["raw"] = output[:1000]
        
        result["total"] = len(result["findings"])
        
        return result

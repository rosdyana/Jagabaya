"""
Trufflehog - Secret scanning tool.
"""

from __future__ import annotations

from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory
from jagabaya.tools.parsers.common import parse_json_lines


class TrufflehogTool(BaseTool):
    """
    Trufflehog wrapper - Detect secrets in repositories and more.
    
    Trufflehog finds and verifies credentials in git repositories,
    S3 buckets, filesystems, and more.
    
    Example:
        >>> tool = TrufflehogTool()
        >>> result = await tool.execute("/path/to/repo")
    """
    
    name = "trufflehog"
    description = "Secret detection and verification tool"
    category = ToolCategory.SECRET_SCANNING
    binary = "trufflehog"
    homepage = "https://github.com/trufflesecurity/trufflehog"
    install_command = "go install github.com/trufflesecurity/trufflehog/v3@latest"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build trufflehog command.
        
        Args:
            target: Target (directory, git URL, etc.)
            source_type: Source type (git, filesystem, s3, github, gitlab)
            only_verified: Only show verified credentials
            no_verification: Skip verification
            concurrency: Number of concurrent workers
            include_paths: Paths to include
            exclude_paths: Paths to exclude
            branch: Git branch to scan
            max_depth: Maximum depth for git history
        """
        args = []
        
        # Source type
        source_type = kwargs.get("source_type", "filesystem")
        args.append(source_type)
        
        # Target
        args.append(target)
        
        # Output format - JSON
        args.append("--json")
        
        # Only verified
        if kwargs.get("only_verified"):
            args.append("--only-verified")
        
        # No verification
        if kwargs.get("no_verification"):
            args.append("--no-verification")
        
        # Concurrency
        concurrency = kwargs.get("concurrency")
        if concurrency:
            args.extend(["--concurrency", str(concurrency)])
        
        # Include paths
        include_paths = kwargs.get("include_paths")
        if include_paths:
            if isinstance(include_paths, list):
                for path in include_paths:
                    args.extend(["--include-paths", path])
            else:
                args.extend(["--include-paths", include_paths])
        
        # Exclude paths
        exclude_paths = kwargs.get("exclude_paths")
        if exclude_paths:
            if isinstance(exclude_paths, list):
                for path in exclude_paths:
                    args.extend(["--exclude-paths", path])
            else:
                args.extend(["--exclude-paths", exclude_paths])
        
        # Git-specific options
        if source_type == "git":
            branch = kwargs.get("branch")
            if branch:
                args.extend(["--branch", branch])
            
            max_depth = kwargs.get("max_depth")
            if max_depth:
                args.extend(["--max-depth", str(max_depth)])
        
        # GitHub-specific options
        if source_type == "github":
            org = kwargs.get("org")
            if org:
                args.extend(["--org", org])
            
            repo = kwargs.get("repo")
            if repo:
                args.extend(["--repo", repo])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse trufflehog JSON output."""
        result = {
            "secrets_found": False,
            "findings": [],
            "verified": [],
            "unverified": [],
            "by_detector": {},
            "total": 0,
        }
        
        entries = parse_json_lines(output)
        
        for entry in entries:
            # Skip non-finding entries
            if "SourceMetadata" not in entry and "DetectorName" not in entry:
                continue
            
            finding = {
                "detector_name": entry.get("DetectorName") or entry.get("DetectorType"),
                "decoder_name": entry.get("DecoderName"),
                "verified": entry.get("Verified", False),
                "raw": entry.get("Raw"),
                "raw_v2": entry.get("RawV2"),
                "redacted": entry.get("Redacted"),
                "extra_data": entry.get("ExtraData", {}),
            }
            
            # Source metadata
            source_meta = entry.get("SourceMetadata", {})
            if source_meta:
                data = source_meta.get("Data", {})
                
                # Git source
                git_data = data.get("Git", {})
                if git_data:
                    finding["source_type"] = "git"
                    finding["file"] = git_data.get("file")
                    finding["line"] = git_data.get("line")
                    finding["commit"] = git_data.get("commit")
                    finding["email"] = git_data.get("email")
                    finding["repository"] = git_data.get("repository")
                    finding["timestamp"] = git_data.get("timestamp")
                
                # Filesystem source
                filesystem_data = data.get("Filesystem", {})
                if filesystem_data:
                    finding["source_type"] = "filesystem"
                    finding["file"] = filesystem_data.get("file")
                    finding["line"] = filesystem_data.get("line")
            
            result["findings"].append(finding)
            result["secrets_found"] = True
            
            # Categorize by verification status
            if finding.get("verified"):
                result["verified"].append(finding)
            else:
                result["unverified"].append(finding)
            
            # Group by detector
            detector = finding.get("detector_name", "unknown")
            if detector not in result["by_detector"]:
                result["by_detector"][detector] = []
            result["by_detector"][detector].append(finding)
        
        result["total"] = len(result["findings"])
        
        return result

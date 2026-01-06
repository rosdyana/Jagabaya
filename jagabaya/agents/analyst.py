"""
Analyst agent.

The Analyst agent is responsible for analyzing tool output,
extracting findings, and identifying security issues.
"""

from __future__ import annotations

from typing import Any

from jagabaya.agents.base import BaseAgent
from jagabaya.llm.prompts.analyst import (
    ANALYST_SYSTEM_PROMPT,
    ANALYSIS_PROMPT,
)
from jagabaya.llm.structured import FindingAnalysis, FindingDetail, AssetDetail
from jagabaya.models.session import SessionState
from jagabaya.models.config import LLMConfig
from jagabaya.models.tools import ToolResult
from jagabaya.models.findings import Finding, FindingSeverity, FindingCategory


class AnalystAgent(BaseAgent[FindingAnalysis]):
    """
    Security findings analysis agent.
    
    The Analyst examines tool output and extracts:
    - Security vulnerabilities
    - Misconfigurations
    - Information disclosures
    - Discovered assets
    
    Example:
        >>> analyst = AnalystAgent(llm_config)
        >>> analysis = await analyst.run(
        ...     state,
        ...     tool_result=nmap_result,
        ... )
        >>> for finding in analysis.findings:
        ...     print(f"{finding.severity}: {finding.title}")
    """
    
    name = "analyst"
    description = "Security finding extraction and analysis"
    
    def __init__(
        self,
        config: LLMConfig,
        verbose: bool = False,
    ):
        """
        Initialize the Analyst agent.
        
        Args:
            config: LLM configuration
            verbose: Enable verbose logging
        """
        super().__init__(config, verbose)
    
    @property
    def system_prompt(self) -> str:
        return ANALYST_SYSTEM_PROMPT
    
    async def run(
        self,
        state: SessionState,
        tool_result: ToolResult | None = None,
        raw_output: str | None = None,
        tool_name: str | None = None,
        **kwargs: Any,
    ) -> FindingAnalysis:
        """
        Analyze tool output and extract findings.
        
        Args:
            state: Current session state
            tool_result: Result from tool execution
            raw_output: Raw output to analyze (if no tool_result)
            tool_name: Name of the tool (if raw_output provided)
            **kwargs: Additional arguments
        
        Returns:
            FindingAnalysis with extracted findings and assets
        """
        if tool_result:
            output = tool_result.raw_output
            tool = tool_result.tool
            target = tool_result.target
            parsed = tool_result.parsed
        else:
            output = raw_output or ""
            tool = tool_name or "unknown"
            target = state.target
            parsed = {}
        
        self.log(f"Analyzing output from: {tool}")
        self.log(f"Output length: {len(output)} characters")
        
        # Build the analysis prompt
        prompt = ANALYSIS_PROMPT.format(
            tool=tool,
            target=target,
            output=self._truncate_output(output),
            parsed_data=self._format_parsed(parsed),
            existing_findings=self._format_existing_findings(state),
        )
        
        # Get structured analysis from LLM
        analysis = await self._complete_structured(
            prompt,
            FindingAnalysis,
        )
        
        self.log(f"Found {len(analysis.findings)} findings")
        self.log(f"Discovered {len(analysis.assets_discovered)} assets")
        
        return analysis
    
    async def analyze_and_create_findings(
        self,
        state: SessionState,
        tool_result: ToolResult,
    ) -> list[Finding]:
        """
        Analyze tool output and create Finding objects.
        
        Args:
            state: Current session state
            tool_result: Result from tool execution
        
        Returns:
            List of Finding objects
        """
        analysis = await self.run(state, tool_result=tool_result)
        
        findings = []
        for detail in analysis.findings:
            finding = self._convert_to_finding(detail, tool_result)
            findings.append(finding)
        
        return findings
    
    async def correlate_findings(
        self,
        state: SessionState,
    ) -> dict[str, Any]:
        """
        Correlate findings across multiple tools and identify patterns.
        
        Args:
            state: Current session state
        
        Returns:
            Correlation analysis results
        """
        if not state.findings:
            return {"correlations": [], "attack_paths": []}
        
        prompt = f"""Analyze these security findings and identify correlations:

## Findings
{self._format_all_findings(state)}

## Discovered Assets
{self._format_assets(state)}

Identify:
1. Related findings that together indicate a larger issue
2. Potential attack paths
3. Priority targets for further testing
4. Overall security posture assessment
"""
        
        result = await self._complete_json(prompt)
        
        return result
    
    def _truncate_output(self, output: str, max_length: int = 50000) -> str:
        """Truncate output if too long for LLM context."""
        if len(output) <= max_length:
            return output
        
        # Keep beginning and end
        half = max_length // 2
        return f"{output[:half]}\n\n... [TRUNCATED {len(output) - max_length} characters] ...\n\n{output[-half:]}"
    
    def _format_parsed(self, parsed: dict[str, Any]) -> str:
        """Format parsed data for the prompt."""
        if not parsed:
            return "No structured data available"
        
        import json
        try:
            return json.dumps(parsed, indent=2, default=str)[:10000]
        except Exception:
            return str(parsed)[:10000]
    
    def _format_existing_findings(self, state: SessionState) -> str:
        """Format existing findings to avoid duplicates."""
        if not state.findings:
            return "No existing findings"
        
        lines = []
        for finding in state.findings[-20:]:  # Last 20 findings
            lines.append(f"- [{finding.severity.value}] {finding.title}")
        
        return "\n".join(lines)
    
    def _format_all_findings(self, state: SessionState) -> str:
        """Format all findings for correlation analysis."""
        if not state.findings:
            return "No findings"
        
        lines = []
        for i, finding in enumerate(state.findings):
            lines.append(
                f"{i+1}. [{finding.severity.value.upper()}] {finding.title}\n"
                f"   Target: {finding.target}\n"
                f"   Tool: {finding.tool}\n"
                f"   Description: {finding.description[:200]}..."
            )
        
        return "\n\n".join(lines)
    
    def _format_assets(self, state: SessionState) -> str:
        """Format discovered assets."""
        if not state.discovered_assets:
            return "No discovered assets"
        
        by_type: dict[str, list] = {}
        for asset in state.discovered_assets:
            if asset.type not in by_type:
                by_type[asset.type] = []
            by_type[asset.type].append(asset.value)
        
        lines = []
        for asset_type, values in by_type.items():
            lines.append(f"- {asset_type}: {', '.join(values[:20])}")
        
        return "\n".join(lines)
    
    def _convert_to_finding(
        self,
        detail: FindingDetail,
        tool_result: ToolResult,
    ) -> Finding:
        """
        Convert a FindingDetail to a Finding object.
        
        Args:
            detail: Finding detail from analysis
            tool_result: Tool result that produced the finding
        
        Returns:
            Finding object
        """
        # Map severity
        try:
            severity = FindingSeverity(detail.severity)
        except ValueError:
            severity = FindingSeverity.INFO
        
        # Guess category from title/description
        category = self._guess_category(detail.title, detail.description)
        
        return Finding(
            title=detail.title,
            description=detail.description,
            severity=severity,
            category=category,
            target=detail.target or tool_result.target,
            port=detail.port,
            tool=tool_result.tool,
            evidence=detail.evidence,
            remediation=detail.remediation,
            cvss_score=detail.cvss_score,
            cve_ids=detail.cve_ids,
            false_positive_likelihood=detail.false_positive_likelihood,
        )
    
    def _guess_category(self, title: str, description: str) -> FindingCategory:
        """Guess the finding category from title and description."""
        text = f"{title} {description}".lower()
        
        if "sql" in text and "injection" in text:
            return FindingCategory.SQL_INJECTION
        elif "xss" in text or "cross-site scripting" in text:
            return FindingCategory.XSS
        elif "ssl" in text or "tls" in text or "certificate" in text:
            return FindingCategory.SSL_TLS_ISSUE
        elif "authentication" in text or "auth" in text:
            return FindingCategory.AUTHENTICATION
        elif "authorization" in text or "access control" in text:
            return FindingCategory.AUTHORIZATION
        elif "information" in text and ("disclosure" in text or "leak" in text):
            return FindingCategory.INFORMATION_DISCLOSURE
        elif "misconfiguration" in text or "default" in text:
            return FindingCategory.MISCONFIGURATION
        elif "outdated" in text or "version" in text or "cve" in text:
            return FindingCategory.OUTDATED_SOFTWARE
        elif "sensitive" in text and "file" in text:
            return FindingCategory.SENSITIVE_FILE_EXPOSURE
        elif "header" in text:
            return FindingCategory.SECURITY_HEADER_MISSING
        elif "cors" in text:
            return FindingCategory.CORS_MISCONFIGURATION
        elif "ssrf" in text:
            return FindingCategory.SSRF
        elif "xxe" in text:
            return FindingCategory.XXE
        elif "file" in text and ("upload" in text or "inclusion" in text):
            return FindingCategory.FILE_INCLUSION
        elif "command" in text and "injection" in text:
            return FindingCategory.COMMAND_INJECTION
        elif "directory" in text or "path" in text:
            return FindingCategory.DIRECTORY_TRAVERSAL
        elif "open" in text and "redirect" in text:
            return FindingCategory.OPEN_REDIRECT
        elif "csrf" in text:
            return FindingCategory.CSRF
        else:
            return FindingCategory.OTHER

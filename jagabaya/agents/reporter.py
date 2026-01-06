"""
Reporter agent.

The Reporter agent is responsible for generating comprehensive
security assessment reports from the collected findings.
"""

from __future__ import annotations

from typing import Any

from jagabaya.agents.base import BaseAgent
from jagabaya.llm.prompts.reporter import (
    REPORTER_SYSTEM_PROMPT,
    EXECUTIVE_SUMMARY_PROMPT,
    FINDING_DETAIL_PROMPT,
    RECOMMENDATIONS_PROMPT,
)
from jagabaya.llm.structured import ExecutiveSummary, ReportSection
from jagabaya.models.session import SessionState
from jagabaya.models.config import LLMConfig


class ReporterAgent(BaseAgent[ReportSection]):
    """
    Security report generation agent.
    
    The Reporter creates comprehensive reports including:
    - Executive summary
    - Detailed findings
    - Risk analysis
    - Recommendations
    
    Example:
        >>> reporter = ReporterAgent(llm_config)
        >>> summary = await reporter.generate_executive_summary(state)
        >>> print(summary.overview)
        >>> print(summary.risk_rating)
    """
    
    name = "reporter"
    description = "Security assessment report generation"
    
    def __init__(
        self,
        config: LLMConfig,
        client_name: str = "Target Organization",
        assessment_type: str = "Penetration Test",
        verbose: bool = False,
    ):
        """
        Initialize the Reporter agent.
        
        Args:
            config: LLM configuration
            client_name: Name of the client/organization
            assessment_type: Type of assessment
            verbose: Enable verbose logging
        """
        super().__init__(config, verbose)
        self.client_name = client_name
        self.assessment_type = assessment_type
    
    @property
    def system_prompt(self) -> str:
        return REPORTER_SYSTEM_PROMPT
    
    async def run(
        self,
        state: SessionState,
        section: str = "all",
        **kwargs: Any,
    ) -> ReportSection:
        """
        Generate a report section.
        
        Args:
            state: Current session state
            section: Section to generate (executive, findings, recommendations, all)
            **kwargs: Additional arguments
        
        Returns:
            ReportSection with generated content
        """
        self.log(f"Generating report section: {section}")
        
        if section == "executive":
            summary = await self.generate_executive_summary(state)
            return ReportSection(
                title="Executive Summary",
                content=self._format_executive_summary(summary),
            )
        elif section == "findings":
            return await self.generate_findings_section(state)
        elif section == "recommendations":
            return await self.generate_recommendations_section(state)
        else:
            return await self.generate_full_report(state)
    
    async def generate_executive_summary(
        self,
        state: SessionState,
    ) -> ExecutiveSummary:
        """
        Generate an executive summary.
        
        Args:
            state: Current session state
        
        Returns:
            ExecutiveSummary object
        """
        self.log("Generating executive summary")
        
        prompt = EXECUTIVE_SUMMARY_PROMPT.format(
            client_name=self.client_name,
            assessment_type=self.assessment_type,
            target=state.target,
            scope=", ".join(state.scope) if state.scope else state.target,
            findings_summary=self._format_findings_summary(state),
            duration=self._calculate_duration(state),
            tools_used=self._get_tools_used(state),
        )
        
        summary = await self._complete_structured(
            prompt,
            ExecutiveSummary,
        )
        
        return summary
    
    async def generate_findings_section(
        self,
        state: SessionState,
    ) -> ReportSection:
        """
        Generate the detailed findings section.
        
        Args:
            state: Current session state
        
        Returns:
            ReportSection with findings details
        """
        self.log("Generating findings section")
        
        subsections = []
        
        # Group findings by severity
        by_severity = self._group_findings_by_severity(state)
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            findings = by_severity.get(severity, [])
            if not findings:
                continue
            
            # Generate detail for each finding
            finding_details = []
            for finding in findings:
                detail = await self._generate_finding_detail(finding)
                finding_details.append(detail)
            
            subsections.append(ReportSection(
                title=f"{severity.upper()} Severity Findings ({len(findings)})",
                content="\n\n---\n\n".join(finding_details),
            ))
        
        return ReportSection(
            title="Detailed Findings",
            content="This section contains detailed analysis of all discovered vulnerabilities.",
            subsections=subsections,
        )
    
    async def generate_recommendations_section(
        self,
        state: SessionState,
    ) -> ReportSection:
        """
        Generate the recommendations section.
        
        Args:
            state: Current session state
        
        Returns:
            ReportSection with recommendations
        """
        self.log("Generating recommendations section")
        
        prompt = RECOMMENDATIONS_PROMPT.format(
            findings_summary=self._format_findings_summary(state),
            top_findings=self._format_top_findings(state),
        )
        
        recommendations = await self._complete(prompt)
        
        return ReportSection(
            title="Recommendations",
            content=recommendations,
        )
    
    async def generate_full_report(
        self,
        state: SessionState,
    ) -> ReportSection:
        """
        Generate a complete report.
        
        Args:
            state: Current session state
        
        Returns:
            ReportSection with full report
        """
        self.log("Generating full report")
        
        # Generate all sections
        summary = await self.generate_executive_summary(state)
        findings = await self.generate_findings_section(state)
        recommendations = await self.generate_recommendations_section(state)
        
        return ReportSection(
            title=f"Security Assessment Report - {self.client_name}",
            content=f"""
# Security Assessment Report

**Client:** {self.client_name}
**Assessment Type:** {self.assessment_type}
**Target:** {state.target}
**Date:** {state.started_at.strftime("%Y-%m-%d")}

---
""",
            subsections=[
                ReportSection(
                    title="Executive Summary",
                    content=self._format_executive_summary(summary),
                ),
                findings,
                recommendations,
                self._generate_methodology_section(),
                self._generate_scope_section(state),
            ],
        )
    
    def render_report(
        self,
        report: ReportSection,
        format: str = "markdown",
    ) -> str:
        """
        Render a report to a specific format.
        
        Args:
            report: Report section to render
            format: Output format (markdown, html)
        
        Returns:
            Rendered report string
        """
        if format == "markdown":
            return self._render_markdown(report)
        elif format == "html":
            return self._render_html(report)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _render_markdown(
        self,
        section: ReportSection,
        level: int = 1,
    ) -> str:
        """Render a section as Markdown."""
        lines = []
        
        # Title
        lines.append(f"{'#' * level} {section.title}")
        lines.append("")
        
        # Content
        if section.content:
            lines.append(section.content)
            lines.append("")
        
        # Subsections
        for subsection in section.subsections:
            lines.append(self._render_markdown(subsection, level + 1))
        
        return "\n".join(lines)
    
    def _render_html(
        self,
        section: ReportSection,
        level: int = 1,
    ) -> str:
        """Render a section as HTML."""
        lines = []
        
        # Title
        lines.append(f"<h{level}>{section.title}</h{level}>")
        
        # Content
        if section.content:
            # Convert markdown to simple HTML
            content = section.content.replace("\n\n", "</p><p>")
            content = content.replace("\n", "<br>")
            lines.append(f"<p>{content}</p>")
        
        # Subsections
        for subsection in section.subsections:
            lines.append(self._render_html(subsection, level + 1))
        
        return "\n".join(lines)
    
    async def _generate_finding_detail(self, finding: Any) -> str:
        """Generate detailed analysis for a single finding."""
        prompt = FINDING_DETAIL_PROMPT.format(
            title=finding.title,
            severity=finding.severity.value,
            description=finding.description,
            target=finding.target,
            evidence=finding.evidence,
            remediation=finding.remediation,
        )
        
        detail = await self._complete(prompt)
        
        return detail
    
    def _format_executive_summary(self, summary: ExecutiveSummary) -> str:
        """Format an ExecutiveSummary as markdown."""
        lines = []
        
        lines.append("## Overview")
        lines.append(summary.overview)
        lines.append("")
        
        lines.append("## Scope")
        lines.append(summary.scope)
        lines.append("")
        
        lines.append("## Key Findings")
        for finding in summary.key_findings:
            lines.append(f"- {finding}")
        lines.append("")
        
        lines.append(f"## Overall Risk Rating: **{summary.risk_rating.upper()}**")
        lines.append("")
        
        lines.append("## Top Recommendations")
        for rec in summary.recommendations:
            lines.append(f"- {rec}")
        lines.append("")
        
        lines.append("## Conclusion")
        lines.append(summary.conclusion)
        
        return "\n".join(lines)
    
    def _format_findings_summary(self, state: SessionState) -> str:
        """Format findings summary for prompts."""
        summary = state.get_findings_summary()
        return f"""
- Critical: {summary.critical}
- High: {summary.high}
- Medium: {summary.medium}
- Low: {summary.low}
- Informational: {summary.info}
- Total: {summary.total}
"""
    
    def _format_top_findings(self, state: SessionState) -> str:
        """Format top findings for prompts."""
        critical_high = [
            f for f in state.findings
            if f.severity.value in ["critical", "high"]
        ]
        
        if not critical_high:
            return "No critical or high severity findings."
        
        lines = []
        for finding in critical_high[:10]:
            lines.append(
                f"- [{finding.severity.value.upper()}] {finding.title}: "
                f"{finding.description[:100]}..."
            )
        
        return "\n".join(lines)
    
    def _group_findings_by_severity(self, state: SessionState) -> dict[str, list]:
        """Group findings by severity level."""
        by_severity: dict[str, list] = {}
        
        for finding in state.findings:
            severity = finding.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        return by_severity
    
    def _calculate_duration(self, state: SessionState) -> str:
        """Calculate assessment duration."""
        from datetime import datetime
        
        if state.completed_at:
            duration = state.completed_at - state.started_at
        else:
            duration = datetime.now() - state.started_at
        
        hours = int(duration.total_seconds() // 3600)
        minutes = int((duration.total_seconds() % 3600) // 60)
        
        return f"{hours}h {minutes}m"
    
    def _get_tools_used(self, state: SessionState) -> str:
        """Get list of tools used in the assessment."""
        tools = set(e.tool for e in state.tool_executions)
        return ", ".join(sorted(tools)) if tools else "None"
    
    def _generate_methodology_section(self) -> ReportSection:
        """Generate the methodology section."""
        return ReportSection(
            title="Methodology",
            content="""
This assessment was conducted using a combination of automated tools and AI-driven analysis. The methodology followed industry-standard penetration testing practices:

1. **Reconnaissance**: Information gathering using passive and active techniques
2. **Scanning**: Port and service enumeration
3. **Enumeration**: Detailed analysis of discovered services
4. **Vulnerability Analysis**: Identification of security weaknesses
5. **Reporting**: Documentation of findings and recommendations

All testing was performed within the defined scope and in accordance with the rules of engagement.
""",
        )
    
    def _generate_scope_section(self, state: SessionState) -> ReportSection:
        """Generate the scope section."""
        scope_list = state.scope if state.scope else [state.target]
        blacklist = state.blacklist if state.blacklist else []
        
        content = f"""
## In Scope
{chr(10).join(f"- {s}" for s in scope_list)}

## Out of Scope
{chr(10).join(f"- {b}" for b in blacklist) if blacklist else "No explicit exclusions"}
"""
        
        return ReportSection(
            title="Scope",
            content=content,
        )

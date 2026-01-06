"""
Correlator agent.

The Correlator agent identifies relationships between findings,
discovers attack paths, and provides holistic risk assessment.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from jagabaya.agents.base import BaseAgent
from jagabaya.llm.prompts.correlator import (
    CORRELATOR_SYSTEM_PROMPT,
    CORRELATION_PROMPT,
)
from jagabaya.llm.structured import CorrelationAnalysis, AttackPath, PriorityTarget
from jagabaya.models.session import SessionState
from jagabaya.models.config import LLMConfig
from jagabaya.models.findings import Finding, FindingSeverity


class CorrelatorAgent(BaseAgent[CorrelationAnalysis]):
    """
    Finding correlation and attack path analysis agent.
    
    The Correlator examines all findings to:
    - Identify attack chains and paths
    - Group related findings
    - Assess combined risk
    - Prioritize targets for remediation
    
    Example:
        >>> correlator = CorrelatorAgent(llm_config)
        >>> analysis = await correlator.run(state)
        >>> for path in analysis.attack_paths:
        ...     print(f"Attack path: {path.name} - Risk: {path.risk_level}")
    """
    
    name = "correlator"
    description = "Finding correlation and attack path analysis"
    
    def __init__(
        self,
        config: LLMConfig,
        verbose: bool = False,
    ):
        """
        Initialize the Correlator agent.
        
        Args:
            config: LLM configuration
            verbose: Enable verbose logging
        """
        super().__init__(config, verbose)
    
    @property
    def system_prompt(self) -> str:
        return CORRELATOR_SYSTEM_PROMPT
    
    async def run(
        self,
        state: SessionState,
        **kwargs: Any,
    ) -> CorrelationAnalysis:
        """
        Analyze findings and identify correlations.
        
        Args:
            state: Current session state with findings
            **kwargs: Additional arguments
        
        Returns:
            CorrelationAnalysis with attack paths and correlations
        """
        if not state.findings:
            self.log("No findings to correlate")
            return CorrelationAnalysis(
                attack_paths=[],
                correlated_groups=[],
                priority_targets=[],
                overall_risk_assessment="No findings to assess",
                risk_score=0.0,
                key_insights=["No security findings were discovered during the assessment"],
            )
        
        self.log(f"Correlating {len(state.findings)} findings")
        
        # Calculate duration
        duration = self._calculate_duration(state)
        
        # Format findings for analysis
        findings_by_severity = self._format_by_severity(state.findings)
        detailed_findings = self._format_detailed_findings(state.findings)
        discovered_assets = self._format_assets(state)
        tools_used = self._get_tools_used(state)
        
        prompt = CORRELATION_PROMPT.format(
            target=state.target,
            duration=duration,
            total_findings=len(state.findings),
            findings_by_severity=findings_by_severity,
            detailed_findings=detailed_findings,
            discovered_assets=discovered_assets,
            tools_used=tools_used,
        )
        
        analysis = await self._complete_structured(
            prompt,
            CorrelationAnalysis,
        )
        
        self.log(f"Identified {len(analysis.attack_paths)} attack paths")
        self.log(f"Found {len(analysis.correlated_groups)} correlated groups")
        self.log(f"Overall risk score: {analysis.risk_score}/10")
        
        return analysis
    
    async def identify_attack_paths(
        self,
        state: SessionState,
    ) -> list[AttackPath]:
        """
        Focus specifically on identifying attack paths.
        
        Args:
            state: Current session state
        
        Returns:
            List of identified attack paths
        """
        analysis = await self.run(state)
        return analysis.attack_paths
    
    async def get_priority_targets(
        self,
        state: SessionState,
        limit: int = 10,
    ) -> list[PriorityTarget]:
        """
        Get prioritized list of targets needing attention.
        
        Args:
            state: Current session state
            limit: Maximum number of targets to return
        
        Returns:
            List of priority targets
        """
        analysis = await self.run(state)
        return analysis.priority_targets[:limit]
    
    def _calculate_duration(self, state: SessionState) -> str:
        """Calculate assessment duration."""
        if state.completed_at:
            duration = state.completed_at - state.started_at
        else:
            duration = datetime.now() - state.started_at
        
        hours = int(duration.total_seconds() // 3600)
        minutes = int((duration.total_seconds() % 3600) // 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    
    def _format_by_severity(self, findings: list[Finding]) -> str:
        """Format findings summary by severity."""
        by_severity: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        for finding in findings:
            severity = finding.severity.value
            if severity in by_severity:
                by_severity[severity] += 1
        
        lines = []
        for severity, count in by_severity.items():
            if count > 0:
                lines.append(f"- **{severity.upper()}**: {count}")
        
        return "\n".join(lines) if lines else "No findings"
    
    def _format_detailed_findings(self, findings: list[Finding]) -> str:
        """Format detailed findings for correlation analysis."""
        lines = []
        
        # Group by severity for better analysis
        by_severity: dict[str, list[Finding]] = {}
        for finding in findings:
            severity = finding.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        # Format in severity order
        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity not in by_severity:
                continue
            
            lines.append(f"\n### {severity.upper()} Severity")
            
            for finding in by_severity[severity][:15]:  # Limit per severity
                port_str = f":{finding.port}" if finding.port else ""
                lines.append(
                    f"\n**{finding.title}** (ID: {finding.id})\n"
                    f"- Target: {finding.target}{port_str}\n"
                    f"- Category: {finding.category.value}\n"
                    f"- Tool: {finding.tool}\n"
                    f"- Description: {finding.description[:300]}..."
                )
                
                if finding.cve_ids:
                    lines.append(f"- CVEs: {', '.join(finding.cve_ids[:5])}")
        
        return "\n".join(lines)
    
    def _format_assets(self, state: SessionState) -> str:
        """Format discovered assets."""
        if not state.discovered_assets:
            return "No additional assets discovered"
        
        by_type: dict[str, list[str]] = {}
        for asset in state.discovered_assets:
            if asset.type not in by_type:
                by_type[asset.type] = []
            if len(by_type[asset.type]) < 20:  # Limit per type
                by_type[asset.type].append(asset.value)
        
        lines = []
        for asset_type, values in by_type.items():
            lines.append(f"- **{asset_type}**: {', '.join(values[:10])}")
            if len(values) > 10:
                lines.append(f"  ... and {len(values) - 10} more")
        
        return "\n".join(lines)
    
    def _get_tools_used(self, state: SessionState) -> str:
        """Get list of tools used."""
        tools = set(f.tool for f in state.findings)
        execution_tools = set(e.tool for e in state.tool_executions)
        all_tools = tools | execution_tools
        
        return ", ".join(sorted(all_tools)) if all_tools else "None"

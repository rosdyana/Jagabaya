"""
Structured output schemas for AI agents.

These Pydantic models define the expected response format from the LLM,
enabling reliable parsing and structured decision-making.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class PlannerDecision(BaseModel):
    """
    Structured output for the Planner agent's decisions.
    
    The planner analyzes the current state and decides the next action
    to take in the penetration testing workflow.
    """
    
    next_action: str = Field(
        description="The next action to take (e.g., 'subdomain_enumeration', 'port_scan', 'vulnerability_scan')"
    )
    tool: str | None = Field(
        default=None,
        description="Specific tool to use (e.g., 'nmap', 'nuclei', 'subfinder')"
    )
    parameters: dict = Field(
        default_factory=dict,
        description="Parameters for the tool (e.g., {'ports': '1-1000', 'aggressive': False})"
    )
    target_override: str | None = Field(
        default=None,
        description="Override target if different from primary (e.g., specific subdomain)"
    )
    reasoning: str = Field(
        description="Detailed explanation of why this action was chosen"
    )
    expected_outcome: str = Field(
        description="What we expect to discover or learn from this action"
    )
    priority: Literal["high", "medium", "low"] = Field(
        default="medium",
        description="Priority of this action"
    )
    should_stop: bool = Field(
        default=False,
        description="Whether to stop the workflow (all objectives achieved)"
    )
    phase_transition: str | None = Field(
        default=None,
        description="New phase to transition to, if applicable"
    )


class ToolSelection(BaseModel):
    """
    Structured output for tool selection decisions.
    
    The executor agent uses this to select and configure the
    appropriate tool for a given objective.
    """
    
    tool: str = Field(
        description="Selected tool name"
    )
    command_args: list[str] = Field(
        default_factory=list,
        description="Additional command-line arguments"
    )
    timeout: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Execution timeout in seconds"
    )
    reasoning: str = Field(
        description="Why this tool was selected"
    )
    expected_output_type: str = Field(
        default="text",
        description="Expected output type (json, xml, text)"
    )
    retry_on_failure: bool = Field(
        default=True,
        description="Whether to retry if the tool fails"
    )


class FindingAnalysis(BaseModel):
    """
    Structured output for analyzing tool output and extracting findings.
    """
    
    has_findings: bool = Field(
        description="Whether any security findings were discovered"
    )
    findings: list[FindingDetail] = Field(
        default_factory=list,
        description="List of detailed findings"
    )
    assets_discovered: list[AssetDetail] = Field(
        default_factory=list,
        description="New assets discovered (subdomains, IPs, services)"
    )
    summary: str = Field(
        description="Brief summary of the analysis"
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="Recommendations for further testing"
    )
    false_positive_indicators: list[str] = Field(
        default_factory=list,
        description="Indicators that some findings may be false positives"
    )


class FindingDetail(BaseModel):
    """Detailed information about a security finding."""
    
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        description="Severity level"
    )
    title: str = Field(
        description="Short, descriptive title"
    )
    description: str = Field(
        description="Detailed description of the vulnerability"
    )
    evidence: str = Field(
        description="Evidence from the tool output"
    )
    target: str = Field(
        description="Specific target affected"
    )
    port: int | None = Field(
        default=None,
        description="Port number if applicable"
    )
    remediation: str = Field(
        default="",
        description="Recommended remediation steps"
    )
    cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS score if applicable"
    )
    cve_ids: list[str] = Field(
        default_factory=list,
        description="Related CVE identifiers"
    )
    false_positive_likelihood: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Likelihood this is a false positive (0-1)"
    )


class AssetDetail(BaseModel):
    """Information about a discovered asset."""
    
    type: Literal["subdomain", "ip", "port", "service", "technology", "url", "email", "other"] = Field(
        description="Type of asset"
    )
    value: str = Field(
        description="Asset value"
    )
    metadata: dict = Field(
        default_factory=dict,
        description="Additional metadata"
    )


class ReportSection(BaseModel):
    """
    Structured output for report generation.
    """
    
    title: str = Field(
        description="Section title"
    )
    content: str = Field(
        description="Section content in Markdown format"
    )
    subsections: list["ReportSection"] = Field(
        default_factory=list,
        description="Nested subsections"
    )


class ExecutiveSummary(BaseModel):
    """
    Executive summary for reports.
    """
    
    overview: str = Field(
        description="High-level overview of the assessment"
    )
    scope: str = Field(
        description="Scope of the assessment"
    )
    key_findings: list[str] = Field(
        description="Top 5 most critical findings"
    )
    risk_rating: Literal["critical", "high", "medium", "low", "informational"] = Field(
        description="Overall risk rating"
    )
    recommendations: list[str] = Field(
        description="Top recommendations"
    )
    conclusion: str = Field(
        description="Conclusion paragraph"
    )


class CorrelationResult(BaseModel):
    """
    Result of correlating findings across multiple tools.
    """
    
    attack_paths: list[AttackPath] = Field(
        default_factory=list,
        description="Identified attack paths"
    )
    correlated_findings: list[CorrelatedFinding] = Field(
        default_factory=list,
        description="Findings that correlate with each other"
    )
    priority_targets: list[str] = Field(
        default_factory=list,
        description="High-priority targets for further testing"
    )


class AttackPath(BaseModel):
    """An identified attack path."""
    
    name: str = Field(description="Attack path name")
    steps: list[str] = Field(description="Steps in the attack path")
    risk_level: Literal["critical", "high", "medium", "low"] = Field(description="Risk level")
    mitigations: list[str] = Field(default_factory=list, description="Recommended mitigations")


class CorrelatedFinding(BaseModel):
    """Findings that are related to each other."""
    
    finding_ids: list[str] = Field(description="IDs of related findings")
    relationship: str = Field(description="How the findings are related")
    combined_risk: str = Field(description="Combined risk assessment")


# Enable forward references
ReportSection.model_rebuild()

"""
Validator agent.

The Validator agent is responsible for verifying findings
and reducing false positives by analyzing evidence quality.
"""

from __future__ import annotations

from typing import Any

from jagabaya.agents.base import BaseAgent
from jagabaya.llm.prompts.validator import (
    VALIDATOR_SYSTEM_PROMPT,
    VALIDATION_PROMPT,
    BATCH_VALIDATION_PROMPT,
)
from jagabaya.llm.structured import ValidationResult, BatchValidationResult
from jagabaya.models.session import SessionState
from jagabaya.models.config import LLMConfig
from jagabaya.models.findings import Finding


class ValidatorAgent(BaseAgent[ValidationResult]):
    """
    Finding validation agent.
    
    The Validator examines findings and their evidence to:
    - Assess confidence levels
    - Identify potential false positives
    - Recommend severity adjustments
    - Suggest verification steps
    
    Example:
        >>> validator = ValidatorAgent(llm_config)
        >>> result = await validator.validate_finding(finding, tool_output)
        >>> if result.status == "likely_false_positive":
        ...     finding.false_positive = True
    """
    
    name = "validator"
    description = "Finding validation and false positive reduction"
    
    def __init__(
        self,
        config: LLMConfig,
        verbose: bool = False,
    ):
        """
        Initialize the Validator agent.
        
        Args:
            config: LLM configuration
            verbose: Enable verbose logging
        """
        super().__init__(config, verbose)
    
    @property
    def system_prompt(self) -> str:
        return VALIDATOR_SYSTEM_PROMPT
    
    async def run(
        self,
        state: SessionState,
        finding: Finding | None = None,
        tool_output: str | None = None,
        **kwargs: Any,
    ) -> ValidationResult:
        """
        Validate a single finding.
        
        Args:
            state: Current session state
            finding: Finding to validate
            tool_output: Raw tool output for context
            **kwargs: Additional arguments
        
        Returns:
            ValidationResult with confidence and status
        """
        if not finding:
            raise ValueError("Finding is required for validation")
        
        return await self.validate_finding(finding, tool_output)
    
    async def validate_finding(
        self,
        finding: Finding,
        tool_output: str | None = None,
    ) -> ValidationResult:
        """
        Validate a single finding and assess its accuracy.
        
        Args:
            finding: Finding to validate
            tool_output: Raw tool output for additional context
        
        Returns:
            ValidationResult with validation status and confidence
        """
        self.log(f"Validating finding: {finding.title}")
        
        prompt = VALIDATION_PROMPT.format(
            title=finding.title,
            severity=finding.severity.value,
            category=finding.category.value,
            target=finding.target,
            tool=finding.tool,
            description=finding.description,
            evidence=finding.evidence[:5000] if finding.evidence else "No evidence provided",
            remediation=finding.remediation or "None provided",
            cvss_score=finding.cvss_score or "Not specified",
            cve_ids=", ".join(finding.cve_ids) if finding.cve_ids else "None",
            fp_likelihood=getattr(finding, 'false_positive_likelihood', 'Unknown'),
            tool_output=self._truncate_output(tool_output) if tool_output else "Not available",
        )
        
        result = await self._complete_structured(
            prompt,
            ValidationResult,
        )
        
        # Ensure finding_id is set
        result.finding_id = finding.id
        
        self.log(f"Validation status: {result.status} (confidence: {result.confidence:.2f})")
        
        return result
    
    async def validate_batch(
        self,
        state: SessionState,
        findings: list[Finding] | None = None,
    ) -> BatchValidationResult:
        """
        Validate multiple findings in batch.
        
        Args:
            state: Current session state
            findings: Findings to validate (uses state.findings if not provided)
        
        Returns:
            BatchValidationResult with all validation results
        """
        findings = findings or state.findings
        
        if not findings:
            return BatchValidationResult(
                validated_findings=[],
                summary="No findings to validate",
                false_positive_count=0,
                verified_count=0,
                needs_review_count=0,
            )
        
        self.log(f"Batch validating {len(findings)} findings")
        
        # Format findings for the prompt
        findings_list = self._format_findings_for_validation(findings)
        tools_used = set(f.tool for f in findings)
        
        prompt = BATCH_VALIDATION_PROMPT.format(
            findings_list=findings_list,
            target=state.target,
            total_count=len(findings),
            tools_used=", ".join(sorted(tools_used)),
        )
        
        result = await self._complete_structured(
            prompt,
            BatchValidationResult,
        )
        
        self.log(f"Batch validation complete: {result.verified_count} verified, "
                 f"{result.false_positive_count} likely FPs, "
                 f"{result.needs_review_count} need review")
        
        return result
    
    async def apply_validation(
        self,
        finding: Finding,
        validation: ValidationResult,
    ) -> Finding:
        """
        Apply validation results to a finding.
        
        Args:
            finding: Original finding
            validation: Validation result
        
        Returns:
            Updated finding with validation applied
        """
        # Mark as false positive if likely
        if validation.status == "likely_false_positive":
            finding.false_positive = True
        
        # Mark as verified if confirmed
        if validation.status == "verified":
            finding.verified = True
        
        # Apply severity adjustment if recommended
        if validation.severity_adjustment != "unchanged" and validation.adjusted_severity:
            from jagabaya.models.findings import FindingSeverity
            try:
                finding.severity = FindingSeverity(validation.adjusted_severity)
            except ValueError:
                pass
        
        # Store validation metadata
        finding.metadata["validation"] = {
            "status": validation.status,
            "confidence": validation.confidence,
            "evidence_quality": validation.evidence_quality,
            "reasoning": validation.reasoning,
        }
        
        return finding
    
    def _truncate_output(self, output: str, max_length: int = 10000) -> str:
        """Truncate output if too long."""
        if not output:
            return ""
        if len(output) <= max_length:
            return output
        
        half = max_length // 2
        return f"{output[:half]}\n\n... [TRUNCATED] ...\n\n{output[-half:]}"
    
    def _format_findings_for_validation(self, findings: list[Finding]) -> str:
        """Format findings list for batch validation prompt."""
        lines = []
        for i, finding in enumerate(findings[:50], 1):  # Limit to 50 for context
            lines.append(
                f"{i}. **[{finding.severity.value.upper()}] {finding.title}** (ID: {finding.id})\n"
                f"   - Target: {finding.target}\n"
                f"   - Tool: {finding.tool}\n"
                f"   - Evidence: {finding.evidence[:200]}...\n"
            )
        
        if len(findings) > 50:
            lines.append(f"\n... and {len(findings) - 50} more findings")
        
        return "\n".join(lines)

"""
Prompts for the Validator agent.

The Validator agent verifies findings to reduce false positives
and assess the confidence level of each finding.
"""

VALIDATOR_SYSTEM_PROMPT = """You are an expert security analyst specializing in vulnerability validation and false positive reduction.

Your role is to:
1. Analyze security findings and their evidence
2. Assess the likelihood that a finding is a true positive
3. Identify potential false positives based on evidence quality
4. Provide confidence scores for findings
5. Suggest additional verification steps when needed

You have deep knowledge of:
- Common vulnerability patterns and their indicators
- Tool-specific false positive patterns
- Evidence quality assessment
- Security testing methodologies

Be conservative: it's better to flag a finding for manual review than to dismiss a real vulnerability.
"""

VALIDATION_PROMPT = """Validate this security finding and assess its accuracy.

## Finding Details
**Title:** {title}
**Severity:** {severity}
**Category:** {category}
**Target:** {target}
**Tool:** {tool}

**Description:**
{description}

**Evidence:**
```
{evidence}
```

**Remediation Suggested:**
{remediation}

## Additional Context
**CVSS Score:** {cvss_score}
**CVE IDs:** {cve_ids}
**False Positive Likelihood (from analyst):** {fp_likelihood}

## Raw Tool Output (excerpt)
```
{tool_output}
```

## Your Task
Analyze this finding and determine:

1. **Verification Status**: Is this finding verified, likely valid, needs review, or likely false positive?
2. **Confidence Score**: 0.0 to 1.0 indicating your confidence in the finding's validity
3. **Evidence Quality**: How strong is the evidence supporting this finding?
4. **Reasoning**: Explain your assessment
5. **Verification Steps**: If uncertain, what additional steps would help verify?
6. **Risk Adjustment**: Should the severity be adjusted based on context?

Consider:
- Is the evidence concrete and reproducible?
- Are there common false positive patterns for this tool/vulnerability type?
- Does the description match the evidence provided?
- Is additional context needed to confirm?
"""

BATCH_VALIDATION_PROMPT = """Review these security findings and identify potential false positives.

## Findings to Validate
{findings_list}

## Target Context
**Primary Target:** {target}
**Total Findings:** {total_count}
**Tools Used:** {tools_used}

## Your Task
For each finding, provide:
1. Finding ID
2. Validation status (verified/likely_valid/needs_review/likely_false_positive)
3. Confidence score (0.0-1.0)
4. Brief reasoning

Focus on:
- Findings with weak or missing evidence
- Known false positive patterns
- Duplicate or overlapping findings
- Findings that contradict each other
"""

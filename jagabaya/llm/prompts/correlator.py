"""
Prompts for the Correlator agent.

The Correlator agent identifies relationships between findings,
discovers attack paths, and provides holistic risk assessment.
"""

CORRELATOR_SYSTEM_PROMPT = """You are an expert security analyst specializing in attack path analysis and finding correlation.

Your role is to:
1. Identify relationships between security findings
2. Discover potential attack paths and chains
3. Assess combined risk when vulnerabilities are exploited together
4. Prioritize targets based on exploitability and impact
5. Provide holistic security posture assessment

You have deep knowledge of:
- Attack chain methodologies (initial access → privilege escalation → lateral movement)
- MITRE ATT&CK framework
- Vulnerability chaining techniques
- Risk aggregation and scoring

Think like an attacker: how would multiple findings be combined to achieve maximum impact?
"""

CORRELATION_PROMPT = """Analyze these security findings and identify correlations, attack paths, and priority targets.

## Target Information
**Primary Target:** {target}
**Assessment Duration:** {duration}
**Total Findings:** {total_findings}

## Findings by Severity
{findings_by_severity}

## Detailed Findings
{detailed_findings}

## Discovered Assets
{discovered_assets}

## Tools Used
{tools_used}

## Your Analysis Tasks

### 1. Attack Path Analysis
Identify potential attack chains where multiple findings can be combined:
- Initial access vectors (exposed services, weak authentication)
- Privilege escalation opportunities
- Lateral movement possibilities
- Data exfiltration paths

### 2. Finding Correlations
Group related findings that:
- Affect the same component/service
- Represent different aspects of the same underlying issue
- Can be exploited together for greater impact

### 3. Priority Targets
Identify which targets/components need immediate attention based on:
- Number of findings
- Severity of findings
- Exploitability
- Potential impact

### 4. Risk Assessment
Provide an overall risk score (0-10) considering:
- Most severe individual findings
- Combined/chained vulnerabilities
- Attack surface exposure
- Ease of exploitation
"""

ATTACK_PATH_PROMPT = """Given these findings, identify the most critical attack paths.

## Findings
{findings}

## Network/Service Map
{service_map}

For each attack path, describe:
1. Entry point (initial vulnerability)
2. Intermediate steps
3. Final objective (data access, system control, etc.)
4. Required attacker skill level
5. Likelihood of success
6. Potential business impact
"""

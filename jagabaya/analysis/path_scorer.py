"""
Attack path scoring and prioritization.

Scores attack paths based on severity, exploitability, and impact.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jagabaya.analysis.attack_paths import AttackChain, PathNode

from jagabaya.models.findings import FindingSeverity


class PathScorer:
    """
    Scores attack paths for prioritization.
    
    Uses a weighted scoring system based on:
    - Severity of findings in the chain
    - Number of steps (complexity)
    - Attack type criticality
    - Presence of CVEs
    
    Example:
        >>> scorer = PathScorer()
        >>> score = scorer.score(chain)
        >>> risk_level = scorer.get_risk_level(score)
    """
    
    # Severity weights
    SEVERITY_WEIGHTS = {
        FindingSeverity.CRITICAL: 10.0,
        FindingSeverity.HIGH: 7.5,
        FindingSeverity.MEDIUM: 5.0,
        FindingSeverity.LOW: 2.5,
        FindingSeverity.INFO: 1.0,
    }
    
    # Attack type criticality multipliers
    ATTACK_TYPE_MULTIPLIERS = {
        "Remote Code Execution": 1.5,
        "SQL Injection": 1.4,
        "Command Injection": 1.4,
        "Authentication Bypass": 1.3,
        "File Inclusion to RCE": 1.4,
        "Subdomain Takeover": 1.2,
        "Man-in-the-Middle": 1.1,
        "Cross-Site Scripting Chain": 1.1,
        "Network Exploitation": 1.3,
        "Source Code Exposure": 1.2,
    }
    
    # Risk level thresholds
    RISK_THRESHOLDS = {
        "critical": 8.0,
        "high": 6.0,
        "medium": 4.0,
        "low": 0.0,
    }
    
    def __init__(self):
        """Initialize the path scorer."""
        pass
    
    def score(self, chain: "AttackChain") -> float:
        """
        Calculate overall score for an attack chain.
        
        Args:
            chain: The attack chain to score
        
        Returns:
            Score from 0.0 to 10.0
        """
        if not chain.nodes:
            return 0.0
        
        # Base score from severity of findings
        severity_score = self._calculate_severity_score(chain)
        
        # Chain length bonus (longer chains = more complex attacks)
        length_multiplier = self._calculate_length_multiplier(chain)
        
        # Attack type multiplier
        attack_multiplier = self._get_attack_multiplier(chain)
        
        # CVE presence bonus
        cve_bonus = self._calculate_cve_bonus(chain)
        
        # Calculate final score
        raw_score = (severity_score * length_multiplier * attack_multiplier) + cve_bonus
        
        # Normalize to 0-10 range
        final_score = min(10.0, max(0.0, raw_score))
        
        return round(final_score, 1)
    
    def get_risk_level(self, score: float) -> str:
        """
        Get risk level string from score.
        
        Args:
            score: Numeric score (0-10)
        
        Returns:
            Risk level: 'critical', 'high', 'medium', or 'low'
        """
        if score >= self.RISK_THRESHOLDS["critical"]:
            return "critical"
        elif score >= self.RISK_THRESHOLDS["high"]:
            return "high"
        elif score >= self.RISK_THRESHOLDS["medium"]:
            return "medium"
        return "low"
    
    def get_priority(self, chain: "AttackChain") -> int:
        """
        Get remediation priority (1-10, 1 = highest priority).
        
        Args:
            chain: The attack chain
        
        Returns:
            Priority from 1 to 10
        """
        score = chain.score if chain.score > 0 else self.score(chain)
        
        # Invert score to priority (higher score = lower priority number)
        priority = 11 - int(score)
        return max(1, min(10, priority))
    
    def _calculate_severity_score(self, chain: "AttackChain") -> float:
        """Calculate base score from finding severities."""
        if not chain.nodes:
            return 0.0
        
        severity_values: list[float] = []
        
        for node in chain.nodes:
            if node.severity:
                weight = self.SEVERITY_WEIGHTS.get(node.severity, 1.0)
                severity_values.append(weight)
        
        if not severity_values:
            return 2.0  # Default for asset-only chains
        
        # Use weighted approach: max severity + average of others
        max_severity = max(severity_values)
        
        if len(severity_values) == 1:
            return max_severity
        
        # Average of remaining
        others = [v for v in severity_values if v != max_severity]
        avg_others = sum(others) / len(others) if others else 0
        
        # Weighted combination
        return (max_severity * 0.7) + (avg_others * 0.3)
    
    def _calculate_length_multiplier(self, chain: "AttackChain") -> float:
        """
        Calculate multiplier based on chain length.
        
        Longer chains indicate more complex (and often more impactful) attacks.
        """
        length = len(chain.nodes)
        
        if length <= 1:
            return 0.8
        elif length == 2:
            return 1.0
        elif length == 3:
            return 1.1
        elif length == 4:
            return 1.15
        else:
            return 1.2  # Cap at 1.2x for very long chains
    
    def _get_attack_multiplier(self, chain: "AttackChain") -> float:
        """Get multiplier based on attack type."""
        if not chain.attack_type:
            return 1.0
        
        return self.ATTACK_TYPE_MULTIPLIERS.get(chain.attack_type, 1.0)
    
    def _calculate_cve_bonus(self, chain: "AttackChain") -> float:
        """
        Calculate bonus for chains with CVEs.
        
        Chains with CVEs are more likely to have public exploits.
        """
        # Count nodes with MITRE techniques (indicates documented attack)
        mitre_count = sum(1 for n in chain.nodes if n.mitre_technique)
        
        # Simple bonus based on presence of documented techniques
        if mitre_count > 0:
            return min(1.0, mitre_count * 0.3)
        
        return 0.0
    
    def compare(self, chain1: "AttackChain", chain2: "AttackChain") -> int:
        """
        Compare two chains for sorting.
        
        Returns:
            -1 if chain1 < chain2, 0 if equal, 1 if chain1 > chain2
        """
        score1 = chain1.score if chain1.score > 0 else self.score(chain1)
        score2 = chain2.score if chain2.score > 0 else self.score(chain2)
        
        if score1 > score2:
            return 1
        elif score1 < score2:
            return -1
        return 0

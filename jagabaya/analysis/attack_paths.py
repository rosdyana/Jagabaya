"""
Attack path discovery and analysis engine.

This module provides rule-based and LLM-assisted attack path discovery,
identifying how individual findings chain together into exploitable paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Any

from pydantic import BaseModel, Field

from jagabaya.models.findings import Finding, FindingSeverity, FindingCategory
from jagabaya.models.session import SessionState, DiscoveredAsset


class NodeType(str, Enum):
    """Types of nodes in an attack path."""
    
    ASSET = "asset"
    FINDING = "finding"
    ACTION = "action"


class PathNode(BaseModel):
    """
    A single node in an attack path.
    
    Represents either a discovered asset (subdomain, port, service)
    or a security finding that can be part of an attack chain.
    """
    
    id: str = Field(description="Unique node identifier")
    node_type: NodeType = Field(description="Type of node")
    label: str = Field(description="Short display label")
    description: str = Field(default="", description="Detailed description")
    severity: FindingSeverity | None = Field(default=None, description="Severity if finding")
    
    # Source data reference
    finding_id: str | None = Field(default=None, description="Finding ID if type is finding")
    asset_type: str | None = Field(default=None, description="Asset type if type is asset")
    asset_value: str | None = Field(default=None, description="Asset value if type is asset")
    
    # Metadata
    tool: str | None = Field(default=None, description="Tool that discovered this")
    target: str | None = Field(default=None, description="Target host/URL")
    port: int | None = Field(default=None, description="Port if applicable")
    
    # MITRE ATT&CK
    mitre_tactic: str | None = Field(default=None, description="MITRE ATT&CK tactic")
    mitre_technique: str | None = Field(default=None, description="MITRE ATT&CK technique")
    
    @classmethod
    def from_finding(cls, finding: Finding) -> "PathNode":
        """Create a node from a Finding."""
        return cls(
            id=f"f_{finding.id}",
            node_type=NodeType.FINDING,
            label=finding.title[:50],
            description=finding.description[:200],
            severity=finding.severity,
            finding_id=finding.id,
            tool=finding.tool,
            target=finding.target,
            port=finding.port,
            mitre_tactic=finding.mitre_tactics[0] if finding.mitre_tactics else None,
            mitre_technique=finding.mitre_techniques[0] if finding.mitre_techniques else None,
        )
    
    @classmethod
    def from_asset(cls, asset: DiscoveredAsset) -> "PathNode":
        """Create a node from a DiscoveredAsset."""
        return cls(
            id=f"a_{asset.type}_{hash(asset.value) % 10000}",
            node_type=NodeType.ASSET,
            label=f"{asset.type}: {asset.value[:30]}",
            description=f"{asset.type.title()} discovered by {asset.source}",
            asset_type=asset.type,
            asset_value=asset.value,
            tool=asset.source,
        )


class AttackChain(BaseModel):
    """
    A chain of connected nodes forming an attack path.
    
    Represents a sequence of findings and assets that could be
    exploited together to achieve an objective.
    """
    
    id: str = Field(description="Unique chain identifier")
    name: str = Field(description="Descriptive name for the attack path")
    description: str = Field(description="Detailed description of the attack path")
    
    # Chain structure
    nodes: list[PathNode] = Field(default_factory=list, description="Nodes in order")
    edges: list[tuple[str, str, str]] = Field(
        default_factory=list, 
        description="Edges as (from_id, to_id, relationship)"
    )
    
    # Scoring
    score: float = Field(ge=0.0, le=10.0, description="Exploitability score (0-10)")
    risk_level: Literal["critical", "high", "medium", "low"] = Field(description="Risk level")
    
    # Impact assessment
    impact: str = Field(default="", description="Potential impact if exploited")
    likelihood: Literal["high", "medium", "low"] = Field(
        default="medium",
        description="Likelihood of successful exploitation"
    )
    
    # Categorization
    attack_type: str = Field(default="", description="Type of attack (RCE, SQLi, etc.)")
    mitre_tactics: list[str] = Field(default_factory=list, description="MITRE ATT&CK tactics")
    
    # Remediation
    mitigations: list[str] = Field(default_factory=list, description="Recommended mitigations")
    priority: int = Field(default=1, ge=1, le=10, description="Remediation priority (1=highest)")
    
    @property
    def severity_counts(self) -> dict[str, int]:
        """Count findings by severity in this chain."""
        counts: dict[str, int] = {}
        for node in self.nodes:
            if node.severity:
                sev = node.severity.value
                counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    @property
    def highest_severity(self) -> FindingSeverity:
        """Get the highest severity in the chain."""
        severity_order = [
            FindingSeverity.CRITICAL,
            FindingSeverity.HIGH,
            FindingSeverity.MEDIUM,
            FindingSeverity.LOW,
            FindingSeverity.INFO,
        ]
        for sev in severity_order:
            for node in self.nodes:
                if node.severity == sev:
                    return sev
        return FindingSeverity.INFO
    
    def to_compact_string(self) -> str:
        """Get a compact one-line representation."""
        node_labels = [n.label for n in self.nodes[:4]]
        if len(self.nodes) > 4:
            node_labels.append(f"...+{len(self.nodes) - 4}")
        return " -> ".join(node_labels)


class AttackPathResult(BaseModel):
    """
    Complete result of attack path analysis.
    """
    
    chains: list[AttackChain] = Field(default_factory=list, description="Discovered attack chains")
    total_chains: int = Field(default=0, description="Total number of chains found")
    
    # Summary statistics
    critical_chains: int = Field(default=0, description="Number of critical risk chains")
    high_chains: int = Field(default=0, description="Number of high risk chains")
    medium_chains: int = Field(default=0, description="Number of medium risk chains")
    low_chains: int = Field(default=0, description="Number of low risk chains")
    
    # Analysis metadata
    analysis_method: str = Field(default="hybrid", description="Method used (rule-based, llm, hybrid)")
    findings_analyzed: int = Field(default=0, description="Number of findings analyzed")
    assets_analyzed: int = Field(default=0, description="Number of assets analyzed")
    
    # Key insights
    top_risks: list[str] = Field(default_factory=list, description="Top risk insights")
    
    def get_by_risk(self, risk_level: str) -> list[AttackChain]:
        """Get chains by risk level."""
        return [c for c in self.chains if c.risk_level == risk_level]
    
    def get_top_chains(self, limit: int = 5) -> list[AttackChain]:
        """Get top chains by score."""
        return sorted(self.chains, key=lambda c: c.score, reverse=True)[:limit]


# Rule-based chain detection patterns
CHAIN_PATTERNS = [
    {
        "name": "Subdomain Takeover",
        "pattern": [
            {"type": "asset", "asset_type": "subdomain"},
            {"type": "finding", "category": ["dns_issue", "misconfiguration"]},
        ],
        "attack_type": "Subdomain Takeover",
        "impact": "Full control of subdomain, phishing, cookie theft",
    },
    {
        "name": "RCE via Outdated Software",
        "pattern": [
            {"type": "asset", "asset_type": "technology"},
            {"type": "finding", "category": ["outdated_software", "cms_vulnerability"]},
            {"type": "finding", "has_cve": True},
        ],
        "attack_type": "Remote Code Execution",
        "impact": "Complete system compromise",
    },
    {
        "name": "SQL Injection Chain",
        "pattern": [
            {"type": "asset", "asset_type": "url"},
            {"type": "finding", "category": ["sql_injection"]},
        ],
        "attack_type": "SQL Injection",
        "impact": "Database access, data exfiltration, potential RCE",
    },
    {
        "name": "Authentication Bypass",
        "pattern": [
            {"type": "finding", "category": ["authentication", "auth_bypass", "weak_credentials"]},
            {"type": "finding", "category": ["info_disclosure", "sensitive_data"]},
        ],
        "attack_type": "Authentication Bypass",
        "impact": "Unauthorized access to sensitive functionality",
    },
    {
        "name": "XSS to Session Hijacking",
        "pattern": [
            {"type": "finding", "category": ["xss"]},
            {"type": "finding", "category": ["session_management", "security_header_missing"]},
        ],
        "attack_type": "Cross-Site Scripting Chain",
        "impact": "Session hijacking, account takeover",
    },
    {
        "name": "Information Disclosure Chain",
        "pattern": [
            {"type": "finding", "category": ["info_disclosure", "sensitive_file_exposure", "debug_enabled"]},
            {"type": "finding", "severity": ["critical", "high"]},
        ],
        "attack_type": "Information Disclosure Escalation",
        "impact": "Credential exposure leading to further compromise",
    },
    {
        "name": "Network Pivot Path",
        "pattern": [
            {"type": "asset", "asset_type": "port"},
            {"type": "finding", "category": ["network_vulnerability", "service_detected"]},
            {"type": "finding", "severity": ["critical", "high"]},
        ],
        "attack_type": "Network Exploitation",
        "impact": "Internal network access, lateral movement",
    },
    {
        "name": "SSL/TLS Weakness Chain",
        "pattern": [
            {"type": "finding", "category": ["ssl_tls_issue", "weak_cipher", "certificate_issue"]},
            {"type": "finding", "category": ["info_disclosure", "sensitive_data"]},
        ],
        "attack_type": "Man-in-the-Middle",
        "impact": "Traffic interception, credential theft",
    },
    {
        "name": "Directory Traversal to RCE",
        "pattern": [
            {"type": "finding", "category": ["directory_traversal", "lfi", "file_inclusion"]},
            {"type": "finding", "category": ["command_injection", "rfi"]},
        ],
        "attack_type": "File Inclusion to RCE",
        "impact": "Remote code execution via file inclusion",
    },
    {
        "name": "Git Exposure Chain",
        "pattern": [
            {"type": "finding", "category": ["sensitive_file_exposure", "info_disclosure"]},
            {"type": "asset", "asset_type": "technology"},
        ],
        "attack_type": "Source Code Exposure",
        "impact": "Source code access, credential discovery, vulnerability identification",
    },
]


class AttackPathEngine:
    """
    Engine for discovering and analyzing attack paths.
    
    Uses a hybrid approach combining:
    1. Rule-based pattern matching for common attack chains
    2. Graph-based analysis for finding connections
    3. Optional LLM enhancement for complex chain discovery
    
    Example:
        >>> engine = AttackPathEngine()
        >>> result = engine.analyze(session_state)
        >>> for chain in result.get_top_chains(5):
        ...     print(f"{chain.name}: {chain.score}/10")
    """
    
    def __init__(self, use_llm: bool = False, verbose: bool = False):
        """
        Initialize the attack path engine.
        
        Args:
            use_llm: Whether to use LLM for enhanced chain discovery
            verbose: Enable verbose logging
        """
        self.use_llm = use_llm
        self.verbose = verbose
        self._llm_chains: list[AttackChain] = []
    
    def log(self, message: str) -> None:
        """Log a message if verbose mode is enabled."""
        if self.verbose:
            print(f"[AttackPathEngine] {message}")
    
    def analyze(self, state: SessionState) -> AttackPathResult:
        """
        Analyze session state to discover attack paths.
        
        Args:
            state: Current session state with findings and assets
        
        Returns:
            AttackPathResult with discovered chains
        """
        if not state.findings and not state.discovered_assets:
            self.log("No findings or assets to analyze")
            return AttackPathResult(
                analysis_method="none",
                top_risks=["No security findings to analyze"],
            )
        
        self.log(f"Analyzing {len(state.findings)} findings and {len(state.discovered_assets)} assets")
        
        # Build node graph
        nodes = self._build_nodes(state)
        self.log(f"Built {len(nodes)} nodes")
        
        # Find chains using rule-based patterns
        rule_chains = self._find_rule_based_chains(state, nodes)
        self.log(f"Found {len(rule_chains)} rule-based chains")
        
        # Find chains using graph analysis
        graph_chains = self._find_graph_chains(state, nodes)
        self.log(f"Found {len(graph_chains)} graph-based chains")
        
        # Combine and deduplicate chains
        all_chains = self._merge_chains(rule_chains + graph_chains + self._llm_chains)
        self.log(f"Total unique chains: {len(all_chains)}")
        
        # Score all chains
        from jagabaya.analysis.path_scorer import PathScorer
        scorer = PathScorer()
        for chain in all_chains:
            chain.score = scorer.score(chain)
            chain.risk_level = scorer.get_risk_level(chain.score)
            chain.priority = scorer.get_priority(chain)
        
        # Sort by score
        all_chains.sort(key=lambda c: c.score, reverse=True)
        
        # Build result
        result = AttackPathResult(
            chains=all_chains,
            total_chains=len(all_chains),
            critical_chains=len([c for c in all_chains if c.risk_level == "critical"]),
            high_chains=len([c for c in all_chains if c.risk_level == "high"]),
            medium_chains=len([c for c in all_chains if c.risk_level == "medium"]),
            low_chains=len([c for c in all_chains if c.risk_level == "low"]),
            analysis_method="hybrid" if self.use_llm else "rule-based",
            findings_analyzed=len(state.findings),
            assets_analyzed=len(state.discovered_assets),
            top_risks=self._generate_top_risks(all_chains),
        )
        
        return result
    
    def set_llm_chains(self, chains: list[AttackChain]) -> None:
        """
        Set chains discovered by LLM (from CorrelatorAgent).
        
        Args:
            chains: Attack chains from LLM analysis
        """
        self._llm_chains = chains
    
    def _build_nodes(self, state: SessionState) -> dict[str, PathNode]:
        """Build a dictionary of all nodes from state."""
        nodes: dict[str, PathNode] = {}
        
        # Add finding nodes
        for finding in state.findings:
            node = PathNode.from_finding(finding)
            nodes[node.id] = node
        
        # Add asset nodes
        for asset in state.discovered_assets:
            node = PathNode.from_asset(asset)
            nodes[node.id] = node
        
        return nodes
    
    def _find_rule_based_chains(
        self, 
        state: SessionState, 
        nodes: dict[str, PathNode]
    ) -> list[AttackChain]:
        """Find chains matching predefined patterns."""
        chains: list[AttackChain] = []
        chain_counter = 0
        
        for pattern in CHAIN_PATTERNS:
            matches = self._match_pattern(state, nodes, pattern)
            
            for match_nodes in matches:
                chain_counter += 1
                chain = AttackChain(
                    id=f"chain_{chain_counter}",
                    name=pattern["name"],
                    description=f"Attack path: {pattern['name']}",
                    nodes=match_nodes,
                    edges=self._build_edges(match_nodes),
                    score=0.0,  # Will be scored later
                    risk_level="medium",  # Will be updated by scorer
                    impact=pattern.get("impact", ""),
                    attack_type=pattern.get("attack_type", ""),
                    mitigations=self._generate_mitigations(match_nodes),
                )
                chains.append(chain)
        
        return chains
    
    def _match_pattern(
        self, 
        state: SessionState, 
        nodes: dict[str, PathNode],
        pattern: dict[str, Any]
    ) -> list[list[PathNode]]:
        """Match a pattern against the current state."""
        matches: list[list[PathNode]] = []
        pattern_steps = pattern.get("pattern", [])
        
        if not pattern_steps:
            return matches
        
        # Find all nodes matching first step
        first_step = pattern_steps[0]
        first_matches = self._match_step(state, nodes, first_step)
        
        if not first_matches:
            return matches
        
        # For each first match, try to complete the chain
        for first_node in first_matches:
            chain_nodes = [first_node]
            valid_chain = True
            
            for step in pattern_steps[1:]:
                step_matches = self._match_step(state, nodes, step)
                # Find a matching node not already in chain
                found = False
                for node in step_matches:
                    if node.id not in [n.id for n in chain_nodes]:
                        # Check if related (same target or connected)
                        if self._nodes_related(chain_nodes[-1], node):
                            chain_nodes.append(node)
                            found = True
                            break
                
                if not found:
                    valid_chain = False
                    break
            
            if valid_chain and len(chain_nodes) >= 2:
                matches.append(chain_nodes)
        
        return matches
    
    def _match_step(
        self, 
        state: SessionState, 
        nodes: dict[str, PathNode],
        step: dict[str, Any]
    ) -> list[PathNode]:
        """Find all nodes matching a pattern step."""
        matching: list[PathNode] = []
        
        step_type = step.get("type")
        
        for node in nodes.values():
            # Check type match
            if step_type == "asset" and node.node_type != NodeType.ASSET:
                continue
            if step_type == "finding" and node.node_type != NodeType.FINDING:
                continue
            
            # Check asset type
            if "asset_type" in step:
                if node.asset_type != step["asset_type"]:
                    continue
            
            # Check finding category
            if "category" in step and node.finding_id:
                finding = next((f for f in state.findings if f.id == node.finding_id), None)
                if finding:
                    categories = step["category"]
                    if isinstance(categories, str):
                        categories = [categories]
                    if finding.category.value not in categories:
                        continue
                else:
                    continue
            
            # Check severity
            if "severity" in step and node.severity:
                severities = step["severity"]
                if isinstance(severities, str):
                    severities = [severities]
                if node.severity.value not in severities:
                    continue
            
            # Check for CVE
            if step.get("has_cve") and node.finding_id:
                finding = next((f for f in state.findings if f.id == node.finding_id), None)
                if not finding or not finding.cve_ids:
                    continue
            
            matching.append(node)
        
        return matching
    
    def _nodes_related(self, node1: PathNode, node2: PathNode) -> bool:
        """Check if two nodes are related (same target, port, etc.)."""
        # Same target
        if node1.target and node2.target:
            if node1.target == node2.target:
                return True
            # Subdomain relationship
            if node1.target.endswith(node2.target) or node2.target.endswith(node1.target):
                return True
        
        # Same tool often means related findings
        if node1.tool and node1.tool == node2.tool:
            return True
        
        # Asset value matches target
        if node1.asset_value and node2.target:
            if node1.asset_value in node2.target or node2.target in node1.asset_value:
                return True
        if node2.asset_value and node1.target:
            if node2.asset_value in node1.target or node1.target in node2.asset_value:
                return True
        
        # Same port
        if node1.port and node1.port == node2.port:
            return True
        
        # Default: consider related if both have no target (loose matching)
        if not node1.target and not node2.target:
            return True
        
        return False
    
    def _build_edges(self, nodes: list[PathNode]) -> list[tuple[str, str, str]]:
        """Build edges between sequential nodes."""
        edges: list[tuple[str, str, str]] = []
        
        for i in range(len(nodes) - 1):
            from_node = nodes[i]
            to_node = nodes[i + 1]
            
            # Determine relationship based on node types
            if from_node.node_type == NodeType.ASSET:
                relationship = "discovered"
            elif to_node.severity and from_node.severity:
                if self._severity_value(to_node.severity) > self._severity_value(from_node.severity):
                    relationship = "escalates to"
                else:
                    relationship = "leads to"
            else:
                relationship = "enables"
            
            edges.append((from_node.id, to_node.id, relationship))
        
        return edges
    
    def _severity_value(self, severity: FindingSeverity) -> int:
        """Convert severity to numeric value."""
        values = {
            FindingSeverity.CRITICAL: 5,
            FindingSeverity.HIGH: 4,
            FindingSeverity.MEDIUM: 3,
            FindingSeverity.LOW: 2,
            FindingSeverity.INFO: 1,
        }
        return values.get(severity, 0)
    
    def _find_graph_chains(
        self, 
        state: SessionState, 
        nodes: dict[str, PathNode]
    ) -> list[AttackChain]:
        """Find chains using graph-based analysis."""
        chains: list[AttackChain] = []
        
        # Group findings by target
        by_target: dict[str, list[PathNode]] = {}
        for node in nodes.values():
            if node.node_type == NodeType.FINDING and node.target:
                target = node.target
                if target not in by_target:
                    by_target[target] = []
                by_target[target].append(node)
        
        # For each target with multiple findings, create potential chains
        chain_counter = len(chains) + 100  # Avoid ID collision
        
        for target, target_nodes in by_target.items():
            if len(target_nodes) < 2:
                continue
            
            # Sort by severity (highest first)
            target_nodes.sort(
                key=lambda n: self._severity_value(n.severity) if n.severity else 0,
                reverse=True
            )
            
            # Check if there's a severity escalation path
            if len(target_nodes) >= 2:
                chain_counter += 1
                
                # Take top 4 nodes for the chain
                chain_nodes = target_nodes[:4]
                
                chain = AttackChain(
                    id=f"chain_{chain_counter}",
                    name=f"Multi-vulnerability Chain ({target})",
                    description=f"Multiple vulnerabilities on {target} that may be chained",
                    nodes=chain_nodes,
                    edges=self._build_edges(chain_nodes),
                    score=0.0,
                    risk_level="medium",
                    impact="Combined exploitation of multiple vulnerabilities",
                    attack_type="Chained Exploitation",
                    mitigations=self._generate_mitigations(chain_nodes),
                )
                chains.append(chain)
        
        return chains
    
    def _merge_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Merge and deduplicate chains."""
        if not chains:
            return []
        
        unique: dict[str, AttackChain] = {}
        
        for chain in chains:
            # Create a key from sorted node IDs
            node_ids = tuple(sorted(n.id for n in chain.nodes))
            key = f"{chain.name}_{node_ids}"
            
            if key not in unique:
                unique[key] = chain
            else:
                # Keep the one with more detail
                existing = unique[key]
                if len(chain.nodes) > len(existing.nodes):
                    unique[key] = chain
        
        return list(unique.values())
    
    def _generate_mitigations(self, nodes: list[PathNode]) -> list[str]:
        """Generate mitigation recommendations for a chain."""
        mitigations: list[str] = []
        
        for node in nodes:
            if node.node_type == NodeType.FINDING and node.severity:
                if node.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                    mitigations.append(f"Address {node.label} immediately")
        
        if not mitigations:
            mitigations.append("Review and remediate all findings in this chain")
        
        return mitigations[:5]  # Limit to 5
    
    def _generate_top_risks(self, chains: list[AttackChain]) -> list[str]:
        """Generate top risk insights from chains."""
        risks: list[str] = []
        
        critical = [c for c in chains if c.risk_level == "critical"]
        high = [c for c in chains if c.risk_level == "high"]
        
        if critical:
            risks.append(f"{len(critical)} critical attack path(s) identified requiring immediate attention")
        
        if high:
            risks.append(f"{len(high)} high-risk attack path(s) that could lead to significant compromise")
        
        # Look for specific attack types
        attack_types = set(c.attack_type for c in chains if c.attack_type)
        for attack_type in list(attack_types)[:3]:
            risks.append(f"Potential {attack_type} attack vector detected")
        
        if not risks:
            risks.append("No critical attack paths identified in current findings")
        
        return risks[:5]

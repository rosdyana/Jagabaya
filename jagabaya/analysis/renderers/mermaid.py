"""
Mermaid diagram renderer for attack paths.

Generates Mermaid.js flowchart syntax for embedding in Markdown/HTML reports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jagabaya.analysis.attack_paths import AttackChain, AttackPathResult, PathNode

from jagabaya.models.findings import FindingSeverity


class MermaidRenderer:
    """
    Renders attack paths as Mermaid.js flowcharts.
    
    Generates syntax compatible with GitHub, GitLab, VS Code, Obsidian,
    and other Markdown renderers that support Mermaid.
    
    Example:
        >>> renderer = MermaidRenderer()
        >>> diagram = renderer.render_chain(chain)
        >>> print(diagram)
        ```mermaid
        flowchart LR
            A[Subdomain Found] -->|discovered| B[Open Port 443]
            B -->|leads to| C[CVE-2021-41773]
        ```
    """
    
    # Severity to color mapping (Mermaid fill colors)
    SEVERITY_COLORS = {
        FindingSeverity.CRITICAL: "#e74c3c",  # Red
        FindingSeverity.HIGH: "#e67e22",      # Orange
        FindingSeverity.MEDIUM: "#f39c12",    # Yellow
        FindingSeverity.LOW: "#3498db",       # Blue
        FindingSeverity.INFO: "#95a5a6",      # Gray
    }
    
    # Node type colors
    NODE_TYPE_COLORS = {
        "asset": "#2ecc71",    # Green
        "finding": "#e74c3c",  # Red (overridden by severity)
        "action": "#9b59b6",   # Purple
    }
    
    def __init__(self, direction: str = "LR"):
        """
        Initialize the Mermaid renderer.
        
        Args:
            direction: Flowchart direction (LR, RL, TB, BT)
        """
        self.direction = direction
    
    def render_chain(self, chain: "AttackChain", include_wrapper: bool = True) -> str:
        """
        Render a single attack chain as a Mermaid diagram.
        
        Args:
            chain: The attack chain to render
            include_wrapper: Whether to include ```mermaid wrapper
        
        Returns:
            Mermaid diagram syntax
        """
        if not chain.nodes:
            return ""
        
        lines: list[str] = []
        
        # Add wrapper if requested
        if include_wrapper:
            lines.append("```mermaid")
        
        lines.append(f"flowchart {self.direction}")
        
        # Add subgraph for the chain
        lines.append(f"    subgraph {self._sanitize_id(chain.name)}")
        lines.append(f"    direction {self.direction}")
        
        # Add nodes
        for node in chain.nodes:
            node_def = self._render_node(node)
            lines.append(f"    {node_def}")
        
        # Add edges
        for from_id, to_id, relationship in chain.edges:
            edge = self._render_edge(from_id, to_id, relationship)
            lines.append(f"    {edge}")
        
        lines.append("    end")
        
        # Add styles for severity colors
        lines.extend(self._render_styles(chain.nodes))
        
        if include_wrapper:
            lines.append("```")
        
        return "\n".join(lines)
    
    def render_result(self, result: "AttackPathResult", max_chains: int = 5) -> str:
        """
        Render multiple attack chains from a result.
        
        Args:
            result: The attack path analysis result
            max_chains: Maximum number of chains to render
        
        Returns:
            Mermaid diagram with multiple subgraphs
        """
        if not result.chains:
            return ""
        
        chains_to_render = result.get_top_chains(max_chains)
        
        lines: list[str] = [
            "```mermaid",
            f"flowchart {self.direction}",
        ]
        
        all_nodes: list["PathNode"] = []
        
        for i, chain in enumerate(chains_to_render):
            subgraph_id = f"chain{i + 1}"
            risk_label = f"{chain.risk_level.upper()} - {chain.name}"
            
            lines.append(f"    subgraph {subgraph_id}[{risk_label}]")
            lines.append(f"    direction {self.direction}")
            
            # Prefix node IDs to avoid collisions between chains
            prefix = f"c{i}_"
            
            for node in chain.nodes:
                node_def = self._render_node(node, prefix)
                lines.append(f"    {node_def}")
                all_nodes.append(node)
            
            for from_id, to_id, relationship in chain.edges:
                edge = self._render_edge(f"{prefix}{from_id}", f"{prefix}{to_id}", relationship)
                lines.append(f"    {edge}")
            
            lines.append("    end")
            lines.append("")
        
        # Add styles
        for i, chain in enumerate(chains_to_render):
            prefix = f"c{i}_"
            lines.extend(self._render_styles(chain.nodes, prefix))
        
        lines.append("```")
        
        return "\n".join(lines)
    
    def render_summary(self, result: "AttackPathResult") -> str:
        """
        Render a summary diagram showing chain counts by risk.
        
        Args:
            result: The attack path analysis result
        
        Returns:
            Simple Mermaid pie chart
        """
        if not result.chains:
            return ""
        
        lines = [
            "```mermaid",
            "pie showData",
            '    title Attack Paths by Risk Level',
        ]
        
        if result.critical_chains > 0:
            lines.append(f'    "Critical" : {result.critical_chains}')
        if result.high_chains > 0:
            lines.append(f'    "High" : {result.high_chains}')
        if result.medium_chains > 0:
            lines.append(f'    "Medium" : {result.medium_chains}')
        if result.low_chains > 0:
            lines.append(f'    "Low" : {result.low_chains}')
        
        lines.append("```")
        
        return "\n".join(lines)
    
    def _render_node(self, node: "PathNode", prefix: str = "") -> str:
        """Render a single node definition."""
        node_id = f"{prefix}{self._sanitize_id(node.id)}"
        label = self._escape_label(node.label)
        
        # Choose shape based on node type
        if node.node_type.value == "asset":
            # Stadium shape for assets
            return f'{node_id}(["{label}"])'
        elif node.severity and node.severity == FindingSeverity.CRITICAL:
            # Hexagon for critical findings
            return f'{node_id}{{{{"{label}"}}}}'
        else:
            # Rectangle for regular findings
            return f'{node_id}["{label}"]'
    
    def _render_edge(self, from_id: str, to_id: str, relationship: str) -> str:
        """Render an edge between nodes."""
        from_id = self._sanitize_id(from_id)
        to_id = self._sanitize_id(to_id)
        relationship = self._escape_label(relationship)
        
        return f'{from_id} -->|{relationship}| {to_id}'
    
    def _render_styles(self, nodes: list["PathNode"], prefix: str = "") -> list[str]:
        """Generate style definitions for nodes."""
        styles: list[str] = []
        
        for node in nodes:
            node_id = f"{prefix}{self._sanitize_id(node.id)}"
            
            if node.severity:
                color = self.SEVERITY_COLORS.get(node.severity, "#95a5a6")
                styles.append(f"    style {node_id} fill:{color},color:#fff")
            elif node.node_type.value == "asset":
                color = self.NODE_TYPE_COLORS["asset"]
                styles.append(f"    style {node_id} fill:{color},color:#fff")
        
        return styles
    
    def _sanitize_id(self, text: str) -> str:
        """Sanitize text for use as a Mermaid ID."""
        # Remove special characters, keep alphanumeric and underscores
        sanitized = "".join(c if c.isalnum() or c == "_" else "_" for c in text)
        # Ensure it starts with a letter
        if sanitized and not sanitized[0].isalpha():
            sanitized = "n_" + sanitized
        return sanitized[:50]  # Limit length
    
    def _escape_label(self, text: str) -> str:
        """Escape text for use in Mermaid labels."""
        # Escape quotes and other special characters
        escaped = text.replace('"', "'")
        escaped = escaped.replace("<", "&lt;")
        escaped = escaped.replace(">", "&gt;")
        return escaped[:40]  # Limit length for readability

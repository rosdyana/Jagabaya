"""
ASCII renderer for compact CLI attack path display.

Generates terminal-friendly visualizations using Rich library.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jagabaya.analysis.attack_paths import AttackChain, AttackPathResult

from jagabaya.models.findings import FindingSeverity


class ASCIIRenderer:
    """
    Renders attack paths as compact ASCII/Rich output for CLI.
    
    Provides compact one-line summaries suitable for terminal display.
    
    Example:
        >>> renderer = ASCIIRenderer()
        >>> output = renderer.render_compact(result)
        >>> console.print(output)
    """
    
    # Severity colors for Rich
    SEVERITY_COLORS = {
        FindingSeverity.CRITICAL: "red bold",
        FindingSeverity.HIGH: "orange1",
        FindingSeverity.MEDIUM: "yellow",
        FindingSeverity.LOW: "blue",
        FindingSeverity.INFO: "dim",
    }
    
    # Risk level colors
    RISK_COLORS = {
        "critical": "red bold",
        "high": "orange1",
        "medium": "yellow",
        "low": "blue",
    }
    
    def __init__(self, max_width: int = 80):
        """
        Initialize the ASCII renderer.
        
        Args:
            max_width: Maximum output width in characters
        """
        self.max_width = max_width
    
    def render_compact(self, result: "AttackPathResult", limit: int = 5) -> str:
        """
        Render attack paths in compact format.
        
        Args:
            result: The attack path analysis result
            limit: Maximum number of chains to show
        
        Returns:
            Rich-formatted string for console output
        """
        if not result.chains:
            return "[dim]No attack paths identified[/]"
        
        lines: list[str] = []
        
        # Header
        lines.append("[bold]Attack Paths Identified[/]")
        lines.append("")
        
        # Top chains
        for i, chain in enumerate(result.get_top_chains(limit), 1):
            lines.append(self._render_chain_compact(chain, i))
        
        # Summary
        if result.total_chains > limit:
            lines.append(f"\n[dim]... and {result.total_chains - limit} more paths[/]")
        
        return "\n".join(lines)
    
    def render_detailed(self, result: "AttackPathResult", limit: int = 3) -> str:
        """
        Render attack paths with more detail.
        
        Args:
            result: The attack path analysis result
            limit: Maximum number of chains to show in detail
        
        Returns:
            Rich-formatted string for console output
        """
        if not result.chains:
            return "[dim]No attack paths identified[/]"
        
        lines: list[str] = []
        
        # Header with summary
        lines.append("[bold]Attack Path Analysis[/]")
        lines.append(self._render_summary(result))
        lines.append("")
        
        # Detailed chains
        for i, chain in enumerate(result.get_top_chains(limit), 1):
            lines.append(self._render_chain_detailed(chain, i))
            lines.append("")
        
        return "\n".join(lines)
    
    def render_chain_oneline(self, chain: "AttackChain") -> str:
        """
        Render a single chain as one line.
        
        Args:
            chain: The attack chain to render
        
        Returns:
            Single-line Rich-formatted string
        """
        risk_color = self.RISK_COLORS.get(chain.risk_level, "white")
        
        # Build node sequence
        node_parts: list[str] = []
        for node in chain.nodes[:4]:
            label = node.label[:20]
            if node.severity:
                sev_color = self.SEVERITY_COLORS.get(node.severity, "white")
                node_parts.append(f"[{sev_color}]{label}[/]")
            else:
                node_parts.append(f"[green]{label}[/]")
        
        if len(chain.nodes) > 4:
            node_parts.append(f"[dim]+{len(chain.nodes) - 4} more[/]")
        
        path_str = " [dim]→[/] ".join(node_parts)
        
        return f"[{risk_color}][{chain.risk_level.upper()}][/] {path_str}"
    
    def _render_chain_compact(self, chain: "AttackChain", index: int) -> str:
        """Render a chain in compact format with index."""
        risk_color = self.RISK_COLORS.get(chain.risk_level, "white")
        
        # Score and risk badge
        score_str = f"{chain.score:.1f}/10"
        
        # Chain summary
        summary = chain.to_compact_string()
        if len(summary) > self.max_width - 30:
            summary = summary[:self.max_width - 33] + "..."
        
        line1 = f"  [{risk_color}]Path {index}: {chain.name}[/] (Score: {score_str})"
        line2 = f"  [dim]{summary}[/]"
        
        return f"{line1}\n{line2}"
    
    def _render_chain_detailed(self, chain: "AttackChain", index: int) -> str:
        """Render a chain with full details."""
        risk_color = self.RISK_COLORS.get(chain.risk_level, "white")
        
        lines: list[str] = []
        
        # Header
        lines.append(f"[{risk_color}]━━━ Path {index}: {chain.name} ━━━[/]")
        lines.append(f"  Risk: [{risk_color}]{chain.risk_level.upper()}[/] | Score: {chain.score:.1f}/10 | Steps: {len(chain.nodes)}")
        
        # Attack type and impact
        if chain.attack_type:
            lines.append(f"  Type: {chain.attack_type}")
        if chain.impact:
            lines.append(f"  Impact: {chain.impact[:60]}")
        
        # Node chain visualization
        lines.append("  Chain:")
        for i, node in enumerate(chain.nodes):
            connector = "  └─" if i == len(chain.nodes) - 1 else "  ├─"
            
            if node.severity:
                sev_color = self.SEVERITY_COLORS.get(node.severity, "white")
                sev_badge = f"[{sev_color}][{node.severity.value.upper()}][/]"
                lines.append(f"{connector} {sev_badge} {node.label}")
            else:
                lines.append(f"{connector} [green][ASSET][/] {node.label}")
        
        # Mitigations
        if chain.mitigations:
            lines.append("  Mitigations:")
            for mitigation in chain.mitigations[:2]:
                lines.append(f"    • {mitigation[:50]}")
        
        return "\n".join(lines)
    
    def _render_summary(self, result: "AttackPathResult") -> str:
        """Render summary statistics."""
        parts: list[str] = []
        
        if result.critical_chains > 0:
            parts.append(f"[red bold]{result.critical_chains} Critical[/]")
        if result.high_chains > 0:
            parts.append(f"[orange1]{result.high_chains} High[/]")
        if result.medium_chains > 0:
            parts.append(f"[yellow]{result.medium_chains} Medium[/]")
        if result.low_chains > 0:
            parts.append(f"[blue]{result.low_chains} Low[/]")
        
        if parts:
            return f"Found {result.total_chains} paths: " + ", ".join(parts)
        return f"Found {result.total_chains} attack paths"
    
    def to_plain_text(self, result: "AttackPathResult", limit: int = 5) -> str:
        """
        Render as plain text without Rich formatting.
        
        Args:
            result: The attack path analysis result
            limit: Maximum number of chains to show
        
        Returns:
            Plain text string
        """
        if not result.chains:
            return "No attack paths identified"
        
        lines: list[str] = []
        
        lines.append("ATTACK PATHS IDENTIFIED")
        lines.append("=" * 40)
        lines.append("")
        
        for i, chain in enumerate(result.get_top_chains(limit), 1):
            lines.append(f"Path {i}: {chain.name}")
            lines.append(f"  Risk: {chain.risk_level.upper()} | Score: {chain.score:.1f}/10")
            lines.append(f"  Chain: {chain.to_compact_string()}")
            if chain.impact:
                lines.append(f"  Impact: {chain.impact[:60]}")
            lines.append("")
        
        return "\n".join(lines)

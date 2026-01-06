"""
Scope validation for Jagabaya.

Ensures all targets are within the authorized scope.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse


class ScopeValidator:
    """
    Validates targets against the defined scope.
    
    Ensures that all scanning activities stay within the
    authorized boundaries defined by the user.
    
    Example:
        >>> validator = ScopeValidator(
        ...     scope=["example.com", "*.example.com", "192.168.1.0/24"],
        ...     blacklist=["admin.example.com", "192.168.1.1"]
        ... )
        >>> validator.is_in_scope("www.example.com")
        True
        >>> validator.is_in_scope("admin.example.com")
        False
    """
    
    def __init__(
        self,
        scope: list[str] | None = None,
        blacklist: list[str] | None = None,
    ):
        """
        Initialize the ScopeValidator.
        
        Args:
            scope: List of in-scope targets (domains, IPs, CIDRs)
            blacklist: List of out-of-scope targets
        """
        self.scope = scope or []
        self.blacklist = blacklist or []
        
        # Parse scope and blacklist
        self._scope_domains: list[str] = []
        self._scope_wildcards: list[str] = []
        self._scope_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._scope_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        
        self._blacklist_domains: list[str] = []
        self._blacklist_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        self._blacklist_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        
        self._parse_scope()
        self._parse_blacklist()
    
    def _parse_scope(self) -> None:
        """Parse scope entries into appropriate categories."""
        for entry in self.scope:
            entry = entry.strip()
            
            # Skip empty entries
            if not entry:
                continue
            
            # Check if it's a CIDR
            if "/" in entry:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    self._scope_networks.append(network)
                    continue
                except ValueError:
                    pass
            
            # Check if it's an IP
            try:
                ip = ipaddress.ip_address(entry)
                self._scope_ips.append(ip)
                continue
            except ValueError:
                pass
            
            # Check if it's a wildcard domain
            if entry.startswith("*."):
                self._scope_wildcards.append(entry[2:].lower())
                continue
            
            # Treat as domain
            self._scope_domains.append(entry.lower())
    
    def _parse_blacklist(self) -> None:
        """Parse blacklist entries."""
        for entry in self.blacklist:
            entry = entry.strip()
            
            if not entry:
                continue
            
            # Check for CIDR
            if "/" in entry:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    self._blacklist_networks.append(network)
                    continue
                except ValueError:
                    pass
            
            # Check for IP
            try:
                ip = ipaddress.ip_address(entry)
                self._blacklist_ips.append(ip)
                continue
            except ValueError:
                pass
            
            # Treat as domain
            self._blacklist_domains.append(entry.lower())
    
    def is_in_scope(self, target: str) -> bool:
        """
        Check if a target is within scope.
        
        Args:
            target: Target to check (domain, IP, URL)
        
        Returns:
            True if in scope, False otherwise
        """
        # Empty scope means everything is in scope
        if not self.scope:
            return not self.is_blacklisted(target)
        
        # Extract the actual target from URLs
        target = self._normalize_target(target)
        
        # Check blacklist first
        if self.is_blacklisted(target):
            return False
        
        # Check if it's an IP
        try:
            ip = ipaddress.ip_address(target)
            
            # Check direct IP match
            if ip in self._scope_ips:
                return True
            
            # Check network membership
            for network in self._scope_networks:
                if ip in network:
                    return True
            
            return False
        except ValueError:
            pass
        
        # It's a domain
        target_lower = target.lower()
        
        # Check exact domain match
        if target_lower in self._scope_domains:
            return True
        
        # Check wildcard matches
        for wildcard_base in self._scope_wildcards:
            if target_lower.endswith(f".{wildcard_base}") or target_lower == wildcard_base:
                return True
        
        # Check if it's a subdomain of a scoped domain
        for domain in self._scope_domains:
            if target_lower.endswith(f".{domain}"):
                return True
        
        return False
    
    def is_blacklisted(self, target: str) -> bool:
        """
        Check if a target is blacklisted.
        
        Args:
            target: Target to check
        
        Returns:
            True if blacklisted
        """
        if not self.blacklist:
            return False
        
        target = self._normalize_target(target)
        
        # Check if it's an IP
        try:
            ip = ipaddress.ip_address(target)
            
            # Check direct IP match
            if ip in self._blacklist_ips:
                return True
            
            # Check network membership
            for network in self._blacklist_networks:
                if ip in network:
                    return True
            
            return False
        except ValueError:
            pass
        
        # It's a domain
        target_lower = target.lower()
        
        return target_lower in self._blacklist_domains
    
    def _normalize_target(self, target: str) -> str:
        """
        Normalize a target to extract the host.
        
        Args:
            target: Target string (URL, domain, IP)
        
        Returns:
            Normalized target
        """
        # Handle URLs
        if "://" in target:
            parsed = urlparse(target)
            target = parsed.hostname or parsed.netloc or target
        
        # Remove port
        if ":" in target and not target.startswith("["):
            target = target.split(":")[0]
        
        # Remove trailing dots
        target = target.rstrip(".")
        
        return target
    
    def validate_targets(self, targets: list[str]) -> dict[str, list[str]]:
        """
        Validate a list of targets.
        
        Args:
            targets: List of targets to validate
        
        Returns:
            Dictionary with 'valid' and 'invalid' lists
        """
        valid = []
        invalid = []
        
        for target in targets:
            if self.is_in_scope(target):
                valid.append(target)
            else:
                invalid.append(target)
        
        return {"valid": valid, "invalid": invalid}
    
    def filter_targets(self, targets: list[str]) -> list[str]:
        """
        Filter a list of targets to only include in-scope ones.
        
        Args:
            targets: List of targets
        
        Returns:
            List of in-scope targets
        """
        return [t for t in targets if self.is_in_scope(t)]
    
    def add_to_scope(self, target: str) -> None:
        """
        Add a target to the scope.
        
        Args:
            target: Target to add
        """
        self.scope.append(target)
        self._parse_scope()  # Re-parse
    
    def add_to_blacklist(self, target: str) -> None:
        """
        Add a target to the blacklist.
        
        Args:
            target: Target to blacklist
        """
        self.blacklist.append(target)
        self._parse_blacklist()  # Re-parse
    
    def get_scope_summary(self) -> dict[str, Any]:
        """
        Get a summary of the scope configuration.
        
        Returns:
            Dictionary with scope details
        """
        return {
            "domains": self._scope_domains,
            "wildcards": [f"*.{w}" for w in self._scope_wildcards],
            "networks": [str(n) for n in self._scope_networks],
            "ips": [str(ip) for ip in self._scope_ips],
            "blacklist_domains": self._blacklist_domains,
            "blacklist_ips": [str(ip) for ip in self._blacklist_ips],
            "blacklist_networks": [str(n) for n in self._blacklist_networks],
        }

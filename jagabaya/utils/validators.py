"""
Input validation utilities for Jagabaya.

Provides validation functions for:
- IP addresses
- Domain names
- URLs
- Ports
- CIDR ranges
- General targets
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


# Regex patterns
DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)
HOSTNAME_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
)
PORT_RANGE_PATTERN = re.compile(r"^(\d+)(?:-(\d+))?$")


class ValidationError(Exception):
    """Raised when validation fails."""
    
    def __init__(self, message: str, field: str | None = None):
        """Initialize with message and optional field name."""
        super().__init__(message)
        self.field = field
        self.message = message


def validate_ip(value: str) -> str:
    """
    Validate an IP address.
    
    Args:
        value: IP address string
    
    Returns:
        Validated IP address
    
    Raises:
        ValidationError: If invalid
    """
    try:
        ip = ipaddress.ip_address(value.strip())
        return str(ip)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: {value}", "ip") from e


def validate_cidr(value: str) -> str:
    """
    Validate a CIDR range.
    
    Args:
        value: CIDR range string (e.g., "192.168.1.0/24")
    
    Returns:
        Validated CIDR range
    
    Raises:
        ValidationError: If invalid
    """
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
        return str(network)
    except ValueError as e:
        raise ValidationError(f"Invalid CIDR range: {value}", "cidr") from e


def validate_domain(value: str) -> str:
    """
    Validate a domain name.
    
    Args:
        value: Domain name string
    
    Returns:
        Validated domain name (lowercase)
    
    Raises:
        ValidationError: If invalid
    """
    domain = value.strip().lower()
    
    # Remove leading/trailing dots
    domain = domain.strip(".")
    
    # Check length
    if len(domain) > 253:
        raise ValidationError(f"Domain too long: {value}", "domain")
    
    # Validate pattern
    if not DOMAIN_PATTERN.match(domain):
        raise ValidationError(f"Invalid domain name: {value}", "domain")
    
    return domain


def validate_hostname(value: str) -> str:
    """
    Validate a hostname (doesn't require TLD).
    
    Args:
        value: Hostname string
    
    Returns:
        Validated hostname (lowercase)
    
    Raises:
        ValidationError: If invalid
    """
    hostname = value.strip().lower()
    
    if len(hostname) > 253:
        raise ValidationError(f"Hostname too long: {value}", "hostname")
    
    if not HOSTNAME_PATTERN.match(hostname):
        raise ValidationError(f"Invalid hostname: {value}", "hostname")
    
    return hostname


def validate_url(value: str) -> str:
    """
    Validate a URL.
    
    Args:
        value: URL string
    
    Returns:
        Validated URL
    
    Raises:
        ValidationError: If invalid
    """
    url = value.strip()
    
    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    
    try:
        parsed = urlparse(url)
        
        if not parsed.scheme or not parsed.netloc:
            raise ValidationError(f"Invalid URL: {value}", "url")
        
        # Validate the netloc as domain or IP
        host = parsed.netloc.split(":")[0]
        try:
            validate_ip(host)
        except ValidationError:
            try:
                validate_domain(host)
            except ValidationError:
                raise ValidationError(f"Invalid URL host: {host}", "url")
        
        return url
    
    except Exception as e:
        if isinstance(e, ValidationError):
            raise
        raise ValidationError(f"Invalid URL: {value}", "url") from e


def validate_port(value: int | str) -> int:
    """
    Validate a port number.
    
    Args:
        value: Port number (int or string)
    
    Returns:
        Validated port number
    
    Raises:
        ValidationError: If invalid
    """
    try:
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValidationError(f"Port out of range: {port}", "port")
        return port
    except (ValueError, TypeError) as e:
        raise ValidationError(f"Invalid port: {value}", "port") from e


def validate_port_range(value: str) -> tuple[int, int]:
    """
    Validate a port range.
    
    Args:
        value: Port range string (e.g., "80", "80-443", "1-1000")
    
    Returns:
        Tuple of (start_port, end_port)
    
    Raises:
        ValidationError: If invalid
    """
    match = PORT_RANGE_PATTERN.match(value.strip())
    if not match:
        raise ValidationError(f"Invalid port range: {value}", "port_range")
    
    start = int(match.group(1))
    end = int(match.group(2)) if match.group(2) else start
    
    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        raise ValidationError(f"Port out of range: {value}", "port_range")
    
    if start > end:
        raise ValidationError(f"Invalid port range (start > end): {value}", "port_range")
    
    return (start, end)


def validate_target(value: str) -> tuple[str, str]:
    """
    Validate a target and determine its type.
    
    Args:
        value: Target string (IP, domain, URL, or CIDR)
    
    Returns:
        Tuple of (validated_target, target_type)
    
    Raises:
        ValidationError: If invalid
    """
    target = value.strip()
    
    # Check for URL
    if target.startswith(("http://", "https://", "ftp://")):
        return validate_url(target), "url"
    
    # Check for CIDR
    if "/" in target and not target.startswith("/"):
        try:
            return validate_cidr(target), "cidr"
        except ValidationError:
            pass
    
    # Check for IP
    try:
        return validate_ip(target), "ip"
    except ValidationError:
        pass
    
    # Check for domain
    try:
        return validate_domain(target), "domain"
    except ValidationError:
        pass
    
    # Try as hostname
    try:
        return validate_hostname(target), "hostname"
    except ValidationError:
        pass
    
    raise ValidationError(f"Invalid target: {value}", "target")


def is_valid_target(value: str) -> bool:
    """
    Check if a target is valid.
    
    Args:
        value: Target string
    
    Returns:
        True if valid, False otherwise
    """
    try:
        validate_target(value)
        return True
    except ValidationError:
        return False


def is_internal_ip(ip: str) -> bool:
    """
    Check if an IP address is internal/private.
    
    Args:
        ip: IP address string
    
    Returns:
        True if internal/private
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def is_valid_email(value: str) -> bool:
    """
    Check if a string is a valid email address.
    
    Args:
        value: Email address string
    
    Returns:
        True if valid
    """
    pattern = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(value.strip()))


def sanitize_target_for_filename(target: str) -> str:
    """
    Sanitize a target string for use in filenames.
    
    Args:
        target: Target string
    
    Returns:
        Sanitized string safe for filenames
    """
    # Replace problematic characters
    sanitized = target.replace("://", "_")
    sanitized = re.sub(r"[/\\:*?\"<>|]", "_", sanitized)
    sanitized = re.sub(r"_+", "_", sanitized)
    sanitized = sanitized.strip("_")
    
    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    
    return sanitized

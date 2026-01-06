"""
Helper utilities for Jagabaya.

Provides general-purpose helper functions for:
- String manipulation
- List operations
- Dictionary operations
- Parsing
"""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable, TypeVar

T = TypeVar("T")


def sanitize_filename(name: str, max_length: int = 255) -> str:
    """
    Sanitize a string for use as a filename.
    
    Args:
        name: Input string
        max_length: Maximum filename length
    
    Returns:
        Sanitized filename-safe string
    """
    # Remove or replace invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(" .")
    
    # Collapse multiple underscores
    sanitized = re.sub(r"_+", "_", sanitized)
    
    # Truncate if too long
    if len(sanitized) > max_length:
        # Preserve extension if present
        if "." in sanitized:
            name_part, ext = sanitized.rsplit(".", 1)
            max_name_len = max_length - len(ext) - 1
            sanitized = f"{name_part[:max_name_len]}.{ext}"
        else:
            sanitized = sanitized[:max_length]
    
    # Fallback for empty result
    if not sanitized:
        sanitized = "unnamed"
    
    return sanitized


def truncate_string(
    text: str,
    max_length: int,
    suffix: str = "...",
) -> str:
    """
    Truncate a string to a maximum length.
    
    Args:
        text: Input string
        max_length: Maximum length including suffix
        suffix: Suffix to append when truncated
    
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[: max_length - len(suffix)] + suffix


def parse_ports(port_string: str) -> list[int]:
    """
    Parse a port specification string.
    
    Supports formats:
    - Single port: "80"
    - Range: "80-100"
    - List: "80,443,8080"
    - Mixed: "22,80-100,443"
    
    Args:
        port_string: Port specification
    
    Returns:
        List of port numbers
    """
    ports: set[int] = set()
    
    for part in port_string.split(","):
        part = part.strip()
        if not part:
            continue
        
        if "-" in part:
            # Range
            try:
                start, end = part.split("-", 1)
                start_port = int(start.strip())
                end_port = int(end.strip())
                
                if 1 <= start_port <= end_port <= 65535:
                    ports.update(range(start_port, end_port + 1))
            except ValueError:
                continue
        else:
            # Single port
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                continue
    
    return sorted(ports)


def merge_dicts(
    base: dict[str, Any],
    override: dict[str, Any],
    deep: bool = True,
) -> dict[str, Any]:
    """
    Merge two dictionaries.
    
    Args:
        base: Base dictionary
        override: Dictionary to merge in (takes precedence)
        deep: Perform deep merge for nested dicts
    
    Returns:
        Merged dictionary
    """
    result = base.copy()
    
    for key, value in override.items():
        if deep and key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value, deep=True)
        else:
            result[key] = value
    
    return result


def deduplicate(
    items: Iterable[T],
    key: Callable[[T], Any] | None = None,
) -> list[T]:
    """
    Remove duplicates from a list while preserving order.
    
    Args:
        items: Items to deduplicate
        key: Function to extract comparison key
    
    Returns:
        Deduplicated list
    """
    seen: set[Any] = set()
    result: list[T] = []
    
    for item in items:
        k = key(item) if key else item
        if k not in seen:
            seen.add(k)
            result.append(item)
    
    return result


def chunk_list(items: list[T], chunk_size: int) -> list[list[T]]:
    """
    Split a list into chunks.
    
    Args:
        items: List to split
        chunk_size: Size of each chunk
    
    Returns:
        List of chunks
    """
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


def flatten(nested: list[list[T]]) -> list[T]:
    """
    Flatten a nested list.
    
    Args:
        nested: Nested list
    
    Returns:
        Flattened list
    """
    return [item for sublist in nested for item in sublist]


def format_bytes(num_bytes: int) -> str:
    """
    Format bytes as human-readable string.
    
    Args:
        num_bytes: Number of bytes
    
    Returns:
        Human-readable string (e.g., "1.5 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes //= 1024
    return f"{num_bytes:.1f} PB"


def format_duration(seconds: float) -> str:
    """
    Format seconds as human-readable duration.
    
    Args:
        seconds: Duration in seconds
    
    Returns:
        Human-readable string (e.g., "2h 30m 15s")
    """
    if seconds < 0:
        return "0s"
    
    delta = timedelta(seconds=int(seconds))
    
    parts = []
    
    days = delta.days
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    
    return " ".join(parts)


def generate_session_id() -> str:
    """
    Generate a unique session ID.
    
    Returns:
        Session ID string
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    random_part = secrets.token_hex(4)
    return f"{timestamp}_{random_part}"


def hash_string(text: str, algorithm: str = "sha256") -> str:
    """
    Hash a string.
    
    Args:
        text: String to hash
        algorithm: Hash algorithm (md5, sha1, sha256)
    
    Returns:
        Hex digest
    """
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def safe_get(
    data: dict[str, Any],
    *keys: str,
    default: Any = None,
) -> Any:
    """
    Safely get a nested value from a dictionary.
    
    Args:
        data: Dictionary to search
        *keys: Keys to traverse
        default: Default value if not found
    
    Returns:
        Found value or default
    """
    current = data
    
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    
    return current


def extract_urls(text: str) -> list[str]:
    """
    Extract URLs from text.
    
    Args:
        text: Text to search
    
    Returns:
        List of extracted URLs
    """
    url_pattern = re.compile(
        r"https?://[^\s<>\"'\)\]\}]+"
    )
    return url_pattern.findall(text)


def extract_ips(text: str) -> list[str]:
    """
    Extract IP addresses from text.
    
    Args:
        text: Text to search
    
    Returns:
        List of extracted IP addresses
    """
    ip_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    return deduplicate(ip_pattern.findall(text))


def extract_domains(text: str) -> list[str]:
    """
    Extract domain names from text.
    
    Args:
        text: Text to search
    
    Returns:
        List of extracted domains
    """
    domain_pattern = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )
    domains = domain_pattern.findall(text)
    
    # Filter out common false positives
    excluded = {"example.com", "example.org", "example.net", "localhost.localdomain"}
    
    return deduplicate([d.lower() for d in domains if d.lower() not in excluded])


def ensure_list(value: Any) -> list:
    """
    Ensure a value is a list.
    
    Args:
        value: Value to convert
    
    Returns:
        List containing value(s)
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def retry_with_backoff(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff_factor: float = 2.0,
) -> Callable:
    """
    Decorator for retrying functions with exponential backoff.
    
    Args:
        max_retries: Maximum number of retries
        initial_delay: Initial delay in seconds
        max_delay: Maximum delay between retries
        backoff_factor: Factor to multiply delay by
    
    Returns:
        Decorator function
    """
    import asyncio
    import functools
    import time
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            delay = initial_delay
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        await asyncio.sleep(delay)
                        delay = min(delay * backoff_factor, max_delay)
            
            raise last_exception
        
        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            delay = initial_delay
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        time.sleep(delay)
                        delay = min(delay * backoff_factor, max_delay)
            
            raise last_exception
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator

"""
Common parsing utilities for tool output.
"""

from __future__ import annotations

import json
import re
from typing import Any


def parse_json_lines(output: str) -> list[dict[str, Any]]:
    """
    Parse JSON lines (JSONL) output format.
    
    Many tools output one JSON object per line.
    
    Args:
        output: Raw output with one JSON object per line
    
    Returns:
        List of parsed JSON objects
    """
    results = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append(obj)
        except json.JSONDecodeError:
            continue
    return results


def parse_plain_lines(output: str, skip_empty: bool = True) -> list[str]:
    """
    Parse plain text output into lines.
    
    Args:
        output: Raw output
        skip_empty: Skip empty lines
    
    Returns:
        List of non-empty lines
    """
    lines = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if skip_empty and not line:
            continue
        lines.append(line)
    return lines


def extract_urls(text: str) -> list[str]:
    """
    Extract URLs from text.
    
    Args:
        text: Text containing URLs
    
    Returns:
        List of unique URLs
    """
    url_pattern = re.compile(
        r'https?://[^\s<>"\'{}|\\^`\[\]]+',
        re.IGNORECASE
    )
    urls = url_pattern.findall(text)
    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in urls:
        # Clean trailing punctuation
        url = url.rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    return unique_urls


def extract_ips(text: str) -> list[str]:
    """
    Extract IP addresses from text.
    
    Args:
        text: Text containing IP addresses
    
    Returns:
        List of unique IP addresses
    """
    ip_pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    ips = ip_pattern.findall(text)
    return list(dict.fromkeys(ips))  # Remove duplicates, preserve order


def extract_domains(text: str) -> list[str]:
    """
    Extract domain names from text.
    
    Args:
        text: Text containing domains
    
    Returns:
        List of unique domains
    """
    domain_pattern = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    domains = domain_pattern.findall(text)
    # Filter out common false positives
    excluded = {'example.com', 'test.com', 'localhost.localdomain'}
    domains = [d.lower() for d in domains if d.lower() not in excluded]
    return list(dict.fromkeys(domains))


def extract_ports(text: str) -> list[int]:
    """
    Extract port numbers from text.
    
    Args:
        text: Text containing port numbers
    
    Returns:
        List of unique port numbers
    """
    port_pattern = re.compile(r'\b(\d{1,5})/(?:tcp|udp)\b|\bport[:\s]+(\d{1,5})\b', re.IGNORECASE)
    ports = []
    for match in port_pattern.finditer(text):
        port_str = match.group(1) or match.group(2)
        if port_str:
            port = int(port_str)
            if 1 <= port <= 65535 and port not in ports:
                ports.append(port)
    return ports


def parse_key_value(text: str, separator: str = ":") -> dict[str, str]:
    """
    Parse key-value pairs from text.
    
    Args:
        text: Text with key-value pairs
        separator: Separator between key and value
    
    Returns:
        Dictionary of key-value pairs
    """
    result = {}
    for line in text.strip().split("\n"):
        if separator in line:
            key, _, value = line.partition(separator)
            result[key.strip()] = value.strip()
    return result


def clean_ansi(text: str) -> str:
    """
    Remove ANSI escape codes from text.
    
    Args:
        text: Text with ANSI codes
    
    Returns:
        Clean text without ANSI codes
    """
    ansi_pattern = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_pattern.sub('', text)


def truncate_output(output: str, max_length: int = 50000) -> str:
    """
    Truncate output if too long.
    
    Args:
        output: Raw output
        max_length: Maximum length
    
    Returns:
        Truncated output with note if truncated
    """
    if len(output) <= max_length:
        return output
    return output[:max_length] + f"\n\n... [TRUNCATED - {len(output) - max_length} bytes omitted]"

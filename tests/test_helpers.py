"""
Tests for helper utilities.
"""

import pytest

from jagabaya.utils.helpers import (
    sanitize_filename,
    truncate_string,
    parse_ports,
    merge_dicts,
    deduplicate,
    chunk_list,
    format_bytes,
    format_duration,
)


class TestSanitizeFilename:
    """Tests for filename sanitization."""
    
    def test_removes_invalid_chars(self):
        assert sanitize_filename("file<>:name") == "file___name"
        assert sanitize_filename("path/to\\file") == "path_to_file"
    
    def test_handles_empty(self):
        assert sanitize_filename("") == "unnamed"
        assert sanitize_filename("...") == "unnamed"
    
    def test_truncates_long_names(self):
        long_name = "a" * 300
        result = sanitize_filename(long_name, max_length=100)
        assert len(result) <= 100


class TestTruncateString:
    """Tests for string truncation."""
    
    def test_no_truncation_needed(self):
        assert truncate_string("short", 10) == "short"
    
    def test_truncates_with_suffix(self):
        assert truncate_string("this is a long string", 10) == "this is..."
    
    def test_custom_suffix(self):
        assert truncate_string("hello world", 8, suffix="~") == "hello w~"


class TestParsePorts:
    """Tests for port parsing."""
    
    def test_single_port(self):
        assert parse_ports("80") == [80]
    
    def test_port_range(self):
        assert parse_ports("80-82") == [80, 81, 82]
    
    def test_port_list(self):
        assert parse_ports("22,80,443") == [22, 80, 443]
    
    def test_mixed(self):
        assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]
    
    def test_invalid_ignored(self):
        assert parse_ports("80,invalid,443") == [80, 443]


class TestMergeDicts:
    """Tests for dictionary merging."""
    
    def test_simple_merge(self):
        result = merge_dicts({"a": 1}, {"b": 2})
        assert result == {"a": 1, "b": 2}
    
    def test_override(self):
        result = merge_dicts({"a": 1}, {"a": 2})
        assert result == {"a": 2}
    
    def test_deep_merge(self):
        base = {"a": {"b": 1, "c": 2}}
        override = {"a": {"c": 3, "d": 4}}
        result = merge_dicts(base, override, deep=True)
        assert result == {"a": {"b": 1, "c": 3, "d": 4}}


class TestDeduplicate:
    """Tests for deduplication."""
    
    def test_simple_dedupe(self):
        assert deduplicate([1, 2, 2, 3, 3, 3]) == [1, 2, 3]
    
    def test_preserves_order(self):
        assert deduplicate([3, 1, 2, 1, 3]) == [3, 1, 2]
    
    def test_with_key_function(self):
        items = [{"id": 1}, {"id": 2}, {"id": 1}]
        result = deduplicate(items, key=lambda x: x["id"])
        assert len(result) == 2


class TestChunkList:
    """Tests for list chunking."""
    
    def test_even_chunks(self):
        assert chunk_list([1, 2, 3, 4], 2) == [[1, 2], [3, 4]]
    
    def test_uneven_chunks(self):
        assert chunk_list([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]
    
    def test_empty_list(self):
        assert chunk_list([], 2) == []


class TestFormatBytes:
    """Tests for byte formatting."""
    
    def test_bytes(self):
        assert format_bytes(500) == "500.0 B"
    
    def test_kilobytes(self):
        assert format_bytes(1024) == "1.0 KB"
    
    def test_megabytes(self):
        assert format_bytes(1024 * 1024) == "1.0 MB"


class TestFormatDuration:
    """Tests for duration formatting."""
    
    def test_seconds(self):
        assert format_duration(45) == "45s"
    
    def test_minutes(self):
        assert format_duration(125) == "2m 5s"
    
    def test_hours(self):
        assert format_duration(3665) == "1h 1m"

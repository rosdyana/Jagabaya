"""
Tests for validation utilities.
"""

import pytest

from jagabaya.utils.validators import (
    validate_ip,
    validate_domain,
    validate_url,
    validate_port,
    validate_cidr,
    validate_target,
    is_valid_target,
    ValidationError,
)


class TestValidateIP:
    """Tests for IP validation."""
    
    def test_valid_ipv4(self):
        assert validate_ip("192.168.1.1") == "192.168.1.1"
        assert validate_ip("10.0.0.1") == "10.0.0.1"
        assert validate_ip("8.8.8.8") == "8.8.8.8"
    
    def test_valid_ipv6(self):
        assert validate_ip("::1") == "::1"
        assert validate_ip("2001:db8::1") == "2001:db8::1"
    
    def test_invalid_ip(self):
        with pytest.raises(ValidationError):
            validate_ip("not-an-ip")
        with pytest.raises(ValidationError):
            validate_ip("256.1.1.1")


class TestValidateDomain:
    """Tests for domain validation."""
    
    def test_valid_domains(self):
        assert validate_domain("example.com") == "example.com"
        assert validate_domain("sub.example.com") == "sub.example.com"
        assert validate_domain("EXAMPLE.COM") == "example.com"
    
    def test_invalid_domains(self):
        with pytest.raises(ValidationError):
            validate_domain("not a domain")
        with pytest.raises(ValidationError):
            validate_domain("-invalid.com")


class TestValidateURL:
    """Tests for URL validation."""
    
    def test_valid_urls(self):
        assert validate_url("https://example.com") == "https://example.com"
        assert validate_url("http://example.com/path") == "http://example.com/path"
    
    def test_adds_scheme(self):
        assert validate_url("example.com").startswith("https://")


class TestValidatePort:
    """Tests for port validation."""
    
    def test_valid_ports(self):
        assert validate_port(80) == 80
        assert validate_port("443") == 443
        assert validate_port(1) == 1
        assert validate_port(65535) == 65535
    
    def test_invalid_ports(self):
        with pytest.raises(ValidationError):
            validate_port(0)
        with pytest.raises(ValidationError):
            validate_port(65536)
        with pytest.raises(ValidationError):
            validate_port("not-a-port")


class TestValidateCIDR:
    """Tests for CIDR validation."""
    
    def test_valid_cidr(self):
        assert validate_cidr("192.168.1.0/24") == "192.168.1.0/24"
        assert validate_cidr("10.0.0.0/8") == "10.0.0.0/8"
    
    def test_invalid_cidr(self):
        with pytest.raises(ValidationError):
            validate_cidr("not-cidr")


class TestValidateTarget:
    """Tests for target validation."""
    
    def test_detects_ip(self):
        target, target_type = validate_target("192.168.1.1")
        assert target_type == "ip"
    
    def test_detects_domain(self):
        target, target_type = validate_target("example.com")
        assert target_type == "domain"
    
    def test_detects_url(self):
        target, target_type = validate_target("https://example.com")
        assert target_type == "url"
    
    def test_detects_cidr(self):
        target, target_type = validate_target("192.168.1.0/24")
        assert target_type == "cidr"


class TestIsValidTarget:
    """Tests for is_valid_target helper."""
    
    def test_valid_targets(self):
        assert is_valid_target("example.com") is True
        assert is_valid_target("192.168.1.1") is True
        assert is_valid_target("https://example.com") is True
    
    def test_invalid_targets(self):
        assert is_valid_target("") is False
        assert is_valid_target("not valid!!!") is False

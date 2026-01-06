"""
Test configuration and fixtures.
"""

import pytest


@pytest.fixture
def sample_target():
    """Sample target for testing."""
    return "example.com"


@pytest.fixture
def sample_ip():
    """Sample IP address for testing."""
    return "192.168.1.1"

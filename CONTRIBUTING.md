# Contributing to Jagabaya

Thank you for your interest in contributing to Jagabaya! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We're building a tool for ethical security testing, and we expect our community to uphold ethical standards.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/rosdyana/Jagabaya/issues)
2. If not, create a new issue with:
   - A clear, descriptive title
   - Steps to reproduce the issue
   - Expected vs actual behavior
   - Your environment (OS, Python version, etc.)

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Explain why it would be valuable

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Run tests: `pytest`
5. Run linting: `ruff check . && black --check .`
6. Commit with a clear message
7. Push and create a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Jagabaya.git
cd Jagabaya

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: .\venv\Scripts\activate  # Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
black --check .
mypy jagabaya/
```

## Code Style

- We use [Black](https://github.com/psf/black) for code formatting
- We use [Ruff](https://github.com/astral-sh/ruff) for linting
- Line length is 100 characters
- Use type hints for all function signatures
- Write docstrings for public functions and classes

## Adding New Tools

To add a new security tool wrapper:

1. Create a new file in `jagabaya/tools/wrappers/`
2. Inherit from `BaseTool`
3. Implement `build_command()` and `parse_output()` methods
4. Register the tool in `jagabaya/tools/wrappers/__init__.py`
5. Add tests in `tests/tools/`

Example:

```python
from jagabaya.tools.base import BaseTool, ToolCategory

class MyTool(BaseTool):
    name = "mytool"
    category = ToolCategory.VULNERABILITY
    description = "Description of what the tool does"
    
    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["mytool", target]
    
    def parse_output(self, output: str, target: str) -> dict:
        # Parse and return structured data
        return {"results": []}
```

## Testing

- Write tests for new features
- Maintain or improve code coverage
- Use pytest fixtures for common setup

## Legal Reminder

Jagabaya is for authorized security testing only. Contributions that could facilitate unauthorized access or malicious activities will not be accepted.

## Questions?

Open an issue or reach out to the maintainers.

Thank you for contributing!

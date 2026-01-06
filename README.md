# Jagabaya - AI-Powered Penetration Testing CLI

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Jagabaya** is a next-generation AI-powered penetration testing automation CLI that supports 100+ LLM providers through LiteLLM. It orchestrates intelligent, step-by-step security assessments using a multi-agent architecture while maintaining ethical hacking standards.

> **Author:** Rosdyana Kusuma

## Features

### Multi-LLM Support (100+ Providers)
- **OpenAI** (GPT-4o, GPT-4, GPT-3.5)
- **Anthropic** (Claude 3.5 Sonnet, Claude 3 Opus)
- **Google** (Gemini Pro, Gemini Ultra)
- **Azure OpenAI**
- **AWS Bedrock**
- **Ollama** (Local models)
- **And 90+ more providers via LiteLLM**

### Intelligent Agent System
- **Planner Agent**: Strategic decision-making for pentest workflow
- **Executor Agent**: Tool selection and execution
- **Analyst Agent**: Finding analysis and correlation
- **Reporter Agent**: Professional report generation

### 20+ Integrated Security Tools
| Category | Tools |
|----------|-------|
| **Network** | nmap, masscan |
| **Web Recon** | httpx, whatweb, wafw00f |
| **Subdomain** | subfinder, amass |
| **Vulnerability** | nuclei, nikto, sqlmap, wpscan |
| **SSL/TLS** | testssl, sslyze |
| **Content Discovery** | gobuster, ffuf, feroxbuster |
| **Parameter Discovery** | arjun |
| **XSS Testing** | xsstrike, dalfox |
| **Secret Scanning** | gitleaks, trufflehog |
| **CMS Detection** | cmseek, wpscan |
| **DNS** | dnsrecon, dnsx |

### Professional Reporting
- Markdown reports (Git-friendly)
- HTML reports (Visual, shareable)
- MITRE ATT&CK mapping
- Executive summaries

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/rosdyana/Jagabaya.git
cd Jagabaya

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: .\venv\Scripts\activate  # Windows

# Install in development mode
pip install -e ".[dev]"
```

### Configuration

```bash
# Initialize configuration
jagabaya init

# Or set environment variables
export OPENAI_API_KEY="your-api-key"
```

### Basic Usage

```bash
# Autonomous AI-driven scan
jagabaya run example.com

# Use a specific LLM provider
jagabaya run example.com --provider anthropic --model claude-3-5-sonnet-20241022

# Verbose output
jagabaya run example.com --verbose

# Specify output directory
jagabaya run example.com --output-dir ./my-results

# List available tools
jagabaya tools list

# Check which tools are installed
jagabaya tools check

# Install missing security tools
jagabaya tools install --all           # Show install commands (dry run)
jagabaya tools install --all --force   # Actually install all tools
jagabaya tools install nmap --force    # Install a specific tool

# Generate report from previous session
jagabaya report generate <session-id> --format html

# List previous sessions
jagabaya session list
```

## Configuration

Create a `jagabaya.yaml` file or use environment variables:

```yaml
llm:
  provider: openai
  model: gpt-4o
  temperature: 0.2
  max_tokens: 4096

scan:
  safe_mode: true
  stealth_mode: false
  require_confirmation: true
  max_parallel_tools: 3
  tool_timeout: 300

scope:
  blacklist:
    - 127.0.0.0/8
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16

output:
  directory: ./jagabaya_output
  report_format: markdown
  save_raw_output: true
```

## Tool Installation

Jagabaya integrates with 20+ security tools. The CLI can help you install missing tools:

```bash
# Check which tools are available
jagabaya tools check

# Show install commands for all missing tools (dry run)
jagabaya tools install --all

# Install all missing tools
jagabaya tools install --all --force

# Install tools by category
jagabaya tools install --category recon --force

# Install a specific tool
jagabaya tools install nmap --force
```

The installer auto-detects your platform and available package managers:
- **Linux**: apt, brew
- **macOS**: brew
- **Windows**: winget, scoop, choco
- **Cross-platform**: go, pip, gem, cargo

## Supported LLM Providers

Jagabaya uses [LiteLLM](https://github.com/BerriAI/litellm) for multi-provider support:

| Provider | Model Examples | Environment Variable |
|----------|---------------|---------------------|
| OpenAI | gpt-4o, gpt-4-turbo | `OPENAI_API_KEY` |
| Anthropic | claude-3-5-sonnet | `ANTHROPIC_API_KEY` |
| Google | gemini-pro | `GOOGLE_API_KEY` |
| Azure OpenAI | gpt-4 | `AZURE_API_KEY`, `AZURE_API_BASE` |
| AWS Bedrock | claude-3 | AWS credentials |
| Ollama | llama3, mistral | (local) |
| Groq | llama-3.1-70b | `GROQ_API_KEY` |
| Together AI | mixtral-8x7b | `TOGETHER_API_KEY` |

## Legal Disclaimer

**Jagabaya is designed exclusively for authorized security testing and educational purposes.**

- **Legal Use**: Authorized penetration testing, security research, educational environments
- **Illegal Use**: Unauthorized access, malicious activities, any form of cyber attack

**You are fully responsible for ensuring you have explicit written permission before testing any system.**

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Jagabaya** - Intelligent, Ethical, Automated Penetration Testing

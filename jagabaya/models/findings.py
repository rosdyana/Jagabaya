"""
Finding models for security vulnerabilities and discoveries.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    """Severity levels for findings."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @property
    def color(self) -> str:
        """Get Rich console color for severity."""
        colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        return colors.get(self.value, "white")
    
    @property
    def score_range(self) -> tuple[float, float]:
        """Get CVSS score range for severity."""
        ranges = {
            "critical": (9.0, 10.0),
            "high": (7.0, 8.9),
            "medium": (4.0, 6.9),
            "low": (0.1, 3.9),
            "info": (0.0, 0.0),
        }
        return ranges.get(self.value, (0.0, 0.0))


class FindingCategory(str, Enum):
    """Categories of security findings."""
    
    # Network
    OPEN_PORT = "open_port"
    SERVICE_DETECTED = "service_detected"
    NETWORK_VULNERABILITY = "network_vulnerability"
    
    # Web Application
    WEB_VULNERABILITY = "web_vulnerability"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    IDOR = "idor"
    XXE = "xxe"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    FILE_INCLUSION = "file_inclusion"
    COMMAND_INJECTION = "command_injection"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    
    # Authentication & Authorization
    WEAK_CREDENTIALS = "weak_credentials"
    AUTH_BYPASS = "auth_bypass"
    SESSION_MANAGEMENT = "session_management"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    
    # Encryption
    SSL_TLS_ISSUE = "ssl_tls_issue"
    WEAK_CIPHER = "weak_cipher"
    CERTIFICATE_ISSUE = "certificate_issue"
    
    # Information Disclosure
    INFO_DISCLOSURE = "info_disclosure"
    INFORMATION_DISCLOSURE = "information_disclosure"
    SENSITIVE_DATA = "sensitive_data"
    SENSITIVE_FILE_EXPOSURE = "sensitive_file_exposure"
    DEBUG_ENABLED = "debug_enabled"
    
    # Configuration
    MISCONFIGURATION = "misconfiguration"
    DEFAULT_CREDENTIALS = "default_credentials"
    SECURITY_HEADER_MISSING = "security_header_missing"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    
    # CMS/Framework
    CMS_VULNERABILITY = "cms_vulnerability"
    OUTDATED_SOFTWARE = "outdated_software"
    
    # Other
    DNS_ISSUE = "dns_issue"
    SUBDOMAIN = "subdomain"
    TECHNOLOGY = "technology"
    OTHER = "other"


class Finding(BaseModel):
    """
    Represents a security finding or discovery.
    
    This is the core data model for all vulnerabilities, 
    misconfigurations, and information discovered during a scan.
    """
    
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    
    # Core information
    severity: FindingSeverity = Field(
        description="Severity level of the finding"
    )
    category: FindingCategory = Field(
        default=FindingCategory.OTHER,
        description="Category of the finding"
    )
    title: str = Field(
        description="Short, descriptive title"
    )
    description: str = Field(
        description="Detailed description of the finding"
    )
    
    # Target information
    target: str = Field(
        description="Target where the finding was discovered"
    )
    port: int | None = Field(
        default=None,
        description="Port number if applicable"
    )
    protocol: str | None = Field(
        default=None,
        description="Protocol (http, https, tcp, udp)"
    )
    path: str | None = Field(
        default=None,
        description="URL path if applicable"
    )
    
    # Evidence
    evidence: str = Field(
        default="",
        description="Raw evidence or proof"
    )
    request: str | None = Field(
        default=None,
        description="HTTP request that triggered the finding"
    )
    response: str | None = Field(
        default=None,
        description="HTTP response containing the vulnerability"
    )
    
    # Source
    tool: str = Field(
        description="Tool that discovered this finding"
    )
    tool_output: str | None = Field(
        default=None,
        description="Raw output from the tool"
    )
    
    # Scoring
    cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS score (0.0-10.0)"
    )
    cvss_vector: str | None = Field(
        default=None,
        description="CVSS vector string"
    )
    
    # References
    cve_ids: list[str] = Field(
        default_factory=list,
        description="Related CVE identifiers"
    )
    cwe_ids: list[str] = Field(
        default_factory=list,
        description="Related CWE identifiers"
    )
    references: list[str] = Field(
        default_factory=list,
        description="Reference URLs"
    )
    
    # MITRE ATT&CK
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactics"
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs"
    )
    
    # Remediation
    remediation: str | None = Field(
        default=None,
        description="Recommended remediation steps"
    )
    
    # Status
    false_positive: bool = Field(
        default=False,
        description="Marked as false positive"
    )
    verified: bool = Field(
        default=False,
        description="Manually verified"
    )
    
    # Metadata
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="When the finding was discovered"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata"
    )
    
    def to_summary(self) -> str:
        """Get a one-line summary of the finding."""
        port_str = f":{self.port}" if self.port else ""
        return f"[{self.severity.value.upper()}] {self.title} @ {self.target}{port_str}"
    
    def to_markdown(self) -> str:
        """Convert finding to Markdown format."""
        md = f"""### {self.title}

**Severity:** {self.severity.value.upper()}
**Category:** {self.category.value}
**Target:** {self.target}{f":{self.port}" if self.port else ""}
**Tool:** {self.tool}

#### Description
{self.description}

"""
        if self.evidence:
            md += f"""#### Evidence
```
{self.evidence[:1000]}{"..." if len(self.evidence) > 1000 else ""}
```

"""
        if self.remediation:
            md += f"""#### Remediation
{self.remediation}

"""
        if self.cve_ids:
            md += f"**CVEs:** {', '.join(self.cve_ids)}\n"
        
        if self.references:
            md += "\n**References:**\n"
            for ref in self.references[:5]:
                md += f"- {ref}\n"
        
        return md


class FindingSummary(BaseModel):
    """Summary statistics for findings."""
    
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    false_positives: int = 0
    
    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "FindingSummary":
        """Create summary from list of findings."""
        summary = cls(total=len(findings))
        
        for finding in findings:
            if finding.false_positive:
                summary.false_positives += 1
                continue
            
            match finding.severity:
                case FindingSeverity.CRITICAL:
                    summary.critical += 1
                case FindingSeverity.HIGH:
                    summary.high += 1
                case FindingSeverity.MEDIUM:
                    summary.medium += 1
                case FindingSeverity.LOW:
                    summary.low += 1
                case FindingSeverity.INFO:
                    summary.info += 1
        
        return summary
    
    def to_dict(self) -> dict[str, int]:
        """Convert to dictionary."""
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
        }

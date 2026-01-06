"""
SQLMap - Automatic SQL injection tool.
"""

from __future__ import annotations

import re
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class SQLMapTool(BaseTool):
    """
    SQLMap wrapper - Automatic SQL injection detection and exploitation.
    
    SQLMap is an open source penetration testing tool that automates
    the detection and exploitation of SQL injection flaws.
    
    Example:
        >>> tool = SQLMapTool()
        >>> result = await tool.execute("https://example.com/page?id=1")
    """
    
    name = "sqlmap"
    description = "Automatic SQL injection detection and exploitation"
    category = ToolCategory.SQL_INJECTION
    binary = "sqlmap"
    homepage = "https://sqlmap.org"
    install_command = "apt install sqlmap / pip install sqlmap"
    output_format = "text"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build sqlmap command.
        
        Args:
            target: Target URL with parameters
            data: POST data
            param: Parameter to test
            method: HTTP method
            cookie: Cookie string
            headers: Custom headers
            level: Test level (1-5)
            risk: Risk level (1-3)
            technique: Injection techniques (BEUSTQ)
            dbs: Enumerate databases
            tables: Enumerate tables
            columns: Enumerate columns
            dump: Dump data
            batch: Non-interactive mode
            forms: Parse and test forms
            crawl: Crawl depth
            random_agent: Use random User-Agent
            tamper: Tamper scripts to use
        """
        args = []
        
        # Target URL or request file
        if target.endswith(".txt") or target.endswith(".req"):
            args.extend(["-r", target])
        else:
            args.extend(["-u", target])
        
        # POST data
        data = kwargs.get("data")
        if data:
            args.extend(["--data", data])
        
        # Specific parameter
        param = kwargs.get("param")
        if param:
            args.extend(["-p", param])
        
        # HTTP method
        method = kwargs.get("method")
        if method:
            args.extend(["--method", method.upper()])
        
        # Cookies
        cookie = kwargs.get("cookie")
        if cookie:
            args.extend(["--cookie", cookie])
        
        # Headers
        headers = kwargs.get("headers")
        if headers:
            if isinstance(headers, dict):
                for key, value in headers.items():
                    args.extend(["--headers", f"{key}: {value}"])
            elif isinstance(headers, list):
                for header in headers:
                    args.extend(["--headers", header])
        
        # Test level
        level = kwargs.get("level", 1)
        args.extend(["--level", str(level)])
        
        # Risk level
        risk = kwargs.get("risk", 1)
        args.extend(["--risk", str(risk)])
        
        # Injection techniques
        technique = kwargs.get("technique")
        if technique:
            args.extend(["--technique", technique])
        
        # Batch mode (non-interactive)
        if kwargs.get("batch", True):
            args.append("--batch")
        
        # Enumeration options
        if kwargs.get("dbs"):
            args.append("--dbs")
        
        if kwargs.get("tables"):
            args.append("--tables")
        
        if kwargs.get("columns"):
            args.append("--columns")
        
        if kwargs.get("dump"):
            args.append("--dump")
        
        if kwargs.get("dump_all"):
            args.append("--dump-all")
        
        # Database to enumerate
        database = kwargs.get("database")
        if database:
            args.extend(["-D", database])
        
        # Table to enumerate
        table = kwargs.get("table")
        if table:
            args.extend(["-T", table])
        
        # Forms
        if kwargs.get("forms"):
            args.append("--forms")
        
        # Crawl
        crawl = kwargs.get("crawl")
        if crawl:
            args.extend(["--crawl", str(crawl)])
        
        # Random User-Agent
        if kwargs.get("random_agent"):
            args.append("--random-agent")
        
        # Tamper scripts
        tamper = kwargs.get("tamper")
        if tamper:
            if isinstance(tamper, list):
                tamper = ",".join(tamper)
            args.extend(["--tamper", tamper])
        
        # Output directory
        output_dir = kwargs.get("output_dir")
        if output_dir:
            args.extend(["--output-dir", output_dir])
        
        # Threads
        threads = kwargs.get("threads", 1)
        args.extend(["--threads", str(threads)])
        
        # Timeout
        timeout = kwargs.get("timeout", 30)
        args.extend(["--timeout", str(timeout)])
        
        # Delay between requests
        delay = kwargs.get("delay")
        if delay:
            args.extend(["--delay", str(delay)])
        
        # Verbose
        if kwargs.get("verbose"):
            args.append("-v")
            args.append("3")
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse sqlmap text output."""
        result = {
            "vulnerable": False,
            "injection_points": [],
            "databases": [],
            "tables": [],
            "columns": [],
            "data": [],
            "dbms": None,
            "os": None,
            "web_server": None,
            "findings": [],
        }
        
        lines = output.strip().split("\n")
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # Check for vulnerability confirmation
            if "sqlmap identified the following injection point" in line.lower():
                result["vulnerable"] = True
            elif "parameter" in line.lower() and "is vulnerable" in line.lower():
                result["vulnerable"] = True
            
            # Parse injection points
            if "Parameter:" in line:
                match = re.search(r"Parameter:\s*(\S+)", line)
                if match:
                    result["injection_points"].append({
                        "parameter": match.group(1),
                        "type": None,
                    })
            
            # Parse injection type
            if "Type:" in line and result["injection_points"]:
                match = re.search(r"Type:\s*(.+)", line)
                if match:
                    result["injection_points"][-1]["type"] = match.group(1).strip()
            
            # Parse DBMS
            if "back-end DBMS:" in line.lower():
                match = re.search(r"back-end DBMS:\s*(.+)", line, re.IGNORECASE)
                if match:
                    result["dbms"] = match.group(1).strip()
            
            # Parse web server
            if "web server operating system:" in line.lower():
                match = re.search(r"web server operating system:\s*(.+)", line, re.IGNORECASE)
                if match:
                    result["os"] = match.group(1).strip()
            
            if "web application technology:" in line.lower():
                match = re.search(r"web application technology:\s*(.+)", line, re.IGNORECASE)
                if match:
                    result["web_server"] = match.group(1).strip()
            
            # Parse databases
            if "available databases" in line.lower():
                current_section = "databases"
            elif current_section == "databases" and line.startswith("[*]"):
                db_name = line.replace("[*]", "").strip()
                if db_name:
                    result["databases"].append(db_name)
            
            # Parse tables
            if "Database:" in line:
                current_section = "tables"
            elif current_section == "tables" and line.startswith("|"):
                table_name = line.strip("|").strip()
                if table_name and not table_name.startswith("-"):
                    result["tables"].append(table_name)
            
            # Track findings
            if "[INFO]" in line:
                info = line.split("[INFO]", 1)[1].strip()
                if any(keyword in info.lower() for keyword in ["vulnerable", "injectable", "detected"]):
                    result["findings"].append({
                        "type": "info",
                        "message": info,
                    })
            
            if "[CRITICAL]" in line:
                critical = line.split("[CRITICAL]", 1)[1].strip()
                result["findings"].append({
                    "type": "critical",
                    "message": critical,
                })
        
        return result

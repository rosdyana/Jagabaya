"""
SSLyze - SSL/TLS configuration analyzer.
"""

from __future__ import annotations

import json
from typing import Any

from jagabaya.tools.base import BaseTool
from jagabaya.models.tools import ToolCategory


class SSLyzeTool(BaseTool):
    """
    SSLyze wrapper - Fast and powerful SSL/TLS scanning.
    
    Analyzes the SSL/TLS configuration of a server by connecting
    to it and testing for supported cipher suites, protocols, etc.
    
    Example:
        >>> tool = SSLyzeTool()
        >>> result = await tool.execute("example.com:443")
    """
    
    name = "sslyze"
    description = "SSL/TLS configuration analyzer"
    category = ToolCategory.SSL_TLS
    binary = "sslyze"
    homepage = "https://github.com/nabla-c0d3/sslyze"
    install_command = "pip install sslyze"
    output_format = "json"
    
    def build_command(self, target: str, **kwargs: Any) -> list[str]:
        """
        Build sslyze command.
        
        Args:
            target: Target host:port
            regular: Run regular scan
            certinfo: Get certificate info
            compression: Test for compression
            early_data: Test for TLS 1.3 early data
            fallback: Test for fallback SCSV
            heartbleed: Test for Heartbleed
            openssl_ccs: Test for OpenSSL CCS injection
            robot: Test for ROBOT attack
            session_renegotiation: Test session renegotiation
            session_resumption: Test session resumption
        """
        args = []
        
        # Output format - JSON to stdout
        args.append("--json_out=-")
        
        # Regular scan (most common tests)
        if kwargs.get("regular", True):
            args.append("--regular")
        
        # Specific scan types
        if kwargs.get("certinfo"):
            args.append("--certinfo")
        
        if kwargs.get("compression"):
            args.append("--compression")
        
        if kwargs.get("early_data"):
            args.append("--early_data")
        
        if kwargs.get("fallback"):
            args.append("--fallback")
        
        if kwargs.get("heartbleed"):
            args.append("--heartbleed")
        
        if kwargs.get("openssl_ccs"):
            args.append("--openssl_ccs")
        
        if kwargs.get("robot"):
            args.append("--robot")
        
        if kwargs.get("session_renegotiation"):
            args.append("--reneg")
        
        if kwargs.get("session_resumption"):
            args.append("--resum")
        
        # Client certificate
        client_cert = kwargs.get("client_cert")
        if client_cert:
            args.extend(["--cert", client_cert])
        
        client_key = kwargs.get("client_key")
        if client_key:
            args.extend(["--key", client_key])
        
        # SNI
        sni = kwargs.get("sni")
        if sni:
            args.extend(["--sni", sni])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        # Target
        args.append(target)
        
        return args
    
    def parse_output(self, output: str) -> dict[str, Any]:
        """Parse sslyze JSON output."""
        result = {
            "target": {},
            "certificate": {},
            "protocols": {},
            "cipher_suites": [],
            "vulnerabilities": [],
            "findings": [],
            "is_vulnerable": False,
            "total": 0,
        }
        
        try:
            data = json.loads(output)
            
            # Parse server scan results
            server_results = data.get("server_scan_results", [])
            
            for server_result in server_results:
                # Target info
                server_info = server_result.get("server_info", {})
                result["target"] = {
                    "hostname": server_info.get("server_location", {}).get("hostname"),
                    "port": server_info.get("server_location", {}).get("port"),
                    "ip_address": server_info.get("server_location", {}).get("ip_address"),
                    "openssl_cipher_suite_name": server_info.get("tls_probing_result", {}).get("cipher_suite_supported"),
                }
                
                scan_commands = server_result.get("scan_commands_results", {})
                
                # Certificate info
                cert_info = scan_commands.get("certificate_info")
                if cert_info:
                    deployments = cert_info.get("certificate_deployments", [])
                    for deployment in deployments:
                        chain = deployment.get("received_certificate_chain", [])
                        if chain:
                            leaf_cert = chain[0]
                            result["certificate"] = {
                                "subject": leaf_cert.get("subject", {}).get("rfc4514_string"),
                                "issuer": leaf_cert.get("issuer", {}).get("rfc4514_string"),
                                "serial_number": leaf_cert.get("serial_number"),
                                "not_valid_before": leaf_cert.get("not_valid_before"),
                                "not_valid_after": leaf_cert.get("not_valid_after"),
                                "signature_algorithm": leaf_cert.get("signature_algorithm_oid"),
                                "public_key_algorithm": leaf_cert.get("public_key", {}).get("algorithm"),
                                "public_key_size": leaf_cert.get("public_key", {}).get("key_size"),
                            }
                            
                            # Check certificate validity
                            verification = deployment.get("leaf_certificate_subject_matches_hostname", True)
                            if not verification:
                                result["findings"].append({
                                    "id": "cert_hostname_mismatch",
                                    "severity": "high",
                                    "finding": "Certificate hostname does not match",
                                })
                                result["is_vulnerable"] = True
                
                # SSL/TLS versions
                for protocol in ["ssl_2_0", "ssl_3_0", "tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"]:
                    proto_result = scan_commands.get(protocol + "_cipher_suites")
                    if proto_result:
                        is_supported = proto_result.get("is_tls_version_supported", False)
                        result["protocols"][protocol] = is_supported
                        
                        if is_supported:
                            accepted_ciphers = proto_result.get("accepted_cipher_suites", [])
                            for cipher in accepted_ciphers:
                                result["cipher_suites"].append({
                                    "protocol": protocol,
                                    "name": cipher.get("cipher_suite", {}).get("name"),
                                    "key_size": cipher.get("cipher_suite", {}).get("key_size"),
                                })
                        
                        # Flag vulnerable protocols
                        if protocol in ["ssl_2_0", "ssl_3_0"] and is_supported:
                            result["vulnerabilities"].append({
                                "id": f"vulnerable_{protocol}",
                                "severity": "critical",
                                "finding": f"{protocol.upper().replace('_', '.')} is enabled (deprecated and insecure)",
                            })
                            result["is_vulnerable"] = True
                        elif protocol in ["tls_1_0", "tls_1_1"] and is_supported:
                            result["vulnerabilities"].append({
                                "id": f"deprecated_{protocol}",
                                "severity": "medium",
                                "finding": f"{protocol.upper().replace('_', '.')} is enabled (deprecated)",
                            })
                
                # Heartbleed
                heartbleed = scan_commands.get("heartbleed")
                if heartbleed and heartbleed.get("is_vulnerable_to_heartbleed"):
                    result["vulnerabilities"].append({
                        "id": "heartbleed",
                        "severity": "critical",
                        "finding": "Server is vulnerable to Heartbleed (CVE-2014-0160)",
                        "cve": "CVE-2014-0160",
                    })
                    result["is_vulnerable"] = True
                
                # ROBOT
                robot = scan_commands.get("robot")
                if robot:
                    robot_result = robot.get("robot_result")
                    if robot_result and "VULNERABLE" in str(robot_result):
                        result["vulnerabilities"].append({
                            "id": "robot",
                            "severity": "high",
                            "finding": "Server is vulnerable to ROBOT attack",
                        })
                        result["is_vulnerable"] = True
                
                # OpenSSL CCS
                ccs = scan_commands.get("openssl_ccs_injection")
                if ccs and ccs.get("is_vulnerable_to_ccs_injection"):
                    result["vulnerabilities"].append({
                        "id": "openssl_ccs_injection",
                        "severity": "high",
                        "finding": "Server is vulnerable to OpenSSL CCS Injection (CVE-2014-0224)",
                        "cve": "CVE-2014-0224",
                    })
                    result["is_vulnerable"] = True
            
        except json.JSONDecodeError as e:
            result["error"] = f"Failed to parse JSON: {e}"
            result["raw"] = output[:1000]
        
        result["total"] = len(result["vulnerabilities"]) + len(result["findings"])
        
        return result

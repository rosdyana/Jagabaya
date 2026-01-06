"""
Nmap XML output parser.

Properly parses Nmap's XML output format for structured data.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any


def parse_nmap_xml(xml_output: str) -> dict[str, Any]:
    """
    Parse Nmap XML output into structured data.
    
    Args:
        xml_output: Raw XML output from nmap -oX
    
    Returns:
        Parsed data with hosts, ports, services, and scripts
    """
    result = {
        "hosts": [],
        "ports": [],
        "services": [],
        "os_matches": [],
        "scripts": [],
        "summary": {},
    }
    
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        # Try to extract just the XML portion
        start = xml_output.find("<?xml")
        if start == -1:
            start = xml_output.find("<nmaprun")
        if start != -1:
            try:
                root = ET.fromstring(xml_output[start:])
            except ET.ParseError:
                return {"error": "Failed to parse XML output", "raw": xml_output[:1000]}
        else:
            return {"error": "No XML content found", "raw": xml_output[:1000]}
    
    # Parse scan info
    if root.tag == "nmaprun":
        result["summary"] = {
            "scanner": root.get("scanner", "nmap"),
            "args": root.get("args", ""),
            "start_time": root.get("startstr", ""),
            "version": root.get("version", ""),
        }
    
    # Parse hosts
    for host in root.findall(".//host"):
        host_data = _parse_host(host)
        if host_data:
            result["hosts"].append(host_data)
            result["ports"].extend(host_data.get("ports", []))
            result["services"].extend(host_data.get("services", []))
            result["os_matches"].extend(host_data.get("os_matches", []))
            result["scripts"].extend(host_data.get("scripts", []))
    
    # Parse runstats
    runstats = root.find(".//runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            result["summary"]["end_time"] = finished.get("timestr", "")
            result["summary"]["elapsed"] = finished.get("elapsed", "")
        
        hosts_stat = runstats.find("hosts")
        if hosts_stat is not None:
            result["summary"]["hosts_up"] = int(hosts_stat.get("up", 0))
            result["summary"]["hosts_down"] = int(hosts_stat.get("down", 0))
            result["summary"]["hosts_total"] = int(hosts_stat.get("total", 0))
    
    return result


def _parse_host(host: ET.Element) -> dict[str, Any] | None:
    """Parse a single host element."""
    # Check host status
    status = host.find("status")
    if status is not None and status.get("state") != "up":
        return None
    
    host_data: dict[str, Any] = {
        "status": "up",
        "addresses": [],
        "hostnames": [],
        "ports": [],
        "services": [],
        "os_matches": [],
        "scripts": [],
    }
    
    # Parse addresses
    for addr in host.findall("address"):
        addr_type = addr.get("addrtype", "ipv4")
        addr_value = addr.get("addr", "")
        host_data["addresses"].append({
            "type": addr_type,
            "address": addr_value,
        })
        if addr_type == "ipv4":
            host_data["ip"] = addr_value
        elif addr_type == "mac":
            host_data["mac"] = addr_value
            vendor = addr.get("vendor")
            if vendor:
                host_data["mac_vendor"] = vendor
    
    # Parse hostnames
    hostnames = host.find("hostnames")
    if hostnames is not None:
        for hostname in hostnames.findall("hostname"):
            host_data["hostnames"].append({
                "name": hostname.get("name", ""),
                "type": hostname.get("type", ""),
            })
    
    # Parse ports
    ports = host.find("ports")
    if ports is not None:
        for port in ports.findall("port"):
            port_data = _parse_port(port, host_data.get("ip", ""))
            if port_data:
                host_data["ports"].append(port_data)
                if port_data.get("service"):
                    host_data["services"].append(port_data["service"])
                if port_data.get("scripts"):
                    host_data["scripts"].extend(port_data["scripts"])
    
    # Parse OS detection
    os_elem = host.find("os")
    if os_elem is not None:
        for osmatch in os_elem.findall("osmatch"):
            os_data = {
                "name": osmatch.get("name", ""),
                "accuracy": int(osmatch.get("accuracy", 0)),
                "os_classes": [],
            }
            for osclass in osmatch.findall("osclass"):
                os_data["os_classes"].append({
                    "type": osclass.get("type", ""),
                    "vendor": osclass.get("vendor", ""),
                    "os_family": osclass.get("osfamily", ""),
                    "os_gen": osclass.get("osgen", ""),
                    "accuracy": int(osclass.get("accuracy", 0)),
                })
            host_data["os_matches"].append(os_data)
    
    # Parse host scripts
    hostscript = host.find("hostscript")
    if hostscript is not None:
        for script in hostscript.findall("script"):
            host_data["scripts"].append({
                "id": script.get("id", ""),
                "output": script.get("output", ""),
                "host": host_data.get("ip", ""),
            })
    
    return host_data


def _parse_port(port: ET.Element, host_ip: str) -> dict[str, Any] | None:
    """Parse a single port element."""
    state = port.find("state")
    if state is None or state.get("state") != "open":
        return None
    
    port_data: dict[str, Any] = {
        "port": int(port.get("portid", 0)),
        "protocol": port.get("protocol", "tcp"),
        "state": "open",
        "host": host_ip,
    }
    
    # Parse service
    service = port.find("service")
    if service is not None:
        service_data = {
            "name": service.get("name", "unknown"),
            "port": port_data["port"],
            "protocol": port_data["protocol"],
            "host": host_ip,
        }
        
        product = service.get("product")
        if product:
            service_data["product"] = product
        
        version = service.get("version")
        if version:
            service_data["version"] = version
        
        extrainfo = service.get("extrainfo")
        if extrainfo:
            service_data["extra_info"] = extrainfo
        
        tunnel = service.get("tunnel")
        if tunnel:
            service_data["tunnel"] = tunnel
        
        port_data["service"] = service_data
    
    # Parse scripts
    scripts = []
    for script in port.findall("script"):
        script_data = {
            "id": script.get("id", ""),
            "output": script.get("output", ""),
            "port": port_data["port"],
            "host": host_ip,
        }
        
        # Parse script tables/elements if present
        for table in script.findall("table"):
            script_data["table"] = _parse_script_table(table)
        
        scripts.append(script_data)
    
    if scripts:
        port_data["scripts"] = scripts
    
    return port_data


def _parse_script_table(table: ET.Element) -> dict[str, Any]:
    """Parse script table elements."""
    result: dict[str, Any] = {}
    
    key = table.get("key")
    if key:
        result["_key"] = key
    
    for elem in table.findall("elem"):
        elem_key = elem.get("key", "value")
        result[elem_key] = elem.text
    
    for subtable in table.findall("table"):
        subtable_key = subtable.get("key", "subtable")
        result[subtable_key] = _parse_script_table(subtable)
    
    return result

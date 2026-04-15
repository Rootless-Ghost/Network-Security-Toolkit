"""
Host and service enumeration.
Detailed probing of discovered hosts for banners, versions, and metadata.
"""

from __future__ import annotations

import logging
import socket
from typing import Dict, List, Optional

from network_mapper.models import Host, NetworkTopology, Service, ServiceState

logger = logging.getLogger(__name__)

try:
    import nmap

    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# Known-dangerous service signatures for quick tagging
_DANGEROUS_SIGNATURES: Dict[str, List[str]] = {
    "telnet": ["telnet"],
    "ftp_anon": ["vsftpd", "proftpd", "pure-ftpd"],
    "smb": ["microsoft-ds", "netbios-ssn", "smb"],
    "rdp": ["ms-wbt-server", "rdp"],
    "vnc": ["vnc"],
    "snmp": ["snmp"],
    "redis_exposed": ["redis"],
    "mongodb_exposed": ["mongodb"],
    "elasticsearch_exposed": ["elasticsearch"],
    "memcached_exposed": ["memcached"],
}

# Port → service name mapping for fallback
_PORT_NAMES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2181: "zookeeper", 2375: "docker", 3306: "mysql",
    3389: "ms-wbt-server", 4444: "metasploit", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 6443: "k8s-api", 7001: "weblogic",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    27018: "mongodb", 28017: "mongodb-http",
}


class ServiceEnumerator:
    """
    Performs detailed enumeration of services on discovered hosts.
    Falls back to basic banner grabbing when nmap is not available.
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self._nm = nmap.PortScanner() if NMAP_AVAILABLE else None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enumerate_host(self, host: Host, ports: str = "") -> Host:
        """Enumerate all services on a single host."""
        if NMAP_AVAILABLE:
            return self._nmap_enumerate(host, ports)
        return self._basic_enumerate(host, ports)

    def enumerate_topology(self, topology: NetworkTopology, ports: str = "") -> NetworkTopology:
        """Enumerate all live hosts in a topology."""
        for host in topology.get_live_hosts():
            logger.info("Enumerating %s", host.ip)
            self.enumerate_host(host, ports)
        return topology

    def tag_dangerous_services(self, topology: NetworkTopology) -> None:
        """Tag hosts with dangerous service labels based on known signatures."""
        for host in topology.get_live_hosts():
            for svc in host.get_open_services():
                for tag, signatures in _DANGEROUS_SIGNATURES.items():
                    if any(sig in svc.name.lower() for sig in signatures):
                        if tag not in host.tags:
                            host.tags.append(tag)
                        if tag not in svc.vulnerabilities:
                            svc.vulnerabilities.append(f"potentially_exposed:{tag}")

    # ------------------------------------------------------------------
    # nmap-based enumeration
    # ------------------------------------------------------------------

    def _nmap_enumerate(self, host: Host, ports: str) -> Host:
        port_arg = ports or "1-65535"
        try:
            self._nm.scan(
                hosts=host.ip,
                ports=port_arg,
                arguments="-sV --version-intensity 5 -T4 --open",
            )
        except Exception as exc:
            logger.error("nmap enumeration failed for %s: %s", host.ip, exc)
            return self._basic_enumerate(host, ports)

        if host.ip not in self._nm.all_hosts():
            return host

        host_data = self._nm[host.ip]
        if host_data.hostname() and not host.hostname:
            host.hostname = host_data.hostname()

        host.services.clear()
        for proto in host_data.all_protocols():
            for port, pdata in host_data[proto].items():
                state_str = pdata.get("state", "closed")
                if state_str == "open":
                    state = ServiceState.OPEN
                elif state_str == "filtered":
                    state = ServiceState.FILTERED
                else:
                    continue
                svc = Service(
                    port=port,
                    protocol=proto,
                    name=pdata.get("name", _PORT_NAMES.get(port, "unknown")),
                    state=state,
                    product=pdata.get("product", ""),
                    version=pdata.get("version", ""),
                    extra_info=pdata.get("extrainfo", ""),
                    cpe=pdata.get("cpe", ""),
                )
                host.services.append(svc)

        return host

    # ------------------------------------------------------------------
    # Fallback: basic TCP banner grabbing
    # ------------------------------------------------------------------

    def _basic_enumerate(self, host: Host, ports: str) -> Host:
        port_list = self._parse_ports(ports)
        host.services.clear()
        for port in port_list:
            banner, open_ = self._grab_banner(host.ip, port)
            if open_:
                svc = Service(
                    port=port,
                    protocol="tcp",
                    name=_PORT_NAMES.get(port, "unknown"),
                    state=ServiceState.OPEN,
                    extra_info=banner,
                )
                host.services.append(svc)
        return host

    def _grab_banner(self, ip: str, port: int) -> tuple[str, bool]:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                except Exception:
                    banner = ""
                return banner[:200], True
        except OSError:
            return "", False

    @staticmethod
    def _parse_ports(ports: str) -> List[int]:
        result: List[int] = []
        if not ports:
            # Default common ports
            result = list(_PORT_NAMES.keys())
            result.sort()
            return result
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                result.extend(range(int(start), int(end) + 1))
            else:
                result.append(int(part))
        return sorted(set(result))

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    @staticmethod
    def summarize(topology: NetworkTopology) -> Dict:
        total_hosts = topology.host_count()
        live_hosts = len(topology.get_live_hosts())
        all_services: List[Service] = []
        for host in topology.get_live_hosts():
            all_services.extend(host.get_open_services())

        service_counts: Dict[str, int] = {}
        for svc in all_services:
            service_counts[svc.name] = service_counts.get(svc.name, 0) + 1

        top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_hosts": total_hosts,
            "live_hosts": live_hosts,
            "total_open_ports": len(all_services),
            "top_services": top_services,
        }

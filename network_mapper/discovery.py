"""
Network topology discovery and mapping.
Performs host discovery, subnet scanning, and builds the network graph.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Tuple

from network_mapper.models import (
    Host,
    HostStatus,
    NetworkEdge,
    NetworkTopology,
    Service,
    ServiceState,
)

logger = logging.getLogger(__name__)

try:
    import nmap

    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning("python-nmap not installed. Some discovery features will be limited.")


class NetworkDiscovery:
    """
    Discovers network topology via ping sweeps, ARP, and nmap.
    Builds a NetworkTopology from the discovered data.
    """

    # Common ports used to infer network connectivity edges
    GATEWAY_PORTS = {80, 443, 22, 23, 8080, 8443}
    COMMON_PORTS = "21-23,25,53,80,110,135,139,143,389,443,445,3306,3389,5900,8080,8443"

    def __init__(
        self,
        targets: List[str],
        timeout: float = 2.0,
        max_workers: int = 50,
        progress_callback: Optional[Callable[[str], None]] = None,
    ):
        self.targets = targets
        self.timeout = timeout
        self.max_workers = max_workers
        self.progress_callback = progress_callback or (lambda msg: None)
        self._nm = nmap.PortScanner() if NMAP_AVAILABLE else None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover(self) -> NetworkTopology:
        """Full topology discovery: expand targets, ping sweep, build graph."""
        topology = NetworkTopology()
        topology.subnets = [t for t in self.targets if "/" in t]

        all_ips = self._expand_targets()
        self.progress_callback(f"[*] Expanded targets to {len(all_ips)} IP(s)")

        live_ips = self._ping_sweep(all_ips)
        self.progress_callback(f"[*] Found {len(live_ips)} live host(s)")

        for ip in live_ips:
            host = Host(ip=ip, status=HostStatus.UP)
            topology.add_host(host)

        # Build simple connectivity edges from shared subnet membership
        self._infer_edges(topology)

        import datetime
        topology.scan_time = datetime.datetime.utcnow()
        return topology

    def discover_with_services(self, ports: Optional[str] = None) -> NetworkTopology:
        """Discovery + service scan in one pass (uses nmap if available)."""
        if NMAP_AVAILABLE:
            return self._nmap_discover(ports or self.COMMON_PORTS)
        topology = self.discover()
        from network_mapper.enumeration import ServiceEnumerator
        enumerator = ServiceEnumerator(timeout=self.timeout)
        for host in topology.get_live_hosts():
            enumerator.enumerate_host(host, ports or self.COMMON_PORTS)
        return topology

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _expand_targets(self) -> List[str]:
        ips: List[str] = []
        for target in self.targets:
            target = target.strip()
            if not target:
                continue
            try:
                if "/" in target:
                    network = ipaddress.ip_network(target, strict=False)
                    ips.extend(str(ip) for ip in network.hosts())
                elif "-" in target.split(".")[-1]:
                    # Range notation: 192.168.1.1-50
                    base, rng = target.rsplit(".", 1)
                    start, end = rng.split("-")
                    for i in range(int(start), int(end) + 1):
                        ips.append(f"{base}.{i}")
                else:
                    # Single IP or hostname
                    resolved = socket.gethostbyname(target)
                    ips.append(resolved)
            except (ValueError, socket.gaierror) as exc:
                logger.warning("Invalid target %s: %s", target, exc)
        return list(dict.fromkeys(ips))  # deduplicate, preserve order

    def _ping_sweep(self, ips: List[str]) -> List[str]:
        live: List[str] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._is_host_up, ip): ip for ip in ips}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    if fut.result():
                        live.append(ip)
                except Exception as exc:
                    logger.debug("Ping check error for %s: %s", ip, exc)
        return sorted(live, key=lambda ip: [int(o) for o in ip.split(".")])

    def _is_host_up(self, ip: str) -> bool:
        # 1. Try a TCP connect to port 80 or 443
        for port in (80, 443, 22, 445, 3389):
            try:
                with socket.create_connection((ip, port), timeout=self.timeout):
                    return True
            except OSError:
                pass
        # 2. ICMP ping via OS command (cross-platform)
        try:
            cmd = (
                ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
                if sys.platform == "win32"
                else ["ping", "-c", "1", "-W", str(int(self.timeout)), ip]
            )
            return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        except Exception:
            return False

    def _nmap_discover(self, ports: str) -> NetworkTopology:
        """Use nmap for combined host discovery + service scan."""
        import datetime

        topology = NetworkTopology()
        topology.subnets = [t for t in self.targets if "/" in t]

        target_str = " ".join(self.targets)
        self.progress_callback(f"[*] Running nmap scan against: {target_str}")

        try:
            self._nm.scan(
                hosts=target_str,
                ports=ports,
                arguments="-sV -O --osscan-guess -T4 --open",
            )
        except Exception as exc:
            logger.error("nmap scan failed: %s", exc)
            return self.discover()

        for ip in self._nm.all_hosts():
            host_data = self._nm[ip]
            status = HostStatus.UP if host_data.state() == "up" else HostStatus.DOWN
            hostname = ""
            if host_data.hostname():
                hostname = host_data.hostname()

            os_info = ""
            if "osmatch" in host_data and host_data["osmatch"]:
                best = host_data["osmatch"][0]
                os_info = f"{best.get('name', '')} ({best.get('accuracy', '')}%)"

            host = Host(ip=ip, hostname=hostname, status=status, os_info=os_info)

            for proto in host_data.all_protocols():
                for port, pdata in host_data[proto].items():
                    state = ServiceState.OPEN if pdata["state"] == "open" else ServiceState.FILTERED
                    svc = Service(
                        port=port,
                        protocol=proto,
                        name=pdata.get("name", "unknown"),
                        state=state,
                        product=pdata.get("product", ""),
                        version=pdata.get("version", ""),
                        extra_info=pdata.get("extrainfo", ""),
                        cpe=pdata.get("cpe", ""),
                    )
                    host.services.append(svc)

            topology.add_host(host)
            self.progress_callback(f"[+] Discovered: {ip} ({hostname or 'no hostname'}) — {len(host.services)} service(s)")

        self._infer_edges(topology)
        topology.scan_time = datetime.datetime.utcnow()
        return topology

    def _infer_edges(self, topology: NetworkTopology) -> None:
        """
        Infer network edges based on subnet membership.
        Hosts in the same /24 (or specified subnet) are connected.
        """
        hosts = list(topology.hosts.keys())
        for i, src in enumerate(hosts):
            for dst in hosts[i + 1 :]:
                if self._same_subnet(src, dst):
                    topology.add_edge(NetworkEdge(source=src, target=dst, weight=1.0))

    @staticmethod
    def _same_subnet(ip1: str, ip2: str, prefix: int = 24) -> bool:
        try:
            n1 = ipaddress.ip_interface(f"{ip1}/{prefix}").network
            n2 = ipaddress.ip_interface(f"{ip2}/{prefix}").network
            return n1 == n2
        except ValueError:
            return False

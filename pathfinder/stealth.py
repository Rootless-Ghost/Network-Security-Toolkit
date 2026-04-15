"""
Stealth scanning capabilities.
Wraps NetworkMapper discovery with slower, less detectable scan parameters
to reduce the chance of triggering IDS/IPS alerts during authorized assessments.
"""

from __future__ import annotations

import logging
import random
import socket
import time
from typing import Callable, List, Optional

from network_mapper.models import Host, NetworkTopology, Service, ServiceState
from network_mapper.discovery import NetworkDiscovery

logger = logging.getLogger(__name__)

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class StealthScanner:
    """
    Performs low-and-slow network scanning to minimise IDS/IPS detection
    during authorized penetration testing engagements.

    Techniques employed:
    - Randomised port and host ordering
    - Configurable per-probe delay (rate limiting)
    - Fragmented SYN scans via nmap when available
    - Decoy scan support
    - Half-open (SYN) scanning
    """

    # Default nmap stealth arguments
    _STEALTH_NMAP_ARGS = (
        "-sS "              # SYN (half-open) scan
        "-T2 "              # Polite timing
        "--randomize-hosts "
        "--data-length 25 " # Add random data to packets (evade signature matching)
        "--max-retries 1 "
        "--host-timeout 60s "
    )

    _PARANOID_NMAP_ARGS = (
        "-sS "
        "-T1 "              # Paranoid — very slow
        "--randomize-hosts "
        "--scan-delay 2s "
        "--max-retries 1 "
    )

    def __init__(
        self,
        delay_range: tuple[float, float] = (0.5, 2.0),
        randomize: bool = True,
        paranoid: bool = False,
        decoys: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
    ):
        self.delay_range = delay_range
        self.randomize = randomize
        self.paranoid = paranoid
        self.decoys = decoys or []
        self.progress_callback = progress_callback or (lambda m: None)
        self._nm = nmap.PortScanner() if NMAP_AVAILABLE else None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        targets: List[str],
        ports: str = "21-23,25,53,80,135,139,443,445,3389,8080",
    ) -> NetworkTopology:
        """
        Perform a stealth scan of the given targets and return a NetworkTopology.
        Falls back to a slow TCP connect scan if nmap is not available.
        """
        if NMAP_AVAILABLE:
            return self._nmap_stealth_scan(targets, ports)
        return self._fallback_stealth_scan(targets, ports)

    # ------------------------------------------------------------------
    # nmap-based stealth scan
    # ------------------------------------------------------------------

    def _nmap_stealth_scan(self, targets: List[str], ports: str) -> NetworkTopology:
        import datetime

        args = self._PARANOID_NMAP_ARGS if self.paranoid else self._STEALTH_NMAP_ARGS
        if self.decoys:
            decoy_str = ",".join(self.decoys)
            args += f"-D {decoy_str} "
        args += f"-p {ports}"

        target_str = " ".join(targets)
        self.progress_callback(f"[~] Stealth scan starting: {target_str}")
        self.progress_callback(f"[~] nmap args: {args.strip()}")

        try:
            self._nm.scan(hosts=target_str, arguments=args)
        except Exception as exc:
            logger.error("Stealth nmap scan failed: %s", exc)
            return self._fallback_stealth_scan(targets, ports)

        topology = NetworkTopology()
        topology.subnets = [t for t in targets if "/" in t]

        for ip in self._nm.all_hosts():
            from network_mapper.models import HostStatus
            host_data = self._nm[ip]
            status = HostStatus.UP if host_data.state() == "up" else HostStatus.DOWN
            host = Host(
                ip=ip,
                hostname=host_data.hostname(),
                status=status,
            )
            for proto in host_data.all_protocols():
                for port, pdata in host_data[proto].items():
                    if pdata["state"] in ("open", "filtered"):
                        svc = Service(
                            port=port,
                            protocol=proto,
                            name=pdata.get("name", "unknown"),
                            state=ServiceState.OPEN if pdata["state"] == "open" else ServiceState.FILTERED,
                            product=pdata.get("product", ""),
                            version=pdata.get("version", ""),
                        )
                        host.services.append(svc)
            topology.add_host(host)
            self.progress_callback(f"[~] Stealthily probed: {ip} ({len(host.services)} port(s))")

        topology.scan_time = datetime.datetime.utcnow()
        return topology

    # ------------------------------------------------------------------
    # Fallback: slow TCP connect scan
    # ------------------------------------------------------------------

    def _fallback_stealth_scan(self, targets: List[str], ports: str) -> NetworkTopology:
        import datetime
        from network_mapper.discovery import NetworkDiscovery
        from network_mapper.models import HostStatus

        disc = NetworkDiscovery(
            targets=targets,
            timeout=3.0,
            progress_callback=self.progress_callback,
        )
        all_ips = disc._expand_targets()

        if self.randomize:
            random.shuffle(all_ips)

        topology = NetworkTopology()
        topology.subnets = [t for t in targets if "/" in t]

        port_list = self._parse_ports(ports)
        if self.randomize:
            random.shuffle(port_list)

        for ip in all_ips:
            self._jitter()
            host = Host(ip=ip)
            live = False
            for port in port_list:
                self._jitter()
                try:
                    with socket.create_connection((ip, port), timeout=2.0):
                        svc = Service(
                            port=port,
                            protocol="tcp",
                            name="unknown",
                            state=ServiceState.OPEN,
                        )
                        host.services.append(svc)
                        live = True
                        self.progress_callback(f"[~] {ip}:{port} open")
                except OSError:
                    pass

            if live:
                host.status = HostStatus.UP
                topology.add_host(host)

        disc._infer_edges(topology)
        topology.scan_time = datetime.datetime.utcnow()
        return topology

    def _jitter(self) -> None:
        delay = random.uniform(*self.delay_range)
        time.sleep(delay)

    @staticmethod
    def _parse_ports(ports: str) -> List[int]:
        result: List[int] = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                result.extend(range(int(start), int(end) + 1))
            else:
                try:
                    result.append(int(part))
                except ValueError:
                    pass
        return list(set(result))

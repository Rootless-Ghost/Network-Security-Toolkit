"""
Network baseline management and change detection.
Saves topology snapshots and compares them to detect new hosts,
removed hosts, and service changes.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from network_mapper.models import Host, NetworkTopology, Service, ServiceState

logger = logging.getLogger(__name__)


@dataclass
class ChangeEvent:
    kind: str          # new_host, removed_host, new_service, removed_service, service_changed
    host_ip: str
    detail: str
    severity: str = "INFO"   # INFO, WARN, CRITICAL

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "host": self.host_ip,
            "detail": self.detail,
            "severity": self.severity,
        }


@dataclass
class BaselineDiff:
    baseline_time: Optional[str]
    current_time: str
    new_hosts: List[str] = field(default_factory=list)
    removed_hosts: List[str] = field(default_factory=list)
    changed_hosts: List[str] = field(default_factory=list)
    events: List[ChangeEvent] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_hosts or self.removed_hosts or self.changed_hosts)

    @property
    def critical_changes(self) -> List[ChangeEvent]:
        return [e for e in self.events if e.severity == "CRITICAL"]

    def to_dict(self) -> dict:
        return {
            "baseline_time": self.baseline_time,
            "current_time": self.current_time,
            "summary": {
                "new_hosts": len(self.new_hosts),
                "removed_hosts": len(self.removed_hosts),
                "changed_hosts": len(self.changed_hosts),
                "total_events": len(self.events),
                "critical_events": len(self.critical_changes),
            },
            "new_hosts": self.new_hosts,
            "removed_hosts": self.removed_hosts,
            "changed_hosts": self.changed_hosts,
            "events": [e.to_dict() for e in self.events],
        }


class BaselineManager:
    """
    Stores and compares network topology snapshots to detect changes.
    Baselines are saved as JSON files and can be compared to current scans
    to identify rogue hosts, new services, and suspicious changes.
    """

    def __init__(self, baseline_dir: str = "./baselines"):
        self.baseline_dir = baseline_dir
        os.makedirs(baseline_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Save / load
    # ------------------------------------------------------------------

    def save(self, topology: NetworkTopology, name: str = "latest") -> str:
        """Save a topology as a named baseline. Returns the file path."""
        path = self._path(name)
        data = topology.to_dict()
        data["_baseline_name"] = name
        data["_saved_at"] = datetime.utcnow().isoformat()
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        logger.info("Baseline '%s' saved to %s", name, path)
        return path

    def load(self, name: str = "latest") -> Optional[NetworkTopology]:
        """Load a named baseline topology. Returns None if not found."""
        path = self._path(name)
        if not os.path.exists(path):
            logger.warning("Baseline '%s' not found at %s", name, path)
            return None
        with open(path) as fh:
            data = json.load(fh)
        return NetworkTopology.from_dict(data)

    def list_baselines(self) -> List[str]:
        """Return names of all saved baselines."""
        names = []
        for fname in os.listdir(self.baseline_dir):
            if fname.endswith(".json"):
                names.append(fname[:-5])
        return sorted(names)

    def delete(self, name: str) -> bool:
        """Delete a named baseline. Returns True if deleted."""
        path = self._path(name)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    # ------------------------------------------------------------------
    # Comparison
    # ------------------------------------------------------------------

    def compare(
        self,
        current: NetworkTopology,
        baseline_name: str = "latest",
    ) -> BaselineDiff:
        """
        Compare the current topology against a saved baseline.
        Returns a BaselineDiff describing all detected changes.
        """
        baseline = self.load(baseline_name)
        current_time = datetime.utcnow().isoformat()

        if baseline is None:
            logger.warning("No baseline '%s' found; treating all hosts as new.", baseline_name)
            diff = BaselineDiff(baseline_time=None, current_time=current_time)
            for ip in current.hosts:
                diff.new_hosts.append(ip)
                diff.events.append(ChangeEvent(
                    kind="new_host", host_ip=ip,
                    detail=f"No baseline — {ip} first seen",
                    severity="INFO",
                ))
            return diff

        baseline_time = (
            baseline.scan_time.isoformat() if baseline.scan_time else "unknown"
        )
        diff = BaselineDiff(baseline_time=baseline_time, current_time=current_time)

        baseline_ips: Set[str] = set(baseline.hosts.keys())
        current_ips: Set[str] = set(current.hosts.keys())

        # New hosts
        for ip in current_ips - baseline_ips:
            diff.new_hosts.append(ip)
            diff.events.append(ChangeEvent(
                kind="new_host",
                host_ip=ip,
                detail=f"New host {ip} not in baseline",
                severity="CRITICAL",
            ))

        # Removed hosts
        for ip in baseline_ips - current_ips:
            diff.removed_hosts.append(ip)
            diff.events.append(ChangeEvent(
                kind="removed_host",
                host_ip=ip,
                detail=f"Host {ip} present in baseline but not in current scan",
                severity="WARN",
            ))

        # Changed hosts
        for ip in current_ips & baseline_ips:
            events = self._compare_host(baseline.hosts[ip], current.hosts[ip])
            if events:
                diff.changed_hosts.append(ip)
                diff.events.extend(events)

        return diff

    def compare_with_alert_threshold(
        self,
        current: NetworkTopology,
        baseline_name: str = "latest",
        alert_on_new_hosts: bool = True,
        alert_on_new_services: bool = True,
    ) -> Tuple[BaselineDiff, bool]:
        """Returns (diff, should_alert) based on configured thresholds."""
        diff = self.compare(current, baseline_name)
        should_alert = False
        if alert_on_new_hosts and diff.new_hosts:
            should_alert = True
        if alert_on_new_services and any(
            e.kind == "new_service" for e in diff.events
        ):
            should_alert = True
        return diff, should_alert

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compare_host(self, baseline: Host, current: Host) -> List[ChangeEvent]:
        events: List[ChangeEvent] = []
        ip = current.ip

        baseline_ports: Dict[int, Service] = {s.port: s for s in baseline.get_open_services()}
        current_ports: Dict[int, Service] = {s.port: s for s in current.get_open_services()}

        # New services
        for port, svc in current_ports.items():
            if port not in baseline_ports:
                severity = "CRITICAL" if port in (22, 23, 80, 443, 445, 3389) else "WARN"
                events.append(ChangeEvent(
                    kind="new_service",
                    host_ip=ip,
                    detail=f"New service: {ip}:{port}/{svc.protocol} ({svc.name} {svc.banner})",
                    severity=severity,
                ))

        # Removed services
        for port in baseline_ports:
            if port not in current_ports:
                events.append(ChangeEvent(
                    kind="removed_service",
                    host_ip=ip,
                    detail=f"Service gone: {ip}:{port}",
                    severity="INFO",
                ))

        # Version changes
        for port in current_ports:
            if port in baseline_ports:
                old_banner = baseline_ports[port].banner
                new_banner = current_ports[port].banner
                if old_banner and new_banner and old_banner != new_banner:
                    events.append(ChangeEvent(
                        kind="service_changed",
                        host_ip=ip,
                        detail=f"{ip}:{port} version changed: '{old_banner}' -> '{new_banner}'",
                        severity="INFO",
                    ))

        return events

    def _path(self, name: str) -> str:
        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
        return os.path.join(self.baseline_dir, f"{safe_name}.json")

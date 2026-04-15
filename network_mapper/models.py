"""
Standardized data structures for network information.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class HostStatus(Enum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class ServiceState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    name: str = "unknown"
    state: ServiceState = ServiceState.OPEN
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: str = ""
    vulnerabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "name": self.name,
            "state": self.state.value,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "cpe": self.cpe,
            "vulnerabilities": self.vulnerabilities,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Service":
        data = dict(data)
        data["state"] = ServiceState(data.get("state", "open"))
        return cls(**data)

    @property
    def banner(self) -> str:
        parts = [p for p in (self.product, self.version, self.extra_info) if p]
        return " ".join(parts) if parts else self.name


@dataclass
class Host:
    ip: str
    hostname: str = ""
    mac: str = ""
    os_info: str = ""
    status: HostStatus = HostStatus.UNKNOWN
    services: List[Service] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_open_services(self) -> List[Service]:
        return [s for s in self.services if s.state == ServiceState.OPEN]

    def has_port(self, port: int) -> bool:
        return any(s.port == port for s in self.get_open_services())

    def get_service(self, port: int) -> Optional[Service]:
        for svc in self.services:
            if svc.port == port:
                return svc
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac": self.mac,
            "os_info": self.os_info,
            "status": self.status.value,
            "services": [s.to_dict() for s in self.services],
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Host":
        data = dict(data)
        data["status"] = HostStatus(data.get("status", "unknown"))
        data["services"] = [Service.from_dict(s) for s in data.get("services", [])]
        return cls(**data)

    def __hash__(self):
        return hash(self.ip)

    def __eq__(self, other):
        return isinstance(other, Host) and self.ip == other.ip


@dataclass
class NetworkEdge:
    source: str  # IP address
    target: str  # IP address
    weight: float = 1.0
    protocol: str = ""
    port: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "weight": self.weight,
            "protocol": self.protocol,
            "port": self.port,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkEdge":
        return cls(**data)


@dataclass
class NetworkPath:
    nodes: List[str]  # Ordered list of IP addresses
    edges: List[NetworkEdge] = field(default_factory=list)
    total_cost: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.nodes)

    def __iter__(self):
        return iter(self.nodes)

    @property
    def hop_count(self) -> int:
        return max(0, len(self.nodes) - 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes,
            "edges": [e.to_dict() for e in self.edges],
            "total_cost": self.total_cost,
            "hop_count": self.hop_count,
            "metadata": self.metadata,
        }


@dataclass
class NetworkTopology:
    hosts: Dict[str, Host] = field(default_factory=dict)
    edges: List[NetworkEdge] = field(default_factory=list)
    subnets: List[str] = field(default_factory=list)
    scan_time: Optional[datetime.datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_host(self, host: Host) -> None:
        self.hosts[host.ip] = host

    def add_edge(self, edge: NetworkEdge) -> None:
        self.edges.append(edge)

    def get_host(self, ip: str) -> Optional[Host]:
        return self.hosts.get(ip)

    def get_live_hosts(self) -> List[Host]:
        return [h for h in self.hosts.values() if h.status == HostStatus.UP]

    def host_count(self) -> int:
        return len(self.hosts)

    def edge_count(self) -> int:
        return len(self.edges)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hosts": {ip: h.to_dict() for ip, h in self.hosts.items()},
            "edges": [e.to_dict() for e in self.edges],
            "subnets": self.subnets,
            "scan_time": self.scan_time.isoformat() if self.scan_time else None,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkTopology":
        topo = cls()
        for ip, hdata in data.get("hosts", {}).items():
            topo.hosts[ip] = Host.from_dict(hdata)
        for edata in data.get("edges", []):
            topo.edges.append(NetworkEdge.from_dict(edata))
        topo.subnets = data.get("subnets", [])
        if data.get("scan_time"):
            topo.scan_time = datetime.datetime.fromisoformat(data["scan_time"])
        topo.metadata = data.get("metadata", {})
        return topo

    @classmethod
    def from_json(cls, json_str: str) -> "NetworkTopology":
        return cls.from_dict(json.loads(json_str))

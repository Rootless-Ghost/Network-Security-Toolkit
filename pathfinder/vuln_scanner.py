"""
Vulnerable service identification.
Scores hosts and services based on known-vulnerable configurations,
exposed management interfaces, and default credentials.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from network_mapper.models import Host, NetworkTopology, Service

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vulnerability signatures
# ---------------------------------------------------------------------------

@dataclass
class VulnSignature:
    id: str
    name: str
    description: str
    cvss: float          # 0.0 – 10.0
    cve: str = ""
    affected_ports: List[int] = field(default_factory=list)
    affected_services: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    remediation: str = ""


_SIGNATURES: List[VulnSignature] = [
    VulnSignature(
        id="TELNET-CLEARTEXT",
        name="Telnet — cleartext protocol",
        description="Telnet transmits credentials in cleartext. Replace with SSH.",
        cvss=8.8,
        affected_ports=[23],
        affected_services=["telnet"],
        remediation="Disable telnet; deploy SSH with key-based authentication.",
    ),
    VulnSignature(
        id="FTP-CLEARTEXT",
        name="FTP — cleartext protocol",
        description="FTP transmits credentials in cleartext. Replace with SFTP/FTPS.",
        cvss=7.5,
        affected_ports=[21],
        affected_services=["ftp"],
        remediation="Disable FTP; use SFTP (SSH) or FTPS with certificate pinning.",
    ),
    VulnSignature(
        id="SMB-EXPOSED",
        name="SMB exposed to network",
        description="SMB (445) exposed. Potential EternalBlue / relay attack vector.",
        cvss=9.8,
        cve="CVE-2017-0144",
        affected_ports=[445, 139],
        affected_services=["microsoft-ds", "netbios-ssn"],
        remediation="Block SMB at perimeter. Patch MS17-010. Disable SMBv1.",
    ),
    VulnSignature(
        id="RDP-EXPOSED",
        name="RDP exposed to network",
        description="RDP (3389) exposed. BlueKeep / credential brute-force risk.",
        cvss=9.8,
        cve="CVE-2019-0708",
        affected_ports=[3389],
        affected_services=["ms-wbt-server"],
        remediation="Restrict RDP to VPN only. Enable NLA. Patch CVE-2019-0708.",
    ),
    VulnSignature(
        id="VNC-EXPOSED",
        name="VNC exposed to network",
        description="VNC (5900) accessible. Often uses weak/no authentication.",
        cvss=9.8,
        affected_ports=[5900, 5901, 5902],
        affected_services=["vnc"],
        remediation="Restrict VNC access. Use strong passwords and tunnel through VPN/SSH.",
    ),
    VulnSignature(
        id="REDIS-NOAUTH",
        name="Redis exposed without authentication",
        description="Redis (6379) accessible without authentication by default.",
        cvss=9.8,
        affected_ports=[6379],
        affected_services=["redis"],
        remediation="Bind Redis to localhost only. Enable AUTH. Use firewall rules.",
    ),
    VulnSignature(
        id="MONGODB-NOAUTH",
        name="MongoDB exposed without authentication",
        description="MongoDB (27017) accessible. Often deployed without authentication.",
        cvss=9.8,
        affected_ports=[27017, 27018, 28017],
        affected_services=["mongodb"],
        remediation="Enable MongoDB authentication. Bind to localhost or VPN.",
    ),
    VulnSignature(
        id="ELASTICSEARCH-EXPOSED",
        name="Elasticsearch exposed",
        description="Elasticsearch (9200) accessible. No built-in auth on older versions.",
        cvss=9.1,
        affected_ports=[9200, 9300],
        affected_services=["elasticsearch"],
        remediation="Enable X-Pack security. Restrict network access via firewall.",
    ),
    VulnSignature(
        id="MEMCACHED-EXPOSED",
        name="Memcached exposed",
        description="Memcached (11211) has no authentication — DDoS amplification vector.",
        cvss=7.5,
        affected_ports=[11211],
        affected_services=["memcached"],
        remediation="Bind memcached to localhost. Block UDP 11211 at firewall.",
    ),
    VulnSignature(
        id="DOCKER-API-EXPOSED",
        name="Docker API exposed",
        description="Docker daemon API (2375) accessible. Full container/host compromise risk.",
        cvss=10.0,
        affected_ports=[2375, 2376],
        affected_services=["docker"],
        remediation="Enable TLS on Docker API. Never expose 2375 to the network.",
    ),
    VulnSignature(
        id="SNMP-DEFAULT",
        name="SNMP with default community strings",
        description="SNMP (161) may be using default 'public'/'private' community strings.",
        cvss=7.5,
        affected_ports=[161, 162],
        affected_services=["snmp"],
        remediation="Change SNMP community strings. Migrate to SNMPv3. Restrict by IP.",
    ),
    VulnSignature(
        id="HTTP-ADMIN-EXPOSED",
        name="HTTP management interface exposed",
        description="Unencrypted HTTP admin panel exposed on non-standard port.",
        cvss=6.5,
        affected_ports=[8080, 8888, 7001, 9090, 9000],
        affected_services=["http-proxy", "http-alt", "weblogic"],
        remediation="Require TLS (HTTPS) for all admin interfaces. Restrict access by IP.",
    ),
    VulnSignature(
        id="MSSQL-EXPOSED",
        name="MSSQL exposed to network",
        description="Microsoft SQL Server (1433) accessible. Brute-force and injection risk.",
        cvss=8.1,
        affected_ports=[1433],
        affected_services=["mssql"],
        remediation="Restrict MSSQL access. Disable SA account. Use Windows Authentication.",
    ),
    VulnSignature(
        id="MYSQL-EXPOSED",
        name="MySQL/MariaDB exposed to network",
        description="MySQL (3306) accessible from network. Credential attack risk.",
        cvss=7.5,
        affected_ports=[3306],
        affected_services=["mysql"],
        remediation="Bind MySQL to localhost. Use strong credentials. Firewall port 3306.",
    ),
    VulnSignature(
        id="POSTGRES-EXPOSED",
        name="PostgreSQL exposed to network",
        description="PostgreSQL (5432) accessible. Trust-mode auth or weak passwords common.",
        cvss=7.5,
        affected_ports=[5432],
        affected_services=["postgresql"],
        remediation="Restrict pg_hba.conf. Disable superuser remote login.",
    ),
]


@dataclass
class VulnFinding:
    host_ip: str
    service: Service
    signature: VulnSignature
    evidence: str = ""

    @property
    def cvss(self) -> float:
        return self.signature.cvss

    @property
    def severity(self) -> str:
        if self.cvss >= 9.0:
            return "CRITICAL"
        elif self.cvss >= 7.0:
            return "HIGH"
        elif self.cvss >= 4.0:
            return "MEDIUM"
        elif self.cvss >= 0.1:
            return "LOW"
        return "INFO"

    def to_dict(self) -> dict:
        return {
            "host": self.host_ip,
            "port": self.service.port,
            "service": self.service.name,
            "vuln_id": self.signature.id,
            "name": self.signature.name,
            "cvss": self.signature.cvss,
            "severity": self.severity,
            "cve": self.signature.cve,
            "description": self.signature.description,
            "remediation": self.signature.remediation,
            "evidence": self.evidence,
        }


class VulnScanner:
    """
    Matches discovered services against known vulnerability signatures.
    Scores each host and returns prioritised findings.
    """

    def __init__(self):
        self.signatures = _SIGNATURES

    def scan_topology(self, topology: NetworkTopology) -> List[VulnFinding]:
        findings: List[VulnFinding] = []
        for host in topology.get_live_hosts():
            findings.extend(self.scan_host(host))
        return sorted(findings, key=lambda f: f.cvss, reverse=True)

    def scan_host(self, host: Host) -> List[VulnFinding]:
        findings: List[VulnFinding] = []
        for svc in host.get_open_services():
            for sig in self.signatures:
                if self._matches(svc, sig):
                    evidence = f"{svc.port}/{svc.protocol} {svc.banner}"
                    finding = VulnFinding(
                        host_ip=host.ip,
                        service=svc,
                        signature=sig,
                        evidence=evidence,
                    )
                    findings.append(finding)
                    # Tag the service
                    if sig.id not in svc.vulnerabilities:
                        svc.vulnerabilities.append(sig.id)
        return findings

    def score_host(self, host: Host) -> float:
        """Return a risk score (0–10) for a host based on its findings."""
        findings = self.scan_host(host)
        if not findings:
            return 0.0
        # Max CVSS drives the score, with diminishing bonus for additional findings
        scores = sorted([f.cvss for f in findings], reverse=True)
        base = scores[0]
        bonus = sum(s * 0.05 for s in scores[1:])
        return min(10.0, base + bonus)

    def host_scores(self, topology: NetworkTopology) -> Dict[str, float]:
        return {host.ip: self.score_host(host) for host in topology.get_live_hosts()}

    @staticmethod
    def _matches(svc: Service, sig: VulnSignature) -> bool:
        if sig.affected_ports and svc.port in sig.affected_ports:
            return True
        svc_name = svc.name.lower()
        if sig.affected_services and any(s in svc_name for s in sig.affected_services):
            return True
        svc_product = svc.product.lower()
        if sig.affected_products and any(p in svc_product for p in sig.affected_products):
            return True
        return False

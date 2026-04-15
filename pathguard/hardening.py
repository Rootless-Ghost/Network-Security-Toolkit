"""
Security hardening recommendations.
Generates actionable hardening guidance per host based on discovered services,
OS, and known misconfigurations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from network_mapper.models import Host, NetworkTopology, Service

logger = logging.getLogger(__name__)


@dataclass
class HardeningRule:
    id: str
    title: str
    description: str
    rationale: str
    remediation: str
    cis_reference: str = ""
    nist_reference: str = ""
    priority: int = 3    # 1=Critical, 2=High, 3=Medium, 4=Low
    triggered_by_ports: List[int] = field(default_factory=list)
    triggered_by_services: List[str] = field(default_factory=list)
    triggered_always: bool = False

    @property
    def priority_label(self) -> str:
        return {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}.get(self.priority, "MEDIUM")


_RULES: List[HardeningRule] = [
    HardeningRule(
        id="H-001",
        title="Disable Telnet — replace with SSH",
        description="Telnet (port 23) transmits all data including credentials in cleartext.",
        rationale="Cleartext protocols allow credential theft via passive network sniffing.",
        remediation=(
            "1. Install and configure SSH (OpenSSH/libssh).\n"
            "2. Migrate all Telnet users to SSH key-based authentication.\n"
            "3. Disable and remove the telnetd service.\n"
            "4. Block TCP 23 at the host firewall and perimeter."
        ),
        cis_reference="CIS Control 4.1",
        nist_reference="NIST SP 800-53 SC-8",
        priority=1,
        triggered_by_ports=[23],
        triggered_by_services=["telnet"],
    ),
    HardeningRule(
        id="H-002",
        title="Disable FTP — use SFTP or FTPS",
        description="FTP (port 21) transmits credentials and data in cleartext.",
        rationale="Passive sniffing can capture FTP credentials and file contents.",
        remediation=(
            "1. Replace FTP with SFTP (SSH-based) or FTPS (TLS-encrypted FTP).\n"
            "2. Disable vsftpd/proftpd service.\n"
            "3. Block TCP 21 at the firewall.\n"
            "4. Audit existing FTP users and migrate to key-based SFTP."
        ),
        cis_reference="CIS Control 4.1",
        nist_reference="NIST SP 800-53 SC-8",
        priority=1,
        triggered_by_ports=[21],
        triggered_by_services=["ftp"],
    ),
    HardeningRule(
        id="H-003",
        title="Restrict SMB access — patch and disable SMBv1",
        description="SMB on ports 445/139 is a frequent lateral movement vector.",
        rationale="EternalBlue (MS17-010) and related vulnerabilities exploit SMB. SMBv1 is insecure.",
        remediation=(
            "1. Apply all Windows security patches (especially MS17-010).\n"
            "2. Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false\n"
            "3. Block outbound TCP 445 at the perimeter.\n"
            "4. Restrict SMB to necessary hosts only via host-based firewall.\n"
            "5. Enable SMB signing to prevent relay attacks."
        ),
        cis_reference="CIS Control 18.3",
        nist_reference="NIST SP 800-53 CM-7",
        priority=1,
        triggered_by_ports=[445, 139],
        triggered_by_services=["microsoft-ds", "netbios-ssn"],
    ),
    HardeningRule(
        id="H-004",
        title="Restrict RDP — require NLA and VPN",
        description="RDP (port 3389) exposed to the network is a high-risk attack vector.",
        rationale="BlueKeep (CVE-2019-0708), brute force, and pass-the-hash attacks target RDP.",
        remediation=(
            "1. Enable Network Level Authentication (NLA).\n"
            "2. Restrict RDP access to VPN or Jump-box only.\n"
            "3. Apply all patches including CVE-2019-0708.\n"
            "4. Block TCP 3389 at the perimeter firewall.\n"
            "5. Enable RDP account lockout policies."
        ),
        cis_reference="CIS Control 4.3",
        nist_reference="NIST SP 800-53 AC-17",
        priority=1,
        triggered_by_ports=[3389],
        triggered_by_services=["ms-wbt-server"],
    ),
    HardeningRule(
        id="H-005",
        title="Secure VNC — require strong authentication and tunnel",
        description="VNC (port 5900) often uses weak passwords or no encryption.",
        rationale="Unauthenticated or weakly authenticated VNC allows full desktop takeover.",
        remediation=(
            "1. Set a strong VNC password (12+ characters).\n"
            "2. Tunnel VNC over SSH: ssh -L 5900:localhost:5900 user@host\n"
            "3. Block TCP 5900 at the firewall.\n"
            "4. Consider replacing VNC with a managed remote desktop solution."
        ),
        cis_reference="CIS Control 4.3",
        nist_reference="NIST SP 800-53 AC-17",
        priority=1,
        triggered_by_ports=[5900, 5901, 5902],
        triggered_by_services=["vnc"],
    ),
    HardeningRule(
        id="H-006",
        title="Enable Redis authentication and bind to localhost",
        description="Redis (port 6379) has no authentication by default.",
        rationale="Unauthenticated Redis allows arbitrary data access and potentially RCE.",
        remediation=(
            "1. Set a strong password: requirepass <strong-password> in redis.conf.\n"
            "2. Bind to localhost: bind 127.0.0.1 in redis.conf.\n"
            "3. Enable protected-mode yes.\n"
            "4. Block TCP 6379 at the firewall.\n"
            "5. Run Redis as a non-privileged user."
        ),
        cis_reference="CIS Control 4.1",
        nist_reference="NIST SP 800-53 IA-5",
        priority=1,
        triggered_by_ports=[6379],
        triggered_by_services=["redis"],
    ),
    HardeningRule(
        id="H-007",
        title="Enable MongoDB authentication",
        description="MongoDB (port 27017) is often deployed without authentication.",
        rationale="Unauthenticated MongoDB allows complete data exfiltration or destruction.",
        remediation=(
            "1. Enable authentication: security.authorization: enabled in mongod.conf.\n"
            "2. Create admin user with strong password.\n"
            "3. Bind to localhost or VPN network only.\n"
            "4. Block TCP 27017 at the firewall.\n"
            "5. Enable TLS/SSL for MongoDB connections."
        ),
        cis_reference="CIS Control 4.1",
        nist_reference="NIST SP 800-53 IA-5",
        priority=1,
        triggered_by_ports=[27017, 27018, 28017],
        triggered_by_services=["mongodb"],
    ),
    HardeningRule(
        id="H-008",
        title="Secure Elasticsearch with X-Pack / TLS",
        description="Elasticsearch (port 9200) has no built-in auth on older versions.",
        rationale="Exposed Elasticsearch allows data access and deletion without credentials.",
        remediation=(
            "1. Enable X-Pack security (Elasticsearch 6.3+).\n"
            "2. Set xpack.security.enabled: true in elasticsearch.yml.\n"
            "3. Configure TLS for node-to-node and client communication.\n"
            "4. Bind to internal network only; block 9200/9300 at the perimeter."
        ),
        cis_reference="CIS Control 4.1",
        nist_reference="NIST SP 800-53 IA-5",
        priority=1,
        triggered_by_ports=[9200, 9300],
        triggered_by_services=["elasticsearch"],
    ),
    HardeningRule(
        id="H-009",
        title="Secure Docker API — enable TLS",
        description="Docker daemon API (port 2375) allows unauthenticated container management.",
        rationale="Unauthenticated Docker API allows container escape to host root.",
        remediation=(
            "1. Never expose port 2375; use 2376 with TLS only.\n"
            "2. Generate CA, server, and client certificates.\n"
            "3. Start dockerd with --tlsverify --tlscacert --tlscert --tlskey.\n"
            "4. Block TCP 2375 at the firewall immediately."
        ),
        cis_reference="CIS Docker Benchmark 2.6",
        nist_reference="NIST SP 800-53 CM-7",
        priority=1,
        triggered_by_ports=[2375, 2376],
        triggered_by_services=["docker"],
    ),
    HardeningRule(
        id="H-010",
        title="Change SNMP default community strings",
        description="SNMP (port 161) often uses default 'public'/'private' community strings.",
        rationale="Default SNMP strings allow network topology discovery and config disclosure.",
        remediation=(
            "1. Change community strings to complex, unique values.\n"
            "2. Upgrade to SNMPv3 with authentication and encryption.\n"
            "3. Restrict SNMP access to specific management hosts (ACL).\n"
            "4. Disable SNMP if not required."
        ),
        cis_reference="CIS Control 11",
        nist_reference="NIST SP 800-53 CM-6",
        priority=2,
        triggered_by_ports=[161, 162],
        triggered_by_services=["snmp"],
    ),
    HardeningRule(
        id="H-011",
        title="Enforce HTTPS — redirect all HTTP traffic",
        description="Plain HTTP (port 80) exposes sensitive data to sniffing.",
        rationale="HTTP credentials and session tokens are visible to network attackers.",
        remediation=(
            "1. Obtain and install a valid TLS certificate (Let's Encrypt or CA-signed).\n"
            "2. Redirect HTTP (80) to HTTPS (443) with 301 redirects.\n"
            "3. Enable HSTS (Strict-Transport-Security header).\n"
            "4. Configure TLS 1.2+ only; disable TLS 1.0 and TLS 1.1."
        ),
        cis_reference="CIS Control 9.2",
        nist_reference="NIST SP 800-53 SC-8",
        priority=2,
        triggered_by_ports=[80, 8080],
        triggered_by_services=["http"],
    ),
    HardeningRule(
        id="H-012",
        title="Enable host-based firewall",
        description="No evidence of port filtering suggests host-based firewall may be inactive.",
        rationale="Host-based firewalls provide defence-in-depth even when perimeter controls fail.",
        remediation=(
            "1. Enable iptables/nftables (Linux) or Windows Defender Firewall.\n"
            "2. Default-deny inbound; whitelist only required services.\n"
            "3. Log dropped packets to SIEM.\n"
            "4. Review firewall rules quarterly."
        ),
        cis_reference="CIS Control 12.4",
        nist_reference="NIST SP 800-53 SC-7",
        priority=3,
        triggered_always=True,
    ),
    HardeningRule(
        id="H-013",
        title="Deploy network segmentation",
        description="Flat network topology enables unrestricted lateral movement.",
        rationale="Network segmentation limits the blast radius of a compromised host.",
        remediation=(
            "1. Identify and group hosts by function (servers, workstations, IoT, DMZ).\n"
            "2. Deploy VLANs or SDN micro-segmentation.\n"
            "3. Apply ACLs between segments: default-deny with explicit allows.\n"
            "4. Place internet-facing services in a DMZ segment."
        ),
        cis_reference="CIS Control 12",
        nist_reference="NIST SP 800-53 SC-7",
        priority=2,
        triggered_always=True,
    ),
]


@dataclass
class HardeningRecommendation:
    rule: HardeningRule
    host_ip: str
    triggered_service: Optional[Service] = None

    @property
    def priority(self) -> int:
        return self.rule.priority

    @property
    def priority_label(self) -> str:
        return self.rule.priority_label

    def to_dict(self) -> dict:
        return {
            "host": self.host_ip,
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "priority": self.priority_label,
            "priority_num": self.priority,
            "cis_reference": self.rule.cis_reference,
            "nist_reference": self.rule.nist_reference,
            "description": self.rule.description,
            "rationale": self.rule.rationale,
            "remediation": self.rule.remediation,
            "triggered_port": self.triggered_service.port if self.triggered_service else None,
        }


class HardeningAdvisor:
    """
    Generates hardening recommendations for each host based on
    discovered services and known-insecure configurations.
    """

    def __init__(self):
        self.rules = _RULES

    def analyze_host(self, host: Host) -> List[HardeningRecommendation]:
        recs: List[HardeningRecommendation] = []
        seen_rule_ids: set = set()

        for rule in self.rules:
            if rule.id in seen_rule_ids:
                continue

            if rule.triggered_always:
                recs.append(HardeningRecommendation(rule=rule, host_ip=host.ip))
                seen_rule_ids.add(rule.id)
                continue

            for svc in host.get_open_services():
                triggered = (
                    (rule.triggered_by_ports and svc.port in rule.triggered_by_ports)
                    or (rule.triggered_by_services and any(s in svc.name.lower() for s in rule.triggered_by_services))
                )
                if triggered and rule.id not in seen_rule_ids:
                    recs.append(HardeningRecommendation(rule=rule, host_ip=host.ip, triggered_service=svc))
                    seen_rule_ids.add(rule.id)
                    break

        recs.sort(key=lambda r: r.priority)
        return recs

    def analyze_topology(self, topology: NetworkTopology) -> Dict[str, List[HardeningRecommendation]]:
        results: Dict[str, List[HardeningRecommendation]] = {}
        for host in topology.get_live_hosts():
            recs = self.analyze_host(host)
            if recs:
                results[host.ip] = recs
        return results

    def get_all_recommendations(
        self, topology: NetworkTopology
    ) -> List[HardeningRecommendation]:
        all_recs = []
        for recs in self.analyze_topology(topology).values():
            all_recs.extend(recs)
        all_recs.sort(key=lambda r: r.priority)
        return all_recs

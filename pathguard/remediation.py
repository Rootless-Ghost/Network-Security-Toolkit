"""
Remediation recommendations with priority scoring.
Consolidates findings from vulnerability scanning, hardening analysis,
and choke point data to produce an ordered remediation roadmap.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from network_mapper.models import NetworkTopology
from pathguard.choke_points import ChokePointAnalyzer
from pathguard.hardening import HardeningAdvisor, HardeningRecommendation
from pathguard.vuln_priority import PrioritizedFinding, VulnPrioritizer

logger = logging.getLogger(__name__)


@dataclass
class RemediationTask:
    id: str
    title: str
    description: str
    affected_hosts: List[str]
    steps: List[str]
    priority_score: float          # 0–10; higher = do first
    effort: str                    # low / medium / high
    impact: str                    # low / medium / high
    category: str                  # vuln / hardening / architecture
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    @property
    def priority_label(self) -> str:
        if self.priority_score >= 9.0:
            return "P1 — Immediate"
        elif self.priority_score >= 7.0:
            return "P2 — Urgent"
        elif self.priority_score >= 5.0:
            return "P3 — Important"
        elif self.priority_score >= 3.0:
            return "P4 — Planned"
        return "P5 — Optional"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "priority": self.priority_label,
            "priority_score": round(self.priority_score, 1),
            "title": self.title,
            "category": self.category,
            "effort": self.effort,
            "impact": self.impact,
            "affected_hosts": self.affected_hosts,
            "description": self.description,
            "steps": self.steps,
            "references": self.references,
            "tags": self.tags,
        }


class RemediationPlanner:
    """
    Builds a prioritised remediation roadmap from multiple analysis sources:
    - Vulnerability findings (from VulnScanner)
    - Hardening recommendations (from HardeningAdvisor)
    - Architecture observations (from ChokePointAnalyzer)

    Tasks are deduplicated, consolidated by type, and scored by:
    1. Exploitability (CVSS / position multiplier)
    2. Number of affected hosts (shared infrastructure gets higher priority)
    3. Ease of remediation (quick wins surfaced early)
    """

    def __init__(self, topology: NetworkTopology):
        self.topology = topology
        self._vuln_prioritizer = VulnPrioritizer(topology)
        self._hardening_advisor = HardeningAdvisor()
        self._choke_analyzer = ChokePointAnalyzer(topology)

    def build_roadmap(self, max_tasks: int = 30) -> List[RemediationTask]:
        """Build the full remediation roadmap, sorted by priority score."""
        tasks: List[RemediationTask] = []
        tasks.extend(self._tasks_from_vulns())
        tasks.extend(self._tasks_from_hardening())
        tasks.extend(self._tasks_from_architecture())

        # Deduplicate by title (consolidate same-issue tasks across hosts)
        tasks = self._consolidate(tasks)
        tasks.sort(key=lambda t: t.priority_score, reverse=True)
        return tasks[:max_tasks]

    def export_json(self, path: str, max_tasks: int = 30) -> str:
        """Export the roadmap to a JSON file."""
        roadmap = self.build_roadmap(max_tasks)
        data = {
            "total_tasks": len(roadmap),
            "generated_at": __import__("datetime").datetime.utcnow().isoformat(),
            "tasks": [t.to_dict() for t in roadmap],
        }
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        logger.info("Remediation roadmap saved to %s", path)
        return path

    # ------------------------------------------------------------------
    # Task generators
    # ------------------------------------------------------------------

    def _tasks_from_vulns(self) -> List[RemediationTask]:
        pf_list = self._vuln_prioritizer.top_priorities(n=50)
        tasks: Dict[str, RemediationTask] = {}

        for pf in pf_list:
            key = pf.finding.signature.id
            if key in tasks:
                if pf.finding.host_ip not in tasks[key].affected_hosts:
                    tasks[key].affected_hosts.append(pf.finding.host_ip)
                tasks[key].priority_score = max(tasks[key].priority_score, pf.composite_score)
            else:
                sig = pf.finding.signature
                steps = [
                    step.strip()
                    for step in sig.remediation.strip().splitlines()
                    if step.strip()
                ]
                task = RemediationTask(
                    id=f"REM-VULN-{sig.id}",
                    title=sig.name,
                    description=sig.description,
                    affected_hosts=[pf.finding.host_ip],
                    steps=steps,
                    priority_score=pf.composite_score,
                    effort=self._estimate_effort(sig.remediation),
                    impact="high" if pf.base_cvss >= 7.0 else "medium",
                    category="vuln",
                    references=[sig.cve] if sig.cve else [],
                    tags=["vulnerability", f"cvss-{pf.base_cvss}"],
                )
                tasks[key] = task

        return list(tasks.values())

    def _tasks_from_hardening(self) -> List[RemediationTask]:
        host_recs = self._hardening_advisor.analyze_topology(self.topology)
        tasks: Dict[str, RemediationTask] = {}

        for ip, recs in host_recs.items():
            for rec in recs:
                key = rec.rule.id
                if key in tasks:
                    if ip not in tasks[key].affected_hosts:
                        tasks[key].affected_hosts.append(ip)
                else:
                    steps = [
                        step.strip()
                        for step in rec.rule.remediation.strip().splitlines()
                        if step.strip()
                    ]
                    # Priority score: invert rule priority (1=critical → 9, 4=low → 3)
                    score = max(1.0, 10.0 - (rec.rule.priority * 2.0))
                    task = RemediationTask(
                        id=f"REM-HARD-{rec.rule.id}",
                        title=rec.rule.title,
                        description=rec.rule.description,
                        affected_hosts=[ip],
                        steps=steps,
                        priority_score=score,
                        effort=self._estimate_effort(rec.rule.remediation),
                        impact="high" if rec.rule.priority <= 2 else "medium",
                        category="hardening",
                        references=[
                            r for r in [rec.rule.cis_reference, rec.rule.nist_reference] if r
                        ],
                        tags=["hardening", rec.rule.priority_label.lower()],
                    )
                    tasks[key] = task

        return list(tasks.values())

    def _tasks_from_architecture(self) -> List[RemediationTask]:
        tasks: List[RemediationTask] = []
        choke_points = self._choke_analyzer.identify_choke_points()
        articulation = [cp for cp in choke_points if cp.is_articulation]

        if articulation:
            art_ips = [cp.ip for cp in articulation]
            tasks.append(RemediationTask(
                id="REM-ARCH-001",
                title="Eliminate single points of failure (articulation nodes)",
                description=(
                    f"{len(articulation)} host(s) are network articulation points — "
                    "their compromise or failure disconnects parts of the network."
                ),
                affected_hosts=art_ips,
                steps=[
                    "1. Add redundant network paths to eliminate single points of failure.",
                    "2. Deploy additional switches/routers to distribute traffic.",
                    "3. Implement spanning tree or ECMP for link redundancy.",
                    "4. Prioritise hardening and monitoring on these hosts.",
                    "5. Consider isolating these nodes in dedicated VLANs.",
                ],
                priority_score=8.5,
                effort="high",
                impact="high",
                category="architecture",
                tags=["architecture", "resilience"],
            ))

        # Flat network
        components = self._choke_analyzer._path_analyzer.connected_components()
        if len(components) == 1 and len(self.topology.hosts) > 5:
            tasks.append(RemediationTask(
                id="REM-ARCH-002",
                title="Implement network segmentation",
                description=(
                    "The network appears flat — all hosts are in a single connected component. "
                    "This enables unrestricted lateral movement after initial compromise."
                ),
                affected_hosts=[h.ip for h in self.topology.get_live_hosts()],
                steps=[
                    "1. Define network zones: DMZ, servers, workstations, IoT, management.",
                    "2. Implement VLANs with 802.1Q tagging on managed switches.",
                    "3. Deploy inter-VLAN routing with stateful firewall ACLs.",
                    "4. Default-deny all inter-VLAN traffic; whitelist only required flows.",
                    "5. Place internet-facing services in the DMZ.",
                    "6. Create a dedicated management VLAN for admin access.",
                ],
                priority_score=9.0,
                effort="high",
                impact="high",
                category="architecture",
                tags=["architecture", "segmentation"],
            ))

        return tasks

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _consolidate(tasks: List[RemediationTask]) -> List[RemediationTask]:
        """Merge duplicate tasks by ID."""
        seen: Dict[str, RemediationTask] = {}
        for task in tasks:
            if task.id in seen:
                for host in task.affected_hosts:
                    if host not in seen[task.id].affected_hosts:
                        seen[task.id].affected_hosts.append(host)
                seen[task.id].priority_score = max(seen[task.id].priority_score, task.priority_score)
            else:
                seen[task.id] = task
        return list(seen.values())

    @staticmethod
    def _estimate_effort(remediation_text: str) -> str:
        steps = [l for l in remediation_text.strip().splitlines() if l.strip().startswith(("1.", "2.", "3.", "4.", "5."))]
        if len(steps) <= 2:
            return "low"
        elif len(steps) <= 4:
            return "medium"
        return "high"

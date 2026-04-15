#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PathGuard CLI — blue team defensive network analysis.
"""

import argparse
import json
import logging
import sys

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _progress(msg: str) -> None:
    console.print(msg, style="dim cyan")


# ------------------------------------------------------------------
# Command implementations
# ------------------------------------------------------------------

def cmd_analyze(args: argparse.Namespace) -> int:
    from network_mapper.models import NetworkTopology
    from pathguard.choke_points import ChokePointAnalyzer
    from pathguard.hardening import HardeningAdvisor
    from pathguard.vuln_priority import VulnPrioritizer
    from pathguard.controls import SecurityControlAdvisor
    from pathguard.remediation import RemediationPlanner

    with open(args.topology) as fh:
        topology = NetworkTopology.from_json(fh.read())

    console.print(Panel.fit(
        "[bold blue]PathGuard — Defensive Network Analysis[/bold blue]",
        border_style="blue",
    ))
    console.print(f"  Hosts in scope : {topology.host_count()}")
    console.print(f"  Live hosts     : {len(topology.get_live_hosts())}")
    console.print(f"  Network edges  : {topology.edge_count()}")

    # Choke points
    if not args.skip_choke_points:
        cp_analyzer = ChokePointAnalyzer(topology)
        choke_points = cp_analyzer.identify_choke_points(top_n=args.top)
        _print_choke_points(choke_points)

    # Hardening
    if not args.skip_hardening:
        advisor = HardeningAdvisor()
        all_recs = advisor.get_all_recommendations(topology)
        _print_hardening(all_recs[:args.top * 2])

    # Vulnerability prioritization
    if not args.skip_vulns:
        prioritizer = VulnPrioritizer(topology)
        pf_list = prioritizer.top_priorities(n=args.top)
        _print_prioritized_vulns(pf_list)

    # Security control recommendations
    if not args.skip_controls:
        ctrl_advisor = SecurityControlAdvisor(topology)
        placements = ctrl_advisor.recommend(top_n=args.top)
        _print_controls(placements)

    # JSON report
    if args.report:
        _save_report(topology, args.report)
        console.print(f"[green]Report saved to {args.report}[/green]")

    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    from network_mapper.models import NetworkTopology
    from pathguard.baseline import BaselineManager

    manager = BaselineManager(baseline_dir=args.baseline_dir)

    if args.save:
        with open(args.topology) as fh:
            topology = NetworkTopology.from_json(fh.read())
        path = manager.save(topology, name=args.name)
        console.print(f"[green]Baseline '{args.name}' saved to {path}[/green]")
        return 0

    if args.compare:
        with open(args.topology) as fh:
            topology = NetworkTopology.from_json(fh.read())
        diff = manager.compare(topology, baseline_name=args.name)
        _print_diff(diff)
        if args.report:
            with open(args.report, "w") as fh:
                json.dump(diff.to_dict(), fh, indent=2)
            console.print(f"[green]Diff report saved to {args.report}[/green]")
        return 0

    if args.list:
        baselines = manager.list_baselines()
        if baselines:
            console.print("\n[bold]Saved baselines:[/bold]")
            for name in baselines:
                console.print(f"  - {name}")
        else:
            console.print("[yellow]No baselines saved yet.[/yellow]")
        return 0

    console.print("[yellow]Specify --save, --compare, or --list.[/yellow]")
    return 1


def cmd_remediate(args: argparse.Namespace) -> int:
    from network_mapper.models import NetworkTopology
    from pathguard.remediation import RemediationPlanner

    with open(args.topology) as fh:
        topology = NetworkTopology.from_json(fh.read())

    planner = RemediationPlanner(topology)
    roadmap = planner.build_roadmap(max_tasks=args.top)

    _print_roadmap(roadmap)

    if args.report:
        planner.export_json(args.report, max_tasks=args.top)
        console.print(f"[green]Remediation roadmap saved to {args.report}[/green]")

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Quick defensive scan: discover + immediately analyse."""
    from network_mapper.discovery import NetworkDiscovery

    disc = NetworkDiscovery(
        targets=args.targets,
        timeout=args.timeout,
        max_workers=args.threads,
        progress_callback=_progress,
    )
    topology = disc.discover_with_services(ports=args.ports)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(topology.to_json())
        console.print(f"[green]Topology saved to {args.output}[/green]")

    # Chain straight into analysis
    if args.analyze:
        import tempfile, os
        tmp = args.output or (
            tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
        )
        if not args.output:
            with open(tmp, "w") as fh:
                fh.write(topology.to_json())

        class _FakeArgs:
            topology = tmp
            top = 10
            report = args.report if hasattr(args, "report") else None
            skip_choke_points = False
            skip_hardening = False
            skip_vulns = False
            skip_controls = False
        cmd_analyze(_FakeArgs())

        if not args.output:
            os.remove(tmp)

    return 0


# ------------------------------------------------------------------
# Print helpers
# ------------------------------------------------------------------

def _print_choke_points(choke_points) -> None:
    if not choke_points:
        console.print("[yellow]No choke points identified.[/yellow]")
        return
    table = Table(title="Network Choke Points", box=box.SIMPLE)
    table.add_column("Host", style="cyan")
    table.add_column("Criticality")
    table.add_column("Betweenness", justify="right")
    table.add_column("Degree", justify="right")
    table.add_column("Articulation")
    table.add_column("Description")
    crit_styles = {
        "CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"
    }
    for cp in choke_points:
        style = crit_styles.get(cp.criticality_label, "white")
        hostname = cp.host.hostname if cp.host and cp.host.hostname else ""
        label = f"{cp.ip}" + (f"\n({hostname})" if hostname else "")
        table.add_row(
            label,
            f"[{style}]{cp.criticality_label}[/{style}]",
            f"{cp.betweenness:.3f}",
            f"{cp.degree:.3f}",
            "YES" if cp.is_articulation else "no",
            cp.description[:40],
        )
    console.print(table)


def _print_hardening(recs) -> None:
    if not recs:
        console.print("[green]No hardening recommendations.[/green]")
        return
    table = Table(title="Hardening Recommendations", box=box.SIMPLE)
    table.add_column("Priority")
    table.add_column("Host", style="cyan")
    table.add_column("Rule ID")
    table.add_column("Finding")
    table.add_column("CIS Ref")
    pri_styles = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}
    for rec in recs:
        style = pri_styles.get(rec.priority_label, "white")
        table.add_row(
            f"[{style}]{rec.priority_label}[/{style}]",
            rec.host_ip,
            rec.rule.id,
            rec.rule.title[:45],
            rec.rule.cis_reference or "—",
        )
    console.print(table)


def _print_prioritized_vulns(pf_list) -> None:
    if not pf_list:
        console.print("[green]No vulnerabilities found.[/green]")
        return
    table = Table(title="Prioritized Vulnerabilities", box=box.SIMPLE)
    table.add_column("Priority")
    table.add_column("Host", style="cyan")
    table.add_column("Port")
    table.add_column("Vulnerability")
    table.add_column("Composite", justify="right")
    table.add_column("Choke Point")
    table.add_column("Likelihood")
    pri_styles = {
        "P1 — Critical": "red", "P2 — High": "orange3",
        "P3 — Medium": "yellow", "P4 — Low": "green", "P5 — Informational": "dim",
    }
    for pf in pf_list:
        style = pri_styles.get(pf.priority_label, "white")
        table.add_row(
            f"[{style}]{pf.priority_label}[/{style}]",
            pf.finding.host_ip,
            str(pf.finding.service.port),
            pf.finding.signature.name[:40],
            f"{pf.composite_score:.1f}",
            "YES" if pf.is_choke_point else "no",
            pf.exploitation_likelihood,
        )
    console.print(table)


def _print_controls(placements) -> None:
    if not placements:
        return
    table = Table(title="Security Control Placement Recommendations", box=box.SIMPLE)
    table.add_column("Priority", justify="right")
    table.add_column("Control")
    table.add_column("Category")
    table.add_column("Cost")
    table.add_column("Effectiveness", justify="right")
    table.add_column("Key Hosts")
    for p in placements:
        hosts = ", ".join(p.recommended_hosts[:3])
        if len(p.recommended_hosts) > 3:
            hosts += f" +{len(p.recommended_hosts) - 3}"
        table.add_row(
            f"{p.priority_score:.0f}",
            p.control.name,
            p.control.category,
            p.control.cost_level,
            f"{p.control.effectiveness:.1f}",
            hosts,
        )
    console.print(table)


def _print_diff(diff) -> None:
    summary = diff.to_dict()["summary"]
    console.print(f"\n[bold]Baseline Comparison[/bold]")
    console.print(f"  Baseline time : {diff.baseline_time or 'N/A'}")
    console.print(f"  Current time  : {diff.current_time}")
    console.print(f"  New hosts     : {summary['new_hosts']}")
    console.print(f"  Removed hosts : {summary['removed_hosts']}")
    console.print(f"  Changed hosts : {summary['changed_hosts']}")
    console.print(f"  Total events  : {summary['total_events']}")
    console.print(f"  Critical      : [red]{summary['critical_events']}[/red]")

    if diff.events:
        table = Table(title="Change Events", box=box.SIMPLE)
        table.add_column("Severity")
        table.add_column("Host", style="cyan")
        table.add_column("Type")
        table.add_column("Detail")
        sev_styles = {"CRITICAL": "red", "WARN": "yellow", "INFO": "dim"}
        for e in sorted(diff.events, key=lambda ev: ev.severity):
            style = sev_styles.get(e.severity, "white")
            table.add_row(
                f"[{style}]{e.severity}[/{style}]",
                e.host_ip,
                e.kind,
                e.detail[:60],
            )
        console.print(table)


def _print_roadmap(roadmap) -> None:
    if not roadmap:
        console.print("[green]No remediation tasks generated.[/green]")
        return
    table = Table(title="Remediation Roadmap", box=box.SIMPLE)
    table.add_column("#", justify="right")
    table.add_column("Priority")
    table.add_column("Category")
    table.add_column("Task")
    table.add_column("Score", justify="right")
    table.add_column("Effort")
    table.add_column("Hosts", justify="right")
    pri_styles = {
        "P1 — Immediate": "red", "P2 — Urgent": "orange3",
        "P3 — Important": "yellow", "P4 — Planned": "green",
        "P5 — Optional": "dim",
    }
    for i, task in enumerate(roadmap, 1):
        style = pri_styles.get(task.priority_label, "white")
        table.add_row(
            str(i),
            f"[{style}]{task.priority_label}[/{style}]",
            task.category,
            task.title[:45],
            f"{task.priority_score:.1f}",
            task.effort,
            str(len(task.affected_hosts)),
        )
    console.print(table)


def _save_report(topology, path: str) -> None:
    from pathguard.choke_points import ChokePointAnalyzer
    from pathguard.hardening import HardeningAdvisor
    from pathguard.vuln_priority import VulnPrioritizer
    from pathguard.controls import SecurityControlAdvisor
    from pathguard.remediation import RemediationPlanner

    cp = ChokePointAnalyzer(topology).identify_choke_points()
    advisor = HardeningAdvisor()
    pf_list = VulnPrioritizer(topology).top_priorities(n=50)
    controls = SecurityControlAdvisor(topology).recommend()
    roadmap = RemediationPlanner(topology).build_roadmap()

    report = {
        "topology_summary": {
            "hosts": topology.host_count(),
            "live_hosts": len(topology.get_live_hosts()),
            "edges": topology.edge_count(),
        },
        "choke_points": [c.to_dict() for c in cp],
        "hardening": [r.to_dict() for r in advisor.get_all_recommendations(topology)],
        "vulnerabilities": [pf.to_dict() for pf in pf_list],
        "control_placements": [c.to_dict() for c in controls],
        "remediation_roadmap": [t.to_dict() for t in roadmap],
    }

    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)


# ------------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pathguard",
        description="PathGuard — Blue team defensive network analysis",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Discover network and immediately analyse defensively")
    p_scan.add_argument("targets", nargs="+", help="IP, CIDR, or hostname")
    p_scan.add_argument("-p", "--ports", default="")
    p_scan.add_argument("-o", "--output", help="Save topology JSON")
    p_scan.add_argument("-t", "--timeout", type=float, default=2.0)
    p_scan.add_argument("--threads", type=int, default=50)
    p_scan.add_argument("--analyze", action="store_true", help="Run full analysis after scan")
    p_scan.add_argument("--report", help="Save JSON analysis report")
    p_scan.set_defaults(func=cmd_scan)

    # analyze
    p_analyze = sub.add_parser("analyze", help="Defensive analysis of a saved topology")
    p_analyze.add_argument("topology", help="Topology JSON file")
    p_analyze.add_argument("--top", type=int, default=10, help="Max items per table")
    p_analyze.add_argument("--report", help="Save JSON report")
    p_analyze.add_argument("--skip-choke-points", action="store_true")
    p_analyze.add_argument("--skip-hardening", action="store_true")
    p_analyze.add_argument("--skip-vulns", action="store_true")
    p_analyze.add_argument("--skip-controls", action="store_true")
    p_analyze.set_defaults(func=cmd_analyze)

    # baseline
    p_baseline = sub.add_parser("baseline", help="Manage and compare network baselines")
    p_baseline.add_argument("--topology", help="Topology JSON file")
    p_baseline.add_argument("--name", default="latest", help="Baseline name")
    p_baseline.add_argument("--baseline-dir", default="./baselines")
    p_baseline.add_argument("--save", action="store_true", help="Save current topology as baseline")
    p_baseline.add_argument("--compare", action="store_true", help="Compare topology to baseline")
    p_baseline.add_argument("--list", action="store_true", help="List saved baselines")
    p_baseline.add_argument("--report", help="Save diff report JSON")
    p_baseline.set_defaults(func=cmd_baseline)

    # remediate
    p_remediate = sub.add_parser("remediate", help="Generate a prioritised remediation roadmap")
    p_remediate.add_argument("topology", help="Topology JSON file")
    p_remediate.add_argument("--top", type=int, default=30)
    p_remediate.add_argument("--report", help="Save JSON roadmap")
    p_remediate.set_defaults(func=cmd_remediate)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    _setup_logging(args.verbose)

    try:
        rc = args.func(args)
        sys.exit(rc or 0)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

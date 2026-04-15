#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PathFinder CLI — red team attack path analysis.

For authorized penetration testing engagements only.
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


def _require_disclaimer(args: argparse.Namespace) -> None:
    if not args.skip_disclaimer:
        from pathfinder.disclaimer import EthicalUseDisclaimer
        EthicalUseDisclaimer.show()


def cmd_scan(args: argparse.Namespace) -> int:
    _require_disclaimer(args)

    if args.stealth:
        from pathfinder.stealth import StealthScanner
        scanner = StealthScanner(
            delay_range=(args.delay_min, args.delay_max),
            randomize=True,
            paranoid=args.paranoid,
            decoys=args.decoys or [],
            progress_callback=_progress,
        )
        topology = scanner.scan(args.targets, ports=args.ports or "21-23,25,53,80,135,139,443,445,3389,8080")
    else:
        from network_mapper.discovery import NetworkDiscovery
        disc = NetworkDiscovery(
            targets=args.targets,
            timeout=args.timeout,
            max_workers=args.threads,
            progress_callback=_progress,
        )
        topology = disc.discover_with_services(ports=args.ports)

    if args.shodan_key:
        from pathfinder.shodan_client import ShodanClient
        client = ShodanClient(args.shodan_key)
        console.print("[cyan]Enriching with Shodan data...[/cyan]")
        client.enrich_topology(topology)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(topology.to_json())
        console.print(f"[green]Topology saved to {args.output}[/green]")
    else:
        console.print("[yellow]Tip: use -o to save topology for further analysis.[/yellow]")

    _print_scan_summary(topology)
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    _require_disclaimer(args)

    from network_mapper.models import NetworkTopology
    from pathfinder.attack_paths import AttackPathFinder
    from pathfinder.lateral_movement import LateralMovementAnalyzer
    from pathfinder.exfil_routes import ExfilRouteAnalyzer

    with open(args.topology) as fh:
        topology = NetworkTopology.from_json(fh.read())

    console.print(Panel.fit("[bold red]PathFinder — Attack Path Analysis[/bold red]", border_style="red"))

    # Vulnerability scan
    from pathfinder.vuln_scanner import VulnScanner
    scanner = VulnScanner()
    findings = scanner.scan_topology(topology)
    scores = scanner.host_scores(topology)

    _print_findings(findings[:args.top])
    _print_host_scores(scores)

    # Attack path mapping
    apf = AttackPathFinder(topology)
    entry = args.entry or _select_entry(scores)
    if not entry:
        console.print("[red]No entry point could be determined. Specify with --entry.[/red]")
        return 1

    targets = args.targets_list.split(",") if args.targets_list else None
    console.print(f"\n[bold]Computing attack paths from [cyan]{entry}[/cyan]...[/bold]")
    attack_paths = apf.find_attack_paths(entry, targets=targets, max_hops=args.max_hops)
    _print_attack_paths(attack_paths[:args.top])

    # Lateral movement
    console.print(f"\n[bold]Lateral movement analysis from [cyan]{entry}[/cyan]...[/bold]")
    lm_analyzer = LateralMovementAnalyzer(topology)
    lm_paths = lm_analyzer.analyze_from(entry, max_hops=args.max_hops)
    _print_lateral_movement(lm_paths[:args.top])

    # Exfil routes
    console.print(f"\n[bold]Exfiltration route analysis...[/bold]")
    exfil = ExfilRouteAnalyzer(topology)
    exfil_routes = exfil.find_exfil_routes(entry)
    _print_exfil_routes(exfil_routes[:args.top])

    # Visualization
    if args.png or args.html:
        from pathfinder.visualization import AttackVisualizer
        viz = AttackVisualizer(topology, risk_scores=scores)
        if args.png:
            viz.save_attack_graph(attack_paths, args.png, entry_point=entry)
            console.print(f"[green]Attack graph PNG saved to {args.png}[/green]")
        if args.html:
            viz.save_interactive_attack_graph(attack_paths, args.html, entry_point=entry)
            console.print(f"[green]Interactive HTML saved to {args.html}[/green]")

    # JSON report
    if args.report:
        report = {
            "entry_point": entry,
            "vulnerability_findings": [f.to_dict() for f in findings],
            "host_risk_scores": scores,
            "attack_paths": [p.to_dict() for p in attack_paths],
            "lateral_movement_paths": [p.to_dict() for p in lm_paths],
            "exfil_routes": [r.to_dict() for r in exfil_routes],
        }
        with open(args.report, "w") as fh:
            json.dump(report, fh, indent=2)
        console.print(f"[green]JSON report saved to {args.report}[/green]")

    return 0


def cmd_shodan(args: argparse.Namespace) -> int:
    _require_disclaimer(args)

    from pathfinder.shodan_client import ShodanClient
    client = ShodanClient(args.api_key)

    if args.ips:
        for ip in args.ips:
            info = client.lookup_host(ip)
            if info:
                console.print_json(json.dumps(info.to_dict(), indent=2))
            else:
                console.print(f"[yellow]No Shodan data for {ip}[/yellow]")
    elif args.query:
        results = client.search_network(args.query, limit=args.limit)
        table = Table(title=f"Shodan Search: {args.query}", box=box.SIMPLE)
        table.add_column("IP")
        table.add_column("Org")
        table.add_column("Country")
        table.add_column("Ports")
        table.add_column("CVEs")
        for r in results:
            table.add_row(
                r.ip, r.org, r.country,
                ", ".join(str(p) for p in r.ports[:5]),
                str(len(r.vulns)),
            )
        console.print(table)

    return 0


# ------------------------------------------------------------------
# Print helpers
# ------------------------------------------------------------------

def _print_scan_summary(topology) -> None:
    from network_mapper.enumeration import ServiceEnumerator
    summary = ServiceEnumerator.summarize(topology)
    console.print(f"\n[bold cyan]Scan Summary[/bold cyan]")
    console.print(f"  Live hosts  : {summary['live_hosts']}")
    console.print(f"  Open ports  : {summary['total_open_ports']}")

    table = Table(title="Discovered Hosts", box=box.SIMPLE)
    table.add_column("IP", style="cyan")
    table.add_column("Hostname")
    table.add_column("OS")
    table.add_column("Ports")
    for host in topology.get_live_hosts():
        ports = ", ".join(str(s.port) for s in host.get_open_services()[:6])
        table.add_row(host.ip, host.hostname or "—", host.os_info[:25] or "—", ports or "—")
    console.print(table)


def _print_findings(findings) -> None:
    if not findings:
        console.print("[green]No vulnerability findings.[/green]")
        return
    table = Table(title="Vulnerability Findings", box=box.SIMPLE)
    table.add_column("Severity", style="bold")
    table.add_column("Host", style="cyan")
    table.add_column("Port")
    table.add_column("Finding")
    table.add_column("CVSS", justify="right")
    table.add_column("CVE")
    sev_styles = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}
    for f in findings:
        sev_style = sev_styles.get(f.severity, "white")
        table.add_row(
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            f.host_ip,
            str(f.service.port),
            f.signature.name,
            f"{f.cvss:.1f}",
            f.signature.cve or "—",
        )
    console.print(table)


def _print_host_scores(scores: dict) -> None:
    if not scores:
        return
    table = Table(title="Host Risk Scores", box=box.SIMPLE)
    table.add_column("Host", style="cyan")
    table.add_column("Risk Score", justify="right")
    table.add_column("Level")
    for ip, score in sorted(scores.items(), key=lambda x: x[1], reverse=True):
        level = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
        styles = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}
        style = styles[level]
        table.add_row(ip, f"{score:.1f}", f"[{style}]{level}[/{style}]")
    console.print(table)


def _print_attack_paths(paths) -> None:
    if not paths:
        console.print("[yellow]No attack paths found.[/yellow]")
        return
    table = Table(title="Attack Paths", box=box.SIMPLE)
    table.add_column("#", justify="right")
    table.add_column("Path", style="cyan")
    table.add_column("Hops", justify="right")
    table.add_column("Difficulty", justify="right")
    table.add_column("Criticality", justify="right")
    table.add_column("Severity")
    sev_styles = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}
    for i, p in enumerate(paths, 1):
        sev = p.severity_label
        style = sev_styles.get(sev, "white")
        table.add_row(
            str(i),
            " -> ".join(p.nodes),
            str(p.hop_count),
            f"{p.total_difficulty:.1f}",
            f"{p.criticality_score:.1f}",
            f"[{style}]{sev}[/{style}]",
        )
    console.print(table)


def _print_lateral_movement(paths) -> None:
    if not paths:
        console.print("[yellow]No lateral movement paths found.[/yellow]")
        return
    table = Table(title="Lateral Movement Paths", box=box.SIMPLE)
    table.add_column("#", justify="right")
    table.add_column("Path", style="cyan")
    table.add_column("Technique")
    table.add_column("Hops", justify="right")
    table.add_column("Priv Gain", justify="right")
    for i, p in enumerate(paths[:10], 1):
        techniques = ", ".join(dict.fromkeys(s.technique.name for s in p.steps))
        table.add_row(
            str(i),
            f"{p.entry_ip} -> {p.final_ip}",
            techniques[:40],
            str(p.hop_count),
            f"{p.total_privilege_gain:.1f}",
        )
    console.print(table)


def _print_exfil_routes(routes) -> None:
    if not routes:
        console.print("[yellow]No exfiltration routes identified.[/yellow]")
        return
    table = Table(title="Exfiltration Routes", box=box.SIMPLE)
    table.add_column("Egress", style="cyan")
    table.add_column("Best Channel")
    table.add_column("Stealth", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Route")
    for r in routes:
        ch = r.best_channel
        table.add_row(
            r.egress_ip,
            ch.name if ch else "—",
            f"{r.stealth_score:.1f}",
            f"{r.risk_score:.1f}",
            " -> ".join(r.path_nodes),
        )
    console.print(table)


def _select_entry(scores: dict) -> str:
    """Pick the lowest-risk host as entry point (attacker's foothold)."""
    if not scores:
        return ""
    return min(scores, key=lambda ip: scores[ip])


# ------------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pathfinder",
        description=(
            "PathFinder — Red team attack path analysis tool. "
            "For authorized penetration testing only."
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--skip-disclaimer", action="store_true",
                        help="Skip the ethical use disclaimer (use with care)")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Discover and fingerprint a target network")
    p_scan.add_argument("targets", nargs="+", help="IP, CIDR, or hostname")
    p_scan.add_argument("-p", "--ports", default="", help="Port spec")
    p_scan.add_argument("-o", "--output", help="Save topology JSON")
    p_scan.add_argument("-t", "--timeout", type=float, default=2.0)
    p_scan.add_argument("--threads", type=int, default=50)
    p_scan.add_argument("--stealth", action="store_true", help="Enable stealth scanning mode")
    p_scan.add_argument("--paranoid", action="store_true", help="Maximum stealth (T1 timing)")
    p_scan.add_argument("--delay-min", type=float, default=0.5, help="Min inter-probe delay (stealth mode)")
    p_scan.add_argument("--delay-max", type=float, default=2.0, help="Max inter-probe delay (stealth mode)")
    p_scan.add_argument("--decoys", nargs="*", help="Decoy IPs for stealth scan")
    p_scan.add_argument("--shodan-key", help="Shodan API key for external enrichment")
    p_scan.set_defaults(func=cmd_scan)

    # analyze
    p_analyze = sub.add_parser("analyze", help="Perform attack path analysis on a saved topology")
    p_analyze.add_argument("topology", help="Topology JSON file (from 'scan -o')")
    p_analyze.add_argument("--entry", help="Attacker entry point IP (default: auto-selected)")
    p_analyze.add_argument("--targets-list", help="Comma-separated target IPs")
    p_analyze.add_argument("--max-hops", type=int, default=6)
    p_analyze.add_argument("--top", type=int, default=10, help="Max results per table")
    p_analyze.add_argument("--png", help="Save attack graph PNG")
    p_analyze.add_argument("--html", help="Save interactive attack HTML")
    p_analyze.add_argument("--report", help="Save JSON report")
    p_analyze.set_defaults(func=cmd_analyze)

    # shodan
    p_shodan = sub.add_parser("shodan", help="Shodan API lookups")
    p_shodan.add_argument("api_key", help="Shodan API key")
    p_shodan.add_argument("--ips", nargs="*", help="IP addresses to look up")
    p_shodan.add_argument("--query", help="Shodan search query")
    p_shodan.add_argument("--limit", type=int, default=50)
    p_shodan.set_defaults(func=cmd_shodan)

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

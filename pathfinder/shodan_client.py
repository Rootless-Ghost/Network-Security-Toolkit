"""
Shodan API integration for external attack surface discovery.
Enriches NetworkTopology hosts with internet-facing exposure data.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from network_mapper.models import Host, NetworkTopology, Service, ServiceState

logger = logging.getLogger(__name__)

try:
    import shodan as shodan_lib
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    logger.warning("shodan library not installed: pip install shodan")


@dataclass
class ShodanHostInfo:
    ip: str
    org: str = ""
    isp: str = ""
    country: str = ""
    city: str = ""
    hostnames: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)       # CVE IDs
    banners: List[Dict[str, Any]] = field(default_factory=list)
    last_update: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "org": self.org,
            "isp": self.isp,
            "country": self.country,
            "city": self.city,
            "hostnames": self.hostnames,
            "ports": self.ports,
            "vulns": self.vulns,
            "last_update": self.last_update,
            "tags": self.tags,
        }


class ShodanClient:
    """
    Wraps the Shodan API to discover external exposure data for given IPs
    and enrich a NetworkTopology accordingly.
    """

    def __init__(self, api_key: str):
        if not SHODAN_AVAILABLE:
            raise RuntimeError(
                "shodan library is required: pip install shodan"
            )
        self._api = shodan_lib.Shodan(api_key)
        self._verify_key()

    def _verify_key(self) -> None:
        try:
            info = self._api.info()
            logger.info(
                "Shodan API connected. Plan: %s, Credits remaining: %s",
                info.get("plan"),
                info.get("query_credits"),
            )
        except shodan_lib.APIError as exc:
            raise RuntimeError(f"Shodan API key invalid or unreachable: {exc}") from exc

    # ------------------------------------------------------------------
    # Host lookup
    # ------------------------------------------------------------------

    def lookup_host(self, ip: str) -> Optional[ShodanHostInfo]:
        """Look up a single IP on Shodan."""
        try:
            data = self._api.host(ip)
            return self._parse_host(data)
        except shodan_lib.APIError as exc:
            if "No information available" in str(exc):
                logger.debug("No Shodan data for %s", ip)
                return None
            logger.warning("Shodan lookup failed for %s: %s", ip, exc)
            return None

    def lookup_hosts(self, ips: List[str]) -> Dict[str, ShodanHostInfo]:
        """Batch-lookup multiple IPs."""
        results: Dict[str, ShodanHostInfo] = {}
        for ip in ips:
            info = self.lookup_host(ip)
            if info:
                results[ip] = info
        return results

    # ------------------------------------------------------------------
    # Network-level enrichment
    # ------------------------------------------------------------------

    def enrich_topology(self, topology: NetworkTopology) -> Dict[str, ShodanHostInfo]:
        """
        Look up all live hosts in the topology on Shodan and merge the results
        into each Host object's metadata and services.
        """
        live_ips = [h.ip for h in topology.get_live_hosts()]
        logger.info("Looking up %d host(s) on Shodan...", len(live_ips))
        shodan_data = self.lookup_hosts(live_ips)

        for ip, info in shodan_data.items():
            host = topology.get_host(ip)
            if not host:
                continue
            self._merge_into_host(host, info)

        logger.info("Shodan enrichment complete: %d/%d hosts found", len(shodan_data), len(live_ips))
        return shodan_data

    def search_network(self, query: str, limit: int = 100) -> List[ShodanHostInfo]:
        """
        Run a Shodan search query and return host info.
        e.g. query='net:192.168.1.0/24' or 'org:"Example Corp"'
        """
        results: List[ShodanHostInfo] = []
        try:
            matches = self._api.search(query, limit=limit)
            for match in matches.get("matches", []):
                info = self._parse_match(match)
                results.append(info)
            logger.info("Shodan search '%s' returned %d result(s)", query, len(results))
        except shodan_lib.APIError as exc:
            logger.error("Shodan search failed: %s", exc)
        return results

    def get_exploit_count(self, cve: str) -> int:
        """Return the number of known public exploits for a CVE via Shodan Exploits API."""
        try:
            results = self._api.exploits.search(cve)
            return results.get("total", 0)
        except Exception as exc:
            logger.debug("Exploit lookup failed for %s: %s", cve, exc)
            return 0

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_host(data: Dict[str, Any]) -> ShodanHostInfo:
        info = ShodanHostInfo(
            ip=data.get("ip_str", ""),
            org=data.get("org", ""),
            isp=data.get("isp", ""),
            country=data.get("country_name", ""),
            city=data.get("city", ""),
            hostnames=data.get("hostnames", []),
            ports=data.get("ports", []),
            vulns=list(data.get("vulns", {}).keys()),
            last_update=data.get("last_update", ""),
            tags=data.get("tags", []),
        )
        for item in data.get("data", []):
            banner = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": item.get("data", "")[:500],
            }
            info.banners.append(banner)
        return info

    @staticmethod
    def _parse_match(match: Dict[str, Any]) -> ShodanHostInfo:
        return ShodanHostInfo(
            ip=match.get("ip_str", ""),
            org=match.get("org", ""),
            isp=match.get("isp", ""),
            country=match.get("location", {}).get("country_name", ""),
            city=match.get("location", {}).get("city", ""),
            hostnames=match.get("hostnames", []),
            ports=[match.get("port", 0)],
            vulns=list(match.get("vulns", {}).keys()),
        )

    @staticmethod
    def _merge_into_host(host: Host, info: ShodanHostInfo) -> None:
        host.metadata["shodan"] = info.to_dict()
        if info.hostnames and not host.hostname:
            host.hostname = info.hostnames[0]
        if info.org:
            host.metadata["org"] = info.org

        # Add Shodan-discovered ports as services if not already present
        existing_ports = {s.port for s in host.services}
        for banner in info.banners:
            port = banner.get("port")
            if port and port not in existing_ports:
                svc = Service(
                    port=port,
                    protocol=banner.get("transport", "tcp"),
                    name=banner.get("product", "unknown"),
                    state=ServiceState.OPEN,
                    product=banner.get("product", ""),
                    version=banner.get("version", ""),
                    extra_info=banner.get("banner", "")[:200],
                )
                host.services.append(svc)
                existing_ports.add(port)

        # Attach CVEs as vulnerability tags
        for cve in info.vulns:
            for svc in host.services:
                if cve not in svc.vulnerabilities:
                    svc.vulnerabilities.append(cve)

        if "shodan_indexed" not in host.tags:
            host.tags.append("shodan_indexed")

"""Peer ASN enrichment plugin using Shadowserver API."""

from typing import Dict, Any, List, Optional
from ipgrep.plugins.enrichment.asn_base import ASNEnrichmentBase


class PeerEnrichment(ASNEnrichmentBase):
    """Enrichment plugin that queries ASN peer information.

    Uses the Shadowserver API to retrieve:
    - List of peer ASNs
    - Peer AS names
    - Peering relationships
    """

    def __init__(self, field_prefix: Optional[str] = None):
        """Initialize Peer enrichment plugin.

        Args:
            field_prefix: Custom field prefix (defaults to 'peer').
        """
        super().__init__(field_prefix)

    def name(self) -> str:
        """Return the name of this enrichment plugin."""
        return "peer"

    def enrich(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich the IP data with peer ASN information.

        Args:
            ip_data: Dictionary containing at least 'ip' key.

        Returns:
            The enriched dictionary with peer ASN fields added.
        """
        # Extract first host if CIDR present
        ip_str = self._extract_first_host(ip_data)

        # Query API (with caching)
        results = self._bulk_query([ip_str], "peer")
        peer_data = results.get(ip_str)

        if peer_data:
            formatted_data = self._format_data(peer_data)
            ip_data = self._add_prefixed_fields(ip_data, formatted_data)
        else:
            # Add error indicator
            prefix = self._get_field_prefix()
            ip_data[f"{prefix}_error"] = "not_found"

        return ip_data

    def _query_batch(
        self, ips: List[str], query_type: str
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """Query a batch of IPs for peer data.

        Args:
            ips: List of IP addresses to query.
            query_type: Type of query (always 'peer' for this plugin).

        Returns:
            Dictionary mapping IP to peer data.
        """
        results = {}

        # Shadowserver peer API supports bulk queries
        # Format: GET /net/asn?peer=IP1,IP2,...
        endpoint = "net/asn"

        # For bulk query, we pass IPs as comma-separated in the peer parameter
        ip_list_str = ",".join(ips)

        try:
            response = self._session.get(
                f"{self.API_BASE_URL}/{endpoint}",
                params={"peer": ip_list_str},
                timeout=self.MAX_TIMEOUT,
            )
            response.raise_for_status()

            # Parse response - JSON array of objects with ip, asn, asn_name, prefix, peer
            data = response.json()

            # Map responses to IPs
            for item in data:
                if "ip" in item:
                    results[item["ip"]] = item

            # Fill in any missing results
            for ip in ips:
                if ip not in results:
                    results[ip] = None

        except Exception:
            # On any error, return None for all IPs
            for ip in ips:
                results[ip] = None

        return results

    def _format_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format raw peer API data.

        Args:
            raw_data: Raw API response data.

        Returns:
            Formatted data dictionary with flattened peer lists.
        """
        formatted = {}

        # Handle peer field - this is a space-delimited string of ASN numbers
        if "peer" in raw_data:
            peer_str = raw_data["peer"]
            if peer_str and isinstance(peer_str, str):
                # Split space-delimited peer ASNs and convert to pipe-delimited
                peer_asns = peer_str.split()
                if peer_asns:
                    formatted["asns"] = "|".join(peer_asns)
                    formatted["count"] = str(len(peer_asns))
                else:
                    formatted["asns"] = ""
                    formatted["count"] = "0"
            else:
                formatted["asns"] = ""
                formatted["count"] = "0"
        else:
            formatted["asns"] = ""
            formatted["count"] = "0"

        # Include other top-level fields from the response
        for key in ["asn", "asn_name", "prefix"]:
            if key in raw_data:
                value = raw_data[key]
                formatted[key] = str(value) if value is not None else ""

        return formatted

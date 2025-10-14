"""Origin ASN enrichment plugin using Shadowserver API."""

from typing import Dict, Any, List, Optional
from ipgrep.plugins.enrichment.asn_base import ASNEnrichmentBase


class OriginEnrichment(ASNEnrichmentBase):
    """Enrichment plugin that queries ASN origin information.

    Uses the Shadowserver API to retrieve:
    - ASN number
    - AS name
    - Network prefix
    - Country code
    - Registry
    - Additional metadata
    """

    def __init__(self, field_prefix: Optional[str] = None):
        """Initialize Origin enrichment plugin.

        Args:
            field_prefix: Custom field prefix (defaults to 'asn_origin').
        """
        super().__init__(field_prefix)

    def name(self) -> str:
        """Return the name of this enrichment plugin."""
        return "asn_origin"

    def enrich(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich the IP data with origin ASN information.

        Args:
            ip_data: Dictionary containing at least 'ip' key.

        Returns:
            The enriched dictionary with origin ASN fields added.
        """
        # Extract first host if CIDR present
        ip_str = self._extract_first_host(ip_data)

        # Query API (with caching)
        results = self._bulk_query([ip_str], "origin")
        origin_data = results.get(ip_str)

        if origin_data:
            formatted_data = self._format_data(origin_data)
            ip_data = self._add_prefixed_fields(ip_data, formatted_data)
        else:
            # Add error indicator
            prefix = self._get_field_prefix()
            ip_data[f"{prefix}_error"] = "not_found"

        return ip_data

    def _query_batch(
        self, ips: List[str], query_type: str
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """Query a batch of IPs for origin data.

        Args:
            ips: List of IP addresses to query.
            query_type: Type of query (always 'origin' for this plugin).

        Returns:
            Dictionary mapping IP to origin data.
        """
        results = {}

        # Shadowserver origin API supports bulk queries
        # Format: GET /net/asn?origin=IP1,IP2,...
        endpoint = "net/asn"

        # For bulk query, we pass IPs as comma-separated in the origin parameter
        ip_list_str = ",".join(ips)

        # Use retry logic from base class
        data = self._api_request_with_retry(endpoint, params={"origin": ip_list_str})

        if data:
            # Parse response - JSON array of objects with ip, asn, asn_name, prefix
            # Map responses to IPs
            for item in data:
                if "ip" in item:
                    results[item["ip"]] = item

        # Fill in any missing results
        for ip in ips:
            if ip not in results:
                results[ip] = None

        return results

    def _format_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format raw origin API data.

        Args:
            raw_data: Raw API response data.

        Returns:
            Formatted data dictionary.
        """
        formatted = {}

        # Common fields from origin query
        # API returns: ip, asn, asn_name, prefix
        field_mapping = {
            "asn": "asn",
            "asn_name": "as_name",
            "prefix": "prefix",
        }

        for api_field, output_field in field_mapping.items():
            if api_field in raw_data:
                value = raw_data[api_field]
                # Convert to string for consistency
                formatted[output_field] = str(value) if value is not None else ""

        return formatted

"""Prefix ASN enrichment plugin using Shadowserver API."""

from typing import Dict, Any, List, Optional
from ipgrep.plugins.enrichment.asn_base import ASNEnrichmentBase
from ipgrep.plugins.enrichment.asn_origin import OriginEnrichment


class PrefixEnrichment(ASNEnrichmentBase):
    """Enrichment plugin that queries ASN prefix information.

    Automatically calls Origin plugin first to determine the ASN,
    then queries prefix information for that ASN.
    Keeps data from both Origin and Prefix queries.
    """

    def __init__(self, field_prefix: Optional[str] = None):
        """Initialize Prefix enrichment plugin.

        Args:
            field_prefix: Custom field prefix (defaults to 'prefix').
        """
        super().__init__(field_prefix)
        # Create origin plugin instance for ASN lookup
        self._origin_plugin = OriginEnrichment(field_prefix="origin")

    def name(self) -> str:
        """Return the name of this enrichment plugin."""
        return "prefix"

    def enrich(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich the IP data with prefix ASN information.

        First queries Origin to get the ASN, then queries prefix info.

        Args:
            ip_data: Dictionary containing at least 'ip' key.

        Returns:
            The enriched dictionary with both origin and prefix fields added.
        """
        # Extract first host if CIDR present
        ip_str = self._extract_first_host(ip_data)

        # Step 1: Get origin data to extract ASN
        ip_data = self._origin_plugin.enrich(ip_data)

        # Check if we successfully got origin data with ASN
        if "origin_asn" not in ip_data or ip_data.get("origin_error"):
            # If origin lookup failed, add error and return
            prefix = self._get_field_prefix()
            ip_data[f"{prefix}_error"] = "no_origin_asn"
            return ip_data

        # Extract ASN from origin data
        asn = ip_data["origin_asn"]

        # Step 2: Query prefix information for this ASN
        prefix_results = self._query_prefix_for_asn(ip_str, asn)

        if prefix_results:
            formatted_data = self._format_data(prefix_results)
            ip_data = self._add_prefixed_fields(ip_data, formatted_data)
        else:
            # Add error indicator
            prefix = self._get_field_prefix()
            ip_data[f"{prefix}_error"] = "not_found"

        return ip_data

    def enrich_batch(self, ip_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich multiple IPs with prefix data.

        Override to properly handle nested origin plugin enrichment.

        Args:
            ip_data_list: List of IP data dictionaries.

        Returns:
            List of enriched IP data dictionaries.
        """
        # Use default implementation (call enrich() for each IP)
        # This is necessary because prefix enrichment needs to call origin
        # plugin for each IP first, then query prefix data
        return [self.enrich(ip_data) for ip_data in ip_data_list]

    def _query_prefix_for_asn(self, ip: str, asn: str) -> Optional[Dict[str, Any]]:
        """Query prefix information for a specific ASN.

        Args:
            ip: IP address string (not used, kept for signature compatibility).
            asn: ASN number as string.

        Returns:
            Prefix data (list of prefix strings) or None.
        """
        # Query Shadowserver prefix API
        # Endpoint: /net/asn?prefix=ASN
        endpoint = "net/asn"

        try:
            response = self._session.get(
                f"{self.API_BASE_URL}/{endpoint}",
                params={"prefix": asn},
                timeout=self.MAX_TIMEOUT,
            )
            response.raise_for_status()

            # Parse response - should be JSON array of prefix strings
            data = response.json()

            return data

        except Exception:
            return None

    def _query_batch(
        self, ips: List[str], query_type: str
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """Query a batch of IPs for prefix data.

        Note: This method is required by the base class but prefix queries
        are handled differently (per-ASN rather than per-IP bulk).

        Args:
            ips: List of IP addresses to query.
            query_type: Type of query.

        Returns:
            Dictionary mapping IP to prefix data.
        """
        # Not used for prefix queries since we query by ASN
        # Return empty dict
        return {ip: None for ip in ips}

    def _format_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format raw prefix API data.

        Args:
            raw_data: Raw API response data (list of prefix strings).

        Returns:
            Formatted data dictionary with flattened prefix lists.
        """
        formatted = {}

        # raw_data is a list of prefix strings
        if isinstance(raw_data, list):
            # Filter to only string items (prefix strings)
            prefixes = [str(item) for item in raw_data if isinstance(item, str)]

            if prefixes:
                formatted["list"] = "|".join(prefixes)
                formatted["count"] = str(len(prefixes))
            else:
                formatted["list"] = ""
                formatted["count"] = "0"
        else:
            formatted["list"] = ""
            formatted["count"] = "0"

        return formatted

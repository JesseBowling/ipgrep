"""Base class for ASN enrichment plugins using Shadowserver API."""

import time
import ipaddress
from abc import abstractmethod
from typing import Dict, Any, List, Optional
import requests

from ipgrep.plugins.base import EnrichmentPlugin


class ASNEnrichmentBase(EnrichmentPlugin):
    """Base class for ASN enrichment plugins.

    Provides retry logic with exponential backoff and bulk query support
    for Shadowserver API with rate limiting (10 IPs per request, 1 req/sec).
    """

    API_BASE_URL = "https://api.shadowserver.org"
    BULK_LIMIT = 10  # Shadowserver rate limit: 10 IPs per request
    RATE_LIMIT_DELAY = 1.0  # 1 second delay between batches
    MAX_TIMEOUT = 10.0

    def __init__(self, field_prefix: Optional[str] = None):
        """Initialize ASN enrichment plugin.

        Args:
            field_prefix: Prefix for output fields (defaults to plugin name).
        """
        self._field_prefix = field_prefix
        self._session = requests.Session()

    def _get_field_prefix(self) -> str:
        """Get the field prefix to use."""
        return self._field_prefix if self._field_prefix else self.name()

    def _api_request_with_retry(
        self, endpoint: str, params: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        """Make API request with exponential backoff retry.

        Args:
            endpoint: API endpoint path.
            params: Optional query parameters.

        Returns:
            API response as dict, or None on failure.
        """
        url = f"{self.API_BASE_URL}/{endpoint}"
        retry_delays = [0.5, 1.0, 2.0, 4.0]  # Exponential backoff delays

        for attempt, delay in enumerate(retry_delays):
            try:
                response = self._session.get(
                    url, params=params, timeout=self.MAX_TIMEOUT
                )
                response.raise_for_status()
                return response.json()
            except requests.exceptions.Timeout:
                if attempt < len(retry_delays) - 1:
                    time.sleep(delay)
                    continue
                else:
                    return None
            except requests.exceptions.HTTPError as e:
                # Rate limiting or server error
                if e.response.status_code in (429, 500, 502, 503, 504):
                    if attempt < len(retry_delays) - 1:
                        time.sleep(delay)
                        continue
                return None
            except requests.exceptions.RequestException:
                # Network error
                if attempt < len(retry_delays) - 1:
                    time.sleep(delay)
                    continue
                return None

        return None

    def _bulk_query(
        self, ips: List[str], query_type: str
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """Perform bulk query for multiple IPs with rate limiting.

        Shadowserver API allows 10 IPs per request, max 1 request per second.

        Args:
            ips: List of IP addresses to query.
            query_type: Type of query (origin, peer, prefix).

        Returns:
            Dictionary mapping IP to response data.
        """
        results = {}

        # Perform bulk query in batches of BULK_LIMIT IPs
        # with rate limiting delay between batches
        for i in range(0, len(ips), self.BULK_LIMIT):
            batch = ips[i : i + self.BULK_LIMIT]

            # Add delay between batches (except for first batch)
            if i > 0:
                time.sleep(self.RATE_LIMIT_DELAY)

            batch_results = self._query_batch(batch, query_type)

            for ip, data in batch_results.items():
                results[ip] = data

        return results

    @abstractmethod
    def _query_batch(
        self, ips: List[str], query_type: str
    ) -> Dict[str, Optional[Dict[str, Any]]]:
        """Query a batch of IPs. Must be implemented by subclasses.

        Args:
            ips: List of IP addresses to query.
            query_type: Type of query.

        Returns:
            Dictionary mapping IP to response data.
        """
        pass

    @abstractmethod
    def _format_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format raw API data for output. Must be implemented by subclasses.

        Args:
            raw_data: Raw API response data.

        Returns:
            Formatted data dictionary with appropriate field names.
        """
        pass

    def _extract_first_host(self, ip_data: Dict[str, Any]) -> str:
        """Extract first host IP from ip_data.

        If CIDR notation is present, returns the first usable host IP.
        Otherwise returns the IP as-is.

        Args:
            ip_data: Dictionary containing 'ip' and optionally 'cidr'.

        Returns:
            IP address string (first host if CIDR present).
        """
        ip_str = ip_data["ip"]

        if "cidr" in ip_data:
            # Parse as network and get first host
            try:
                cidr = ip_data["cidr"]
                network = ipaddress.ip_network(f"{ip_str}/{cidr}", strict=False)
                # Get first host (network address + 1 for IPv4, or just network address for IPv6)
                hosts = list(network.hosts())
                if hosts:
                    return str(hosts[0])
                else:
                    # Network has no hosts (e.g., /32 or /128), use the address itself
                    return str(network.network_address)
            except (ValueError, IndexError):
                # Fall back to original IP
                return ip_str

        return ip_str

    def _add_prefixed_fields(
        self, ip_data: Dict[str, Any], new_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add fields with plugin name prefix.

        Args:
            ip_data: Original IP data dictionary.
            new_data: New data to add with prefixes.

        Returns:
            Updated IP data dictionary.
        """
        prefix = self._get_field_prefix()

        for key, value in new_data.items():
            prefixed_key = f"{prefix}_{key}"
            ip_data[prefixed_key] = value

        return ip_data

    def enrich_batch(self, ip_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich multiple IPs efficiently using bulk queries.

        Override base class to implement efficient batching for API calls.

        Args:
            ip_data_list: List of IP data dictionaries.

        Returns:
            List of enriched IP data dictionaries.
        """
        if not ip_data_list:
            return ip_data_list

        # Extract IPs to query
        ips_to_enrich = [self._extract_first_host(ip_data) for ip_data in ip_data_list]

        # Perform bulk query for all IPs at once
        query_type = self.name()
        bulk_results = self._bulk_query(ips_to_enrich, query_type)

        # Apply results back to each ip_data entry
        enriched_list = []
        for ip_data, ip_str in zip(ip_data_list, ips_to_enrich):
            result_data = bulk_results.get(ip_str)

            if result_data:
                formatted_data = self._format_data(result_data)
                ip_data = self._add_prefixed_fields(ip_data, formatted_data)
            else:
                # Add error indicator
                prefix = self._get_field_prefix()
                ip_data[f"{prefix}_error"] = "not_found"

            enriched_list.append(ip_data)

        return enriched_list

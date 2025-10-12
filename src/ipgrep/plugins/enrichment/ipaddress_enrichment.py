"""IPAddress enrichment plugin using Python's ipaddress library."""

import ipaddress
from typing import Dict, Any, List
from ipgrep.plugins.base import EnrichmentPlugin


class IPAddressEnrichment(EnrichmentPlugin):
    """Enrichment plugin that classifies IPs using the ipaddress library.

    Checks the following properties:
    - is_multicast
    - is_private
    - is_global
    - is_reserved
    - is_loopback
    - is_link_local
    - is_unspecified

    Returns all true classifications combined with a delimiter.
    """

    def __init__(self, delimiter: str = "|"):
        """Initialize the enrichment plugin.

        Args:
            delimiter: Character(s) to use when joining multiple classifications.
                      Defaults to pipe (|).
        """
        self.delimiter = delimiter
        self._classification_checks = [
            ("multicast", "is_multicast"),
            ("private", "is_private"),
            ("global", "is_global"),
            ("reserved", "is_reserved"),
            ("loopback", "is_loopback"),
            ("link_local", "is_link_local"),
            ("unspecified", "is_unspecified"),
        ]

    def name(self) -> str:
        """Return the name of this enrichment plugin."""
        return "ipaddress"

    def enrich(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich the IP data with classification information.

        Args:
            ip_data: Dictionary containing at least 'ip' key.

        Returns:
            The enriched dictionary with 'classification' field added.
        """
        ip_str = ip_data["ip"]

        try:
            # Create IP address object
            # Note: If CIDR is present, we treat it as a single host for classification
            # as per requirements (enrichment plugins may presume prefix represents single host)
            ip_obj = ipaddress.ip_address(ip_str)

            # Check all classification properties
            classifications = []
            for name, attr in self._classification_checks:
                if hasattr(ip_obj, attr) and getattr(ip_obj, attr):
                    classifications.append(name)

            # Join classifications with delimiter
            if classifications:
                ip_data["classification"] = self.delimiter.join(classifications)
            else:
                ip_data["classification"] = "none"

        except ValueError:
            # Invalid IP address (shouldn't happen after extraction validation)
            ip_data["classification"] = "invalid"

        return ip_data

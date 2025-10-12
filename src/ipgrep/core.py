"""Core processing pipeline for ipgrep."""

from typing import List, Dict, Any, Set, Tuple
from ipgrep.extractor import IPExtractor
from ipgrep.plugins.base import EnrichmentPlugin, OutputPlugin


class IPGrepPipeline:
    """Main processing pipeline for extracting, enriching, and outputting IP data."""

    def __init__(
        self,
        extract_cidr: bool = False,
        enrichments: List[EnrichmentPlugin] = None,
        output_plugin: OutputPlugin = None,
    ):
        """Initialize the pipeline.

        Args:
            extract_cidr: Whether to extract/default CIDR notation.
            enrichments: List of enrichment plugins to apply in order.
            output_plugin: The output plugin to use for formatting.
        """
        self.extractor = IPExtractor(extract_cidr=extract_cidr)
        self.enrichments = enrichments or []
        self.output_plugin = output_plugin
        self.extract_cidr = extract_cidr

    def process(self, text: str) -> str:
        """Process text through the complete pipeline.

        Args:
            text: The text to extract IPs from.

        Returns:
            Formatted output string.
        """
        # Extract unique IPs
        ip_tuples = self.extractor.extract(text)

        # Convert to data dictionaries
        ip_data_list = self._tuples_to_data(ip_tuples)

        # Apply enrichments in chain
        # Use batch enrichment if supported for better performance
        for enrichment in self.enrichments:
            ip_data_list = enrichment.enrich_batch(ip_data_list)

        # Format output
        if self.output_plugin:
            return self.output_plugin.format(ip_data_list)
        else:
            # Default to plain output (one IP per line)
            return self._default_format(ip_data_list)

    def _tuples_to_data(self, ip_tuples: Set[Tuple[str, str]]) -> List[Dict[str, Any]]:
        """Convert IP tuples to data dictionaries.

        Args:
            ip_tuples: Set of (ip, cidr) tuples.

        Returns:
            List of dictionaries with 'ip' and optionally 'cidr' keys.
        """
        ip_data_list = []
        for ip, cidr in sorted(ip_tuples):  # Sort for consistent ordering
            data = {"ip": ip}
            if cidr is not None:
                data["cidr"] = cidr
            ip_data_list.append(data)
        return ip_data_list

    def _default_format(self, ip_data_list: List[Dict[str, Any]]) -> str:
        """Default formatting (plain output).

        Args:
            ip_data_list: List of IP data dictionaries.

        Returns:
            One IP per line (with CIDR if available).
        """
        lines = []
        for ip_data in ip_data_list:
            if "cidr" in ip_data:
                lines.append(f"{ip_data['ip']}/{ip_data['cidr']}")
            else:
                lines.append(ip_data["ip"])
        return "\n".join(lines)

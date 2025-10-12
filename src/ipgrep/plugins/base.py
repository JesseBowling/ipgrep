"""Base classes for ipgrep plugins."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
import sys

if sys.version_info >= (3, 10):
    from importlib.metadata import entry_points
else:
    from importlib_metadata import entry_points


class EnrichmentPlugin(ABC):
    """Base class for enrichment plugins.

    Enrichment plugins add additional data fields to each IP address.
    They can be chained together to apply multiple enrichments.
    """

    @abstractmethod
    def name(self) -> str:
        """Return the name of this enrichment plugin."""
        pass

    @abstractmethod
    def enrich(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich the IP data with additional fields.

        Args:
            ip_data: Dictionary containing at least 'ip' key with the IP address string
                    and optionally 'cidr' key with CIDR notation.

        Returns:
            The enriched dictionary with additional fields added.
        """
        pass

    def enrich_batch(self, ip_data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich multiple IP data entries at once (optional batch operation).

        Default implementation falls back to calling enrich() for each IP.
        Plugins can override this for more efficient batch processing.

        Args:
            ip_data_list: List of dictionaries containing IP data.

        Returns:
            List of enriched dictionaries in the same order.
        """
        return [self.enrich(ip_data) for ip_data in ip_data_list]


class OutputPlugin(ABC):
    """Base class for output plugins.

    Output plugins format the enriched IP data for display.
    """

    @abstractmethod
    def name(self) -> str:
        """Return the name of this output plugin."""
        pass

    @abstractmethod
    def format(self, ip_data_list: List[Dict[str, Any]]) -> str:
        """Format the list of IP data for output.

        Args:
            ip_data_list: List of dictionaries containing IP data and enrichment fields.
                         Each dictionary must have at least an 'ip' key.

        Returns:
            Formatted string ready for output.
        """
        pass


class PluginManager:
    """Manages plugin discovery and loading via entry points."""

    @staticmethod
    def load_enrichment_plugins() -> Dict[str, type]:
        """Load all available enrichment plugins.

        Returns:
            Dictionary mapping plugin names to plugin classes.
        """
        plugins = {}
        eps = entry_points()

        # Handle both old and new style entry_points API
        if hasattr(eps, "select"):
            # Python 3.10+ style
            enrichment_eps = eps.select(group="ipgrep.enrichment")
        else:
            # Python 3.9 style
            enrichment_eps = eps.get("ipgrep.enrichment", [])

        for ep in enrichment_eps:
            try:
                plugin_class = ep.load()
                plugins[ep.name] = plugin_class
            except Exception as e:
                print(
                    f"Warning: Failed to load enrichment plugin '{ep.name}': {e}",
                    file=sys.stderr,
                )

        return plugins

    @staticmethod
    def load_output_plugins() -> Dict[str, type]:
        """Load all available output plugins.

        Returns:
            Dictionary mapping plugin names to plugin classes.
        """
        plugins = {}
        eps = entry_points()

        # Handle both old and new style entry_points API
        if hasattr(eps, "select"):
            # Python 3.10+ style
            output_eps = eps.select(group="ipgrep.output")
        else:
            # Python 3.9 style
            output_eps = eps.get("ipgrep.output", [])

        for ep in output_eps:
            try:
                plugin_class = ep.load()
                plugins[ep.name] = plugin_class
            except Exception as e:
                print(
                    f"Warning: Failed to load output plugin '{ep.name}': {e}",
                    file=sys.stderr,
                )

        return plugins

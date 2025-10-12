"""JSON output plugin."""

import json
from typing import List, Dict, Any
from ipgrep.plugins.base import OutputPlugin


class JSONOutput(OutputPlugin):
    """Output plugin that formats IPs as JSON array.

    Outputs a pretty-printed JSON array containing all IP data.
    """

    def name(self) -> str:
        """Return the name of this output plugin."""
        return "json"

    def format(self, ip_data_list: List[Dict[str, Any]]) -> str:
        """Format the IP data as JSON.

        Args:
            ip_data_list: List of IP data dictionaries.

        Returns:
            Pretty-printed JSON array.
        """
        return json.dumps(ip_data_list)

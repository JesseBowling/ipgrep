"""Plain text output plugin (one IP per line)."""

from typing import List, Dict, Any
from ipgrep.plugins.base import OutputPlugin


class PlainOutput(OutputPlugin):
    """Output plugin that formats IPs as plain text, one per line.

    This is the default output format. If CIDR is present, it's included
    with the IP address.
    """

    def name(self) -> str:
        """Return the name of this output plugin."""
        return "plain"

    def format(self, ip_data_list: List[Dict[str, Any]]) -> str:
        """Format the IP data as plain text.

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
        return "\n".join(lines) if lines else ""

"""Space delimited output plugin."""

from typing import List, Dict, Any
from ipgrep.plugins.base import OutputPlugin


class SpaceDelimitedOutput(OutputPlugin):
    """Output plugin that formats IPs as space-delimited text.

    Each line contains all fields for an IP, separated by spaces.
    """

    def name(self) -> str:
        """Return the name of this output plugin."""
        return "space"

    def format(self, ip_data_list: List[Dict[str, Any]]) -> str:
        """Format the IP data as space-delimited text.

        Args:
            ip_data_list: List of IP data dictionaries.

        Returns:
            Space-delimited output with one IP per line.
        """
        if not ip_data_list:
            return ""

        # Collect all unique field names
        fieldnames = ["ip"]
        additional_fields = set()

        for ip_data in ip_data_list:
            for key in ip_data.keys():
                if key != "ip":
                    additional_fields.add(key)

        fieldnames.extend(sorted(additional_fields))

        lines = []
        for ip_data in ip_data_list:
            values = []
            for field in fieldnames:
                value = ip_data.get(field, "")
                # Handle CIDR specially to attach to IP
                if field == "ip" and "cidr" in ip_data:
                    values.append(f"{value}/{ip_data['cidr']}")
                elif field == "cidr":
                    continue  # Skip CIDR field as it's already appended to IP
                else:
                    # Convert complex types to JSON string
                    if isinstance(value, (list, dict)):
                        import json

                        values.append(json.dumps(value))
                    else:
                        values.append(str(value) if value is not None else "")
            lines.append(" ".join(values))

        return "\n".join(lines)

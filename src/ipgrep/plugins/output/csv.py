"""CSV output plugin."""

import csv
import io
from typing import List, Dict, Any
from ipgrep.plugins.base import OutputPlugin


class CSVOutput(OutputPlugin):
    """Output plugin that formats IPs as CSV.

    Includes a header row with all field names. Automatically handles
    all enrichment fields.
    """

    def name(self) -> str:
        """Return the name of this output plugin."""
        return "csv"

    def format(self, ip_data_list: List[Dict[str, Any]]) -> str:
        """Format the IP data as CSV.

        Args:
            ip_data_list: List of IP data dictionaries.

        Returns:
            CSV formatted string with header row.
        """
        if not ip_data_list:
            return ""

        # Collect all unique field names across all records
        # 'ip' should always be first
        fieldnames = ["ip"]
        additional_fields = set()

        for ip_data in ip_data_list:
            for key in ip_data.keys():
                if key != "ip":
                    additional_fields.add(key)

        # Sort additional fields for consistent ordering
        fieldnames.extend(sorted(additional_fields))

        # Write CSV to string buffer
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator='\n')

        writer.writeheader()
        for ip_data in ip_data_list:
            # Ensure all fields are present (fill missing with empty string)
            # Convert any complex types to strings
            row = {}
            for field in fieldnames:
                value = ip_data.get(field, "")
                if isinstance(value, (list, dict)):
                    # Convert complex types to JSON string representation
                    import json

                    row[field] = json.dumps(value)
                else:
                    row[field] = str(value) if value is not None else ""
            writer.writerow(row)

        return output.getvalue().rstrip("\n")

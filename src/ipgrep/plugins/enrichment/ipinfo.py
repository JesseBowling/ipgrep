"""IPInfo enrichment plugin using ipinfo-db library."""

import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

import ipinfo_db

from ipgrep.plugins.base import EnrichmentPlugin


logger = logging.getLogger(__name__)


class IPInfoEnrichment(EnrichmentPlugin):
    """Enrichment plugin that uses IPInfo.io database via ipinfo-db library.

    Requires IPINFO_ACCESS_TOKEN environment variable to be set.
    Automatically downloads and caches the IPInfo database locally.
    Recreates database if older than 1 day.
    """

    def __init__(self, field_prefix: Optional[str] = None):
        """Initialize IPInfo enrichment plugin.

        Args:
            field_prefix: Custom field prefix (defaults to 'ipinfo').

        Raises:
            ValueError: If IPINFO_ACCESS_TOKEN environment variable is not set.
        """
        self._field_prefix = field_prefix
        self._client = None

        # Check for required environment variable
        self._token = os.environ.get("IPINFO_ACCESS_TOKEN")
        if not self._token:
            error_msg = (
                "IPINFO_ACCESS_TOKEN environment variable is required but not set. "
                "Please set it to your IPInfo.io access token."
            )
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Initialize client
        self._initialize_client()

    def name(self) -> str:
        """Return the name of this enrichment plugin."""
        return "ipinfo"

    def _get_field_prefix(self) -> str:
        """Get the field prefix to use."""
        return self._field_prefix if self._field_prefix else "ipinfo"

    def _initialize_client(self):
        """Initialize the IPInfo client, checking database age."""
        try:
            # Create initial client
            logger.info("Initializing IPInfo database client")
            self._client = ipinfo_db.Client(self._token)

            # Check if database file exists and its age
            if hasattr(self._client, "path") and self._client.path:
                db_path = Path(self._client.path)
                if db_path.exists():
                    # Get modification time
                    mod_time = datetime.fromtimestamp(db_path.stat().st_mtime)
                    age = datetime.now() - mod_time

                    # If older than 1 day, recreate with replace=True
                    if age > timedelta(days=1):
                        logger.info(
                            f"Database is {age.days} days old, downloading fresh copy"
                        )
                        self._client = ipinfo_db.Client(self._token, replace=True)
                    else:
                        logger.info(f"Using existing database (age: {age})")
                else:
                    logger.info("Database file not found, will be downloaded")
            else:
                logger.info("Database client initialized")

        except Exception as e:
            logger.error(f"Failed to initialize IPInfo client: {e}")
            raise

    def enrich(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich the IP data with IPInfo information.

        Args:
            ip_data: Dictionary containing at least 'ip' key.

        Returns:
            The enriched dictionary with IPInfo fields added.
        """
        ip_str = ip_data["ip"]

        if not self._client:
            logger.warning("IPInfo client not initialized")
            prefix = self._get_field_prefix()
            ip_data[f"{prefix}_error"] = "client_not_initialized"
            return ip_data

        try:
            # Use getDetails() to get all information
            details = self._client.getDetails(ip_str)

            if details:
                prefix = self._get_field_prefix()

                # Check if details is a dict-like object
                if hasattr(details, "__dict__"):
                    # Convert object attributes to dict
                    details_dict = vars(details)
                elif isinstance(details, dict):
                    details_dict = details
                else:
                    # If it's a simple value, just store it
                    ip_data[f"{prefix}_details"] = str(details)
                    return ip_data

                # Add all fields from details with prefix
                for key, value in details_dict.items():
                    # Skip private attributes
                    if key.startswith("_"):
                        continue

                    # Convert values to strings for consistency
                    if isinstance(value, (str, int, float, bool)):
                        ip_data[f"{prefix}_{key}"] = str(value)
                    elif isinstance(value, dict):
                        # For nested dicts, flatten with underscore
                        for subkey, subvalue in value.items():
                            ip_data[f"{prefix}_{key}_{subkey}"] = str(subvalue)
                    elif value is not None:
                        # For other types, convert to string
                        ip_data[f"{prefix}_{key}"] = str(value)
            else:
                # No data found for this IP
                prefix = self._get_field_prefix()
                ip_data[f"{prefix}_error"] = "not_found"

        except Exception as e:
            logger.error(f"Error looking up IP {ip_str}: {e}")
            prefix = self._get_field_prefix()
            ip_data[f"{prefix}_error"] = "lookup_failed"

        return ip_data

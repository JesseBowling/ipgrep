"""IP address and CIDR extraction from arbitrary text."""

import re
import ipaddress
from typing import Set, Tuple
from urllib.parse import urlparse


class IPExtractor:
    """Extracts IP addresses and CIDR notation from text."""

    # IPv4 pattern - matches standard IPv4 addresses
    IPV4_PATTERN = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"

    # IPv6 pattern - matches standard IPv6 addresses including compressed forms
    # This matches the full range of IPv6 formats including ::1, ::ffff:192.0.2.1, etc.
    IPV6_PATTERN = r"[0-9a-fA-F:]+::[0-9a-fA-F:]*|::[0-9a-fA-F:]+|[0-9a-fA-F:]+::|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"

    # CIDR pattern for both IPv4 and IPv6
    CIDR_SUFFIX = r"/(\d{1,3})"

    # URL pattern to detect if IP is in a URL context
    URL_PATTERN = r"(?:https?://|ftp://|file://)"

    def __init__(self, extract_cidr: bool = False, defang: bool = False):
        """Initialize the IP extractor.

        Args:
            extract_cidr: If True, also extract CIDR notation and add default
                         CIDR for IPs without it.
            defang: If True, handle defanged IPs (e.g., 1[.]2[.]3[.]4).
        """
        self.extract_cidr = extract_cidr
        self.defang = defang

    def extract(self, text: str) -> Set[Tuple[str, str]]:
        """Extract unique IP addresses from text.

        Args:
            text: The text to extract IP addresses from.

        Returns:
            Set of tuples (ip_address, cidr) where cidr is the CIDR notation
            or None if not extracted/applicable.
        """
        # Preprocess text to handle defanged IPs if enabled
        if self.defang:
            text = self._refang_text(text)

        results = set()

        # Extract IPv4 addresses
        results.update(self._extract_ipv4(text))

        # Extract IPv6 addresses
        results.update(self._extract_ipv6(text))

        return results

    def _extract_ipv4(self, text: str) -> Set[Tuple[str, str]]:
        """Extract IPv4 addresses from text."""
        results = set()

        # Find all potential IPv4 addresses with optional CIDR
        pattern = self.IPV4_PATTERN
        if self.extract_cidr:
            pattern += f"(?:{self.CIDR_SUFFIX})?"

        for match in re.finditer(pattern, text):
            ip_str = match.group(0)
            cidr = None
            from_url = False

            # Check if this IP is part of a URL
            start_pos = max(0, match.start() - 20)
            context = text[start_pos : match.start()]
            if re.search(self.URL_PATTERN, context):
                from_url = True

            # Separate IP from CIDR if present
            if self.extract_cidr and "/" in ip_str:
                ip_part, cidr_part = ip_str.split("/", 1)
                try:
                    cidr_value = int(cidr_part)
                    if 0 <= cidr_value <= 32:
                        cidr = cidr_part
                        ip_str = ip_part
                    else:
                        # Invalid CIDR, skip
                        continue
                except ValueError:
                    continue
            elif self.extract_cidr:
                # No CIDR specified, use default host CIDR
                cidr = "32"

            # If IP is from URL, force to single host
            if from_url and self.extract_cidr:
                cidr = "32"

            # Validate the IP address
            if self._validate_ip(ip_str):
                results.add((ip_str, cidr))

        return results

    def _extract_ipv6(self, text: str) -> Set[Tuple[str, str]]:
        """Extract IPv6 addresses from text."""
        results = set()

        # Remove brackets commonly found around IPv6 in URLs
        # e.g., [2001:db8::1] or http://[2001:db8::1]:8080
        text_normalized = text.replace("[", " ").replace("]", " ")

        pattern = f"(?:{self.IPV6_PATTERN})"
        if self.extract_cidr:
            pattern += f"(?:{self.CIDR_SUFFIX})?"

        for match in re.finditer(pattern, text_normalized):
            ip_str = match.group(0)
            cidr = None
            from_url = False

            # Check if this IP is part of a URL (check in original text)
            # Look for [ipv6] pattern or http:// prefix
            if "[" in text and "]" in text:
                # Check if our IP was inside brackets in original
                bracket_pattern = r"\[" + re.escape(ip_str.split("/")[0]) + r"\]"
                if re.search(bracket_pattern, text):
                    from_url = True

            # Check for URL prefix
            start_pos = max(0, match.start() - 20)
            context = text_normalized[start_pos : match.start()]
            if re.search(self.URL_PATTERN, context):
                from_url = True

            # Separate IP from CIDR if present
            if self.extract_cidr and "/" in ip_str:
                ip_part, cidr_part = ip_str.split("/", 1)
                try:
                    cidr_value = int(cidr_part)
                    if 0 <= cidr_value <= 128:
                        cidr = cidr_part
                        ip_str = ip_part
                    else:
                        # Invalid CIDR, skip
                        continue
                except ValueError:
                    continue
            elif self.extract_cidr:
                # No CIDR specified, use default host CIDR
                cidr = "128"

            # If IP is from URL, force to single host
            if from_url and self.extract_cidr:
                cidr = "128"

            # Validate the IP address
            if self._validate_ip(ip_str):
                results.add((ip_str, cidr))

        return results

    @staticmethod
    def _refang_text(text: str) -> str:
        """Convert defanged text to standard format.

        Replaces common defanging patterns:
        - [.] -> .
        - [dot] -> . (case insensitive)
        - (.) -> .
        - (dot) -> . (case insensitive)

        Args:
            text: The text potentially containing defanged IPs.

        Returns:
            Text with defanged patterns replaced.
        """
        # Replace [.] with .
        text = text.replace("[.]", ".")

        # Replace (.) with .
        text = text.replace("(.)", ".")

        # Replace [dot] and [DOT] with . (case insensitive)
        text = re.sub(r'\[dot\]', '.', text, flags=re.IGNORECASE)

        # Replace (dot) and (DOT) with . (case insensitive)
        text = re.sub(r'\(dot\)', '.', text, flags=re.IGNORECASE)

        return text

    @staticmethod
    def _validate_ip(ip_str: str) -> bool:
        """Validate that a string is a valid IP address.

        Args:
            ip_str: The string to validate.

        Returns:
            True if valid IP address, False otherwise.
        """
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

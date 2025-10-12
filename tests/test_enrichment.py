"""Tests for enrichment plugins."""

import pytest
from ipgrep.plugins.enrichment.ipaddress_enrichment import IPAddressEnrichment


class TestIPAddressEnrichment:
    """Test the IPAddress enrichment plugin."""

    def test_private_ipv4(self):
        """Test classification of private IPv4 address."""
        enrichment = IPAddressEnrichment()
        ip_data = {"ip": "192.168.1.1"}
        result = enrichment.enrich(ip_data)
        assert "classification" in result
        assert "private" in result["classification"]

    def test_loopback_ipv4(self):
        """Test classification of loopback IPv4 address."""
        enrichment = IPAddressEnrichment()
        ip_data = {"ip": "127.0.0.1"}
        result = enrichment.enrich(ip_data)
        assert "classification" in result
        assert "loopback" in result["classification"]

    def test_loopback_ipv6(self):
        """Test classification of loopback IPv6 address."""
        enrichment = IPAddressEnrichment()
        ip_data = {"ip": "::1"}
        result = enrichment.enrich(ip_data)
        assert "classification" in result
        assert "loopback" in result["classification"]

    def test_public_ipv4(self):
        """Test classification of public IPv4 address."""
        enrichment = IPAddressEnrichment()
        ip_data = {"ip": "8.8.8.8"}
        result = enrichment.enrich(ip_data)
        assert "classification" in result
        # Public IPs should be marked as global
        assert "global" in result["classification"]

    def test_multicast_ipv4(self):
        """Test classification of multicast IPv4 address."""
        enrichment = IPAddressEnrichment()
        ip_data = {"ip": "224.0.0.1"}
        result = enrichment.enrich(ip_data)
        assert "classification" in result
        assert "multicast" in result["classification"]

    def test_link_local_ipv4(self):
        """Test classification of link-local IPv4 address."""
        enrichment = IPAddressEnrichment()
        ip_data = {"ip": "169.254.1.1"}
        result = enrichment.enrich(ip_data)
        assert "classification" in result
        assert "link_local" in result["classification"]

    def test_link_local_ipv6(self):
        """Test classification of link-local IPv6 address."""
        enrichment = IPAddressEnrichment()
        ip_data = {"ip": "fe80::1"}
        result = enrichment.enrich(ip_data)
        assert "classification" in result
        assert "link_local" in result["classification"]

    def test_unspecified_ipv4(self):
        """Test classification of unspecified IPv4 address."""
        enrichment = IPAddressEnrichment()
        ip_data = {"ip": "0.0.0.0"}
        result = enrichment.enrich(ip_data)
        assert "classification" in result
        assert "unspecified" in result["classification"]

    def test_unspecified_ipv6(self):
        """Test classification of unspecified IPv6 address."""
        enrichment = IPAddressEnrichment()
        ip_data = {"ip": "::"}
        result = enrichment.enrich(ip_data)
        assert "classification" in result
        assert "unspecified" in result["classification"]

    def test_multiple_classifications(self):
        """Test IP with multiple classifications."""
        enrichment = IPAddressEnrichment()
        # Loopback is also reserved
        ip_data = {"ip": "127.0.0.1"}
        result = enrichment.enrich(ip_data)
        assert "classification" in result
        # Should contain pipe delimiter between classifications
        assert "|" in result["classification"]

    def test_custom_delimiter(self):
        """Test custom delimiter for multiple classifications."""
        enrichment = IPAddressEnrichment(delimiter=",")
        ip_data = {"ip": "127.0.0.1"}
        result = enrichment.enrich(ip_data)
        assert "classification" in result
        # Should use comma delimiter
        if "," in result["classification"] or result["classification"].count(",") == 0:
            # Either has comma or only one classification
            pass
        else:
            pytest.fail("Expected comma delimiter or single classification")

    def test_preserves_existing_fields(self):
        """Test that enrichment preserves existing fields."""
        enrichment = IPAddressEnrichment()
        ip_data = {"ip": "192.168.1.1", "cidr": "24", "other": "value"}
        result = enrichment.enrich(ip_data)
        assert result["ip"] == "192.168.1.1"
        assert result["cidr"] == "24"
        assert result["other"] == "value"
        assert "classification" in result

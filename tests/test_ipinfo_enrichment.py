"""Tests for IPInfo enrichment plugin using real API calls."""

import os
import pytest
from ipgrep.plugins.enrichment.ipinfo import IPInfoEnrichment


@pytest.mark.remote
class TestIPInfoEnrichment:
    """Test the IPInfo enrichment plugin with real API calls."""

    def test_token_present(self):
        """Test that plugin has access to IPINFO_ACCESS_TOKEN environment variable."""
        token = os.environ.get("IPINFO_ACCESS_TOKEN")
        assert token is not None, "IPINFO_ACCESS_TOKEN environment variable not set"

    def test_requires_token(self):
        """Test that plugin requires IPINFO_ACCESS_TOKEN environment variable."""
        # Save original token if present
        original_token = os.environ.get("IPINFO_ACCESS_TOKEN")

        try:
            # Remove token
            if "IPINFO_ACCESS_TOKEN" in os.environ:
                del os.environ["IPINFO_ACCESS_TOKEN"]

            # Should raise ValueError
            with pytest.raises(ValueError, match="IPINFO_ACCESS_TOKEN"):
                IPInfoEnrichment()
        finally:
            # Restore original token
            if original_token:
                os.environ["IPINFO_ACCESS_TOKEN"] = original_token

    def test_single_ipv4_lookup(self):
        """Test successful lookup for single IPv4 address."""
        enrichment = IPInfoEnrichment()
        ip_data = {"ip": "8.8.8.8"}

        result = enrichment.enrich(ip_data)

        # Verify expected fields are present
        assert "ipinfo_country" in result
        assert "ipinfo_asn" in result

        # Verify data types
        assert isinstance(result["ipinfo_country"], str)
        assert len(result["ipinfo_country"]) > 0

        # Verify specific known values for Google DNS
        assert result["ipinfo_country"] == "US"
        assert "15169" in result["ipinfo_asn"]

    def test_single_ipv6_lookup(self):
        """Test successful lookup for single IPv6 address."""
        enrichment = IPInfoEnrichment()
        ip_data = {"ip": "2001:4860:4860::8888"}

        result = enrichment.enrich(ip_data)

        # Verify expected fields are present
        assert "ipinfo_country" in result
        assert "ipinfo_asn" in result

        # Verify specific known values for Google DNS
        assert result["ipinfo_country"] == "US"
        assert "15169" in result["ipinfo_asn"]

    def test_multiple_ips_lookup(self):
        """Test lookup with multiple IPs."""
        enrichment = IPInfoEnrichment()

        # Test two different IPs
        ip_data_1 = {"ip": "8.8.8.8"}
        ip_data_2 = {"ip": "1.1.1.1"}

        result_1 = enrichment.enrich(ip_data_1)
        result_2 = enrichment.enrich(ip_data_2)

        # Verify both got enriched
        assert "ipinfo_country" in result_1
        assert "ipinfo_country" in result_2

        # Verify they have different countries (Google vs Cloudflare)
        assert result_1["ipinfo_country"] == "US"
        assert result_2["ipinfo_country"] == "AU"  # Cloudflare routes to Australia

    def test_private_ip_lookup(self):
        """Test handling of private IP address."""
        enrichment = IPInfoEnrichment()
        ip_data = {"ip": "192.168.1.1"}

        result = enrichment.enrich(ip_data)

        # Private IPs typically don't have data
        # Should either have error or no enrichment fields
        assert "ipinfo_error" in result or "ipinfo_country" not in result

    def test_preserves_existing_fields(self):
        """Test that enrichment preserves existing fields."""
        enrichment = IPInfoEnrichment()
        ip_data = {"ip": "8.8.8.8", "cidr": "32", "classification": "global"}

        result = enrichment.enrich(ip_data)

        # Existing fields should be preserved
        assert result["ip"] == "8.8.8.8"
        assert result["cidr"] == "32"
        assert result["classification"] == "global"
        # New fields should be added
        assert "ipinfo_country" in result

    def test_custom_field_prefix(self):
        """Test custom field prefix."""
        enrichment = IPInfoEnrichment(field_prefix="custom")
        ip_data = {"ip": "8.8.8.8"}

        result = enrichment.enrich(ip_data)

        # Fields should use custom prefix
        assert "custom_country" in result
        assert "custom_asn" in result
        assert result["custom_country"] == "US"

    def test_expected_field_structure(self):
        """Test that expected fields are returned."""
        enrichment = IPInfoEnrichment()
        ip_data = {"ip": "8.8.8.8"}

        result = enrichment.enrich(ip_data)

        # Verify common fields exist
        expected_fields = [
            "ipinfo_country",
            "ipinfo_country_name",
            "ipinfo_continent",
            "ipinfo_continent_name",
            "ipinfo_asn",
            "ipinfo_as_name",
            "ipinfo_as_domain",
        ]

        for field in expected_fields:
            assert field in result, f"Expected field {field} not found"
            # All fields should have non-empty values for Google DNS
            assert result[field], f"Field {field} is empty"

    def test_asn_format(self):
        """Test ASN format includes 'AS' prefix."""
        enrichment = IPInfoEnrichment()
        ip_data = {"ip": "8.8.8.8"}

        result = enrichment.enrich(ip_data)

        # ASN should be in format "AS15169"
        assert "ipinfo_asn" in result
        assert result["ipinfo_asn"].startswith("AS")
        assert "15169" in result["ipinfo_asn"]

    def test_database_initialization(self):
        """Test that database initializes successfully."""
        # Simply creating the enrichment should download/initialize database
        enrichment = IPInfoEnrichment()

        # Check that client was created
        assert enrichment._client is not None

    def test_continent_codes(self):
        """Test continent code values."""
        enrichment = IPInfoEnrichment()

        # Test North America (Google)
        ip_data_na = {"ip": "8.8.8.8"}
        result_na = enrichment.enrich(ip_data_na)
        assert result_na["ipinfo_continent"] == "NA"
        assert result_na["ipinfo_continent_name"] == "North America"

    def test_cloudflare_ip(self):
        """Test Cloudflare DNS IP for variety."""
        enrichment = IPInfoEnrichment()
        ip_data = {"ip": "1.1.1.1"}

        result = enrichment.enrich(ip_data)

        # Verify Cloudflare-specific data
        assert "ipinfo_country" in result
        assert "ipinfo_asn" in result
        assert "13335" in result["ipinfo_asn"]  # Cloudflare ASN
        assert "Cloudflare" in result["ipinfo_as_name"]

    def test_opendns_ip(self):
        """Test OpenDNS IP for additional variety."""
        enrichment = IPInfoEnrichment()
        ip_data = {"ip": "208.67.222.222"}

        result = enrichment.enrich(ip_data)

        # Verify OpenDNS-specific data
        assert result["ipinfo_country"] == "US"
        assert "ipinfo_asn" in result
        assert "36692" in result["ipinfo_asn"]  # Cisco OpenDNS ASN

    def test_no_private_attributes(self):
        """Test that private attributes are not included in output."""
        enrichment = IPInfoEnrichment()
        ip_data = {"ip": "8.8.8.8"}

        result = enrichment.enrich(ip_data)

        # Verify no fields starting with underscore
        for key in result.keys():
            if key.startswith("ipinfo_"):
                field_name = key.replace("ipinfo_", "")
                assert not field_name.startswith("_"), \
                    f"Found private attribute in output: {key}"

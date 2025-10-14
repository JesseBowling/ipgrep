"""Tests for ASN enrichment plugins using real API calls."""

import pytest
from ipgrep.plugins.enrichment.asn_origin import OriginEnrichment
from ipgrep.plugins.enrichment.asn_peer import PeerEnrichment
from ipgrep.plugins.enrichment.asn_prefix import PrefixEnrichment

@pytest.mark.remote
@pytest.mark.ratelimit
class TestOriginEnrichment:
    """Test the Origin ASN enrichment plugin with real API calls."""

    def test_single_ipv4_lookup(self):
        """Test successful origin lookup for single IPv4 address."""
        enrichment = OriginEnrichment()
        ip_data = {"ip": "8.8.8.8"}

        result = enrichment.enrich(ip_data)

        # Verify expected fields are present
        assert "asn_origin_asn" in result
        assert "asn_origin_as_name" in result
        assert "asn_origin_prefix" in result

        # Verify data types
        assert isinstance(result["asn_origin_asn"], str)
        assert len(result["asn_origin_asn"]) > 0

        # Verify specific known values for Google DNS
        assert result["asn_origin_asn"] == "15169"
        assert "Google" in result["asn_origin_as_name"] or "GOOGLE" in result["asn_origin_as_name"]
        assert result["asn_origin_prefix"] == "8.8.8.0/24"

    def test_single_ipv6_lookup(self):
        """Test successful origin lookup for single IPv6 address."""
        enrichment = OriginEnrichment()
        ip_data = {"ip": "2001:4860:4860::8888"}

        result = enrichment.enrich(ip_data)

        # Verify expected fields are present
        assert "asn_origin_asn" in result
        assert "asn_origin_as_name" in result
        assert "asn_origin_prefix" in result

        # Verify specific known values for Google DNS
        assert result["asn_origin_asn"] == "15169"

    def test_multiple_ips_lookup(self):
        """Test origin lookup with multiple IPs to verify bulk query."""
        enrichment = OriginEnrichment()

        # Test two different IPs
        ip_data_1 = {"ip": "8.8.8.8"}
        ip_data_2 = {"ip": "1.1.1.1"}

        result_1 = enrichment.enrich(ip_data_1)
        result_2 = enrichment.enrich(ip_data_2)

        # Verify both got enriched
        assert "asn_origin_asn" in result_1
        assert "asn_origin_asn" in result_2

        # Verify they have different ASNs
        assert result_1["asn_origin_asn"] == "15169"  # Google
        assert result_2["asn_origin_asn"] == "13335"  # Cloudflare

    def test_cidr_extraction(self):
        """Test that CIDR notation uses first host IP."""
        enrichment = OriginEnrichment()
        ip_data = {"ip": "8.8.8.0", "cidr": "24"}

        result = enrichment.enrich(ip_data)

        # Should query for 8.8.8.0 (first host) and get Google's ASN
        assert "asn_origin_asn" in result
        assert result["asn_origin_asn"] == "15169"

    def test_private_ip_lookup(self):
        """Test handling of private IP address."""
        enrichment = OriginEnrichment()
        ip_data = {"ip": "192.168.1.1"}

        result = enrichment.enrich(ip_data)

        # Private IPs typically don't have ASN info
        # Should either have error or no data
        assert "asn_origin_error" in result or "asn_origin_asn" not in result or result.get("asn_origin_asn") == ""

    def test_preserves_existing_fields(self):
        """Test that enrichment preserves existing fields."""
        enrichment = OriginEnrichment()
        ip_data = {"ip": "8.8.8.8", "cidr": "32", "classification": "global"}

        result = enrichment.enrich(ip_data)

        # Existing fields should be preserved
        assert result["ip"] == "8.8.8.8"
        assert result["cidr"] == "32"
        assert result["classification"] == "global"
        # New fields should be added
        assert "asn_origin_asn" in result

@pytest.mark.remote
@pytest.mark.ratelimit
class TestPeerEnrichment:
    """Test the Peer ASN enrichment plugin with real API calls."""

    def test_single_ip_peer_lookup(self):
        """Test successful peer lookup for single IP."""
        enrichment = PeerEnrichment()
        ip_data = {"ip": "8.8.8.8"}

        result = enrichment.enrich(ip_data)

        # Verify expected fields are present
        assert "asn_peer_asns" in result
        assert "asn_peer_count" in result

        # Verify data types
        assert isinstance(result["asn_peer_asns"], str)
        assert isinstance(result["asn_peer_count"], str)

        # Verify count is a valid number
        count = int(result["asn_peer_count"])
        assert count >= 0

        # If there are peers, verify format
        if count > 0:
            assert "|" in result["asn_peer_asns"] or count == 1
            # Verify ASNs are numeric
            asns = result["asn_peer_asns"].split("|")
            for asn in asns:
                assert asn.isdigit()

    def test_multiple_ips_peer_lookup(self):
        """Test peer lookup with multiple IPs."""
        enrichment = PeerEnrichment()

        ip_data_1 = {"ip": "8.8.8.8"}
        ip_data_2 = {"ip": "1.1.1.1"}

        result_1 = enrichment.enrich(ip_data_1)
        result_2 = enrichment.enrich(ip_data_2)

        # Verify both got enriched
        assert "asn_peer_count" in result_1
        assert "asn_peer_count" in result_2

        # Both should have valid counts
        assert int(result_1["asn_peer_count"]) >= 0
        assert int(result_2["asn_peer_count"]) >= 0

    def test_peer_includes_asn_info(self):
        """Test that peer response includes ASN information."""
        enrichment = PeerEnrichment()
        ip_data = {"ip": "8.8.8.8"}

        result = enrichment.enrich(ip_data)

        # Peer response should also include origin ASN info
        assert "asn_peer_asn" in result or "asn_peer_asns" in result
        if "asn_peer_asn" in result:
            assert result["asn_peer_asn"] == "15169"

@pytest.mark.remote
@pytest.mark.ratelimit
class TestPrefixEnrichment:
    """Test the Prefix ASN enrichment plugin with real API calls."""

    def test_single_ip_prefix_lookup(self):
        """Test successful prefix lookup with auto-Origin."""
        enrichment = PrefixEnrichment()
        ip_data = {"ip": "8.8.8.8"}

        result = enrichment.enrich(ip_data)

        # Should have origin data (from auto-Origin call)
        assert "asn_origin_asn" in result
        assert result["asn_origin_asn"] == "15169"
        assert "asn_origin_as_name" in result

        # Should have prefix data
        assert "asn_prefix_list" in result
        assert "asn_prefix_count" in result

        # Verify prefix count is valid
        count = int(result["asn_prefix_count"])
        assert count > 0  # Google should have many prefixes

        # Verify prefix list format
        prefixes = result["asn_prefix_list"].split("|")
        assert len(prefixes) == count

        # Verify at least one prefix looks valid (contains /)
        assert any("/" in prefix for prefix in prefixes)

    def test_multiple_ips_prefix_lookup(self):
        """Test prefix lookup with multiple IPs."""
        enrichment = PrefixEnrichment()

        ip_data_1 = {"ip": "8.8.8.8"}
        ip_data_2 = {"ip": "8.8.4.4"}  # Use another Google IP to ensure same ASN

        result_1 = enrichment.enrich(ip_data_1)
        result_2 = enrichment.enrich(ip_data_2)

        # Both should have origin and prefix data
        assert "asn_origin_asn" in result_1
        assert "asn_origin_asn" in result_2
        assert "asn_prefix_count" in result_1
        assert "asn_prefix_count" in result_2

        # Both should have positive counts
        assert int(result_1["asn_prefix_count"]) > 0
        assert int(result_2["asn_prefix_count"]) > 0

    def test_prefix_preserves_origin_data(self):
        """Test that both origin and prefix data are preserved."""
        enrichment = PrefixEnrichment()
        ip_data = {"ip": "8.8.8.8"}

        result = enrichment.enrich(ip_data)

        # Both origin and prefix fields should be present
        assert "asn_origin_asn" in result
        assert "asn_origin_as_name" in result
        assert "asn_origin_prefix" in result
        assert "asn_prefix_list" in result
        assert "asn_prefix_count" in result

    def test_private_ip_prefix_lookup(self):
        """Test prefix lookup for private IP (should fail at origin stage)."""
        enrichment = PrefixEnrichment()
        ip_data = {"ip": "192.168.1.1"}

        result = enrichment.enrich(ip_data)

        # Should have origin error or no ASN
        # Which should prevent prefix lookup
        assert "asn_prefix_error" in result or "asn_origin_error" in result

@pytest.mark.remote
@pytest.mark.ratelimit
class TestASNBaseFeatures:
    """Test base ASN functionality across all plugins."""

    def test_first_host_extraction_ipv4(self):
        """Test first host extraction from IPv4 CIDR."""
        enrichment = OriginEnrichment()
        ip_data = {"ip": "8.8.8.0", "cidr": "24"}

        result = enrichment.enrich(ip_data)

        # Should query with first host (8.8.8.0) and get Google's ASN
        assert "asn_origin_asn" in result
        assert result["asn_origin_asn"] == "15169"

    def test_first_host_extraction_ipv6(self):
        """Test first host extraction from IPv6 CIDR."""
        enrichment = OriginEnrichment()
        ip_data = {"ip": "2001:4860:4860::", "cidr": "32"}

        result = enrichment.enrich(ip_data)

        # Should query with first host and get Google's ASN
        assert "asn_origin_asn" in result
        assert result["asn_origin_asn"] == "15169"

    def test_custom_field_prefix(self):
        """Test custom field prefix."""
        enrichment = OriginEnrichment(field_prefix="custom")
        ip_data = {"ip": "8.8.8.8"}

        result = enrichment.enrich(ip_data)

        # Fields should use custom prefix
        assert "custom_asn" in result
        assert "custom_as_name" in result
        assert result["custom_asn"] == "15169"

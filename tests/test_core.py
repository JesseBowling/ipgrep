"""Tests for core pipeline functionality."""

import pytest
from ipgrep.core import IPGrepPipeline
from ipgrep.plugins.enrichment.ipaddress_enrichment import IPAddressEnrichment
from ipgrep.plugins.output.plain import PlainOutput
from ipgrep.plugins.output.json import JSONOutput
import json

@pytest.mark.local
class TestPipelineBasics:
    """Test basic pipeline functionality."""

    def test_simple_pipeline(self):
        """Test simple pipeline without enrichment."""
        pipeline = IPGrepPipeline()
        text = "Server at 192.168.1.1 is online"
        result = pipeline.process(text)
        assert "192.168.1.1" in result

    def test_multiple_ips(self):
        """Test pipeline with multiple IPs."""
        pipeline = IPGrepPipeline()
        text = "Servers 192.168.1.1 and 10.0.0.1 are online"
        result = pipeline.process(text)
        assert "192.168.1.1" in result
        assert "10.0.0.1" in result

    def test_empty_text(self):
        """Test pipeline with empty text."""
        pipeline = IPGrepPipeline()
        result = pipeline.process("")
        assert result == ""

@pytest.mark.local
class TestPipelineWithCIDR:
    """Test pipeline with CIDR extraction."""

    def test_cidr_extraction(self):
        """Test CIDR extraction."""
        pipeline = IPGrepPipeline(extract_cidr=True)
        text = "Network 192.168.1.0/24"
        result = pipeline.process(text)
        assert "192.168.1.0/24" in result

    def test_default_cidr(self):
        """Test default CIDR assignment."""
        pipeline = IPGrepPipeline(extract_cidr=True)
        text = "Host 192.168.1.1"
        result = pipeline.process(text)
        assert "192.168.1.1/32" in result

@pytest.mark.local
class TestPipelineWithEnrichment:
    """Test pipeline with enrichment plugins."""

    def test_single_enrichment(self):
        """Test pipeline with single enrichment."""
        enrichment = IPAddressEnrichment()
        output = PlainOutput()
        pipeline = IPGrepPipeline(enrichments=[enrichment], output_plugin=output)
        text = "Private IP: 192.168.1.1"
        result = pipeline.process(text)
        assert "192.168.1.1" in result

    def test_enrichment_chain(self):
        """Test chaining multiple enrichments."""
        enrichment1 = IPAddressEnrichment()
        enrichment2 = IPAddressEnrichment(delimiter=",")
        output = JSONOutput()
        pipeline = IPGrepPipeline(
            enrichments=[enrichment1, enrichment2], output_plugin=output
        )
        text = "IP: 192.168.1.1"
        result = pipeline.process(text)
        parsed = json.loads(result)
        # Second enrichment should override classification with comma delimiter
        assert "classification" in parsed[0]

@pytest.mark.local
class TestPipelineWithOutput:
    """Test pipeline with different output formats."""

    def test_json_output(self):
        """Test pipeline with JSON output."""
        output = JSONOutput()
        pipeline = IPGrepPipeline(output_plugin=output)
        text = "IP: 192.168.1.1"
        result = pipeline.process(text)
        parsed = json.loads(result)
        assert len(parsed) == 1
        assert parsed[0]["ip"] == "192.168.1.1"

    def test_plain_output(self):
        """Test pipeline with plain output."""
        output = PlainOutput()
        pipeline = IPGrepPipeline(output_plugin=output)
        text = "IP: 192.168.1.1"
        result = pipeline.process(text)
        assert result == "192.168.1.1"

@pytest.mark.local
class TestEndToEnd:
    """End-to-end integration tests."""

    def test_full_pipeline_with_enrichment_and_cidr(self):
        """Test complete pipeline with all features."""
        enrichment = IPAddressEnrichment()
        output = JSONOutput()
        pipeline = IPGrepPipeline(
            extract_cidr=True, enrichments=[enrichment], output_plugin=output
        )
        text = """
        Private network: 192.168.1.0/24
        Public DNS: 8.8.8.8
        Loopback: 127.0.0.1
        """
        result = pipeline.process(text)
        parsed = json.loads(result)

        # Should have 3 IPs
        assert len(parsed) == 3

        # Check that all have CIDR
        for ip_data in parsed:
            assert "cidr" in ip_data

        # Check that all have classification
        for ip_data in parsed:
            assert "classification" in ip_data

    def test_mixed_ipv4_ipv6(self):
        """Test pipeline with mixed IP versions."""
        pipeline = IPGrepPipeline()
        text = "IPv4: 192.168.1.1 and IPv6: 2001:db8::1"
        result = pipeline.process(text)
        assert "192.168.1.1" in result
        assert "2001:db8::1" in result

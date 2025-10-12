"""Tests for IP extraction functionality."""

import pytest
from ipgrep.extractor import IPExtractor


class TestIPv4Extraction:
    """Test IPv4 address extraction."""

    def test_basic_ipv4_extraction(self):
        """Test basic IPv4 extraction."""
        extractor = IPExtractor()
        text = "Server at 192.168.1.1 is online"
        result = extractor.extract(text)
        assert ("192.168.1.1", None) in result

    def test_multiple_ipv4(self):
        """Test extracting multiple IPv4 addresses."""
        extractor = IPExtractor()
        text = "Servers 10.0.0.1 and 10.0.0.2 are online"
        result = extractor.extract(text)
        assert len(result) == 2
        assert ("10.0.0.1", None) in result
        assert ("10.0.0.2", None) in result

    def test_ipv4_with_punctuation(self):
        """Test IPv4 extraction with surrounding punctuation."""
        extractor = IPExtractor()
        text = "IP is (192.168.1.1), other is [10.0.0.1]."
        result = extractor.extract(text)
        assert ("192.168.1.1", None) in result
        assert ("10.0.0.1", None) in result

    def test_ipv4_in_url(self):
        """Test IPv4 extraction from URLs."""
        extractor = IPExtractor(extract_cidr=True)
        text = "Visit http://192.168.1.1:8080/path"
        result = extractor.extract(text)
        # IP from URL should be forced to /32
        assert ("192.168.1.1", "32") in result

    def test_invalid_ipv4_rejected(self):
        """Test that invalid IPv4 addresses are rejected."""
        extractor = IPExtractor()
        text = "Invalid: 256.1.1.1 and 192.168.1.256"
        result = extractor.extract(text)
        assert len(result) == 0


class TestIPv6Extraction:
    """Test IPv6 address extraction."""

    def test_basic_ipv6_extraction(self):
        """Test basic IPv6 extraction."""
        extractor = IPExtractor()
        text = "IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        result = extractor.extract(text)
        assert ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", None) in result

    def test_compressed_ipv6(self):
        """Test compressed IPv6 format."""
        extractor = IPExtractor()
        text = "Compressed: 2001:db8::1"
        result = extractor.extract(text)
        assert ("2001:db8::1", None) in result

    def test_ipv6_loopback(self):
        """Test IPv6 loopback address."""
        extractor = IPExtractor()
        text = "Loopback: ::1"
        result = extractor.extract(text)
        assert ("::1", None) in result

    def test_ipv6_in_brackets(self):
        """Test IPv6 in brackets (URL format)."""
        extractor = IPExtractor(extract_cidr=True)
        text = "URL: http://[2001:db8::1]:8080/path"
        result = extractor.extract(text)
        # IP from URL should be forced to /128
        assert ("2001:db8::1", "128") in result


class TestCIDRExtraction:
    """Test CIDR notation extraction."""

    def test_ipv4_with_cidr(self):
        """Test IPv4 with CIDR notation."""
        extractor = IPExtractor(extract_cidr=True)
        text = "Network: 192.168.1.0/24"
        result = extractor.extract(text)
        assert ("192.168.1.0", "24") in result

    def test_ipv4_without_cidr_gets_default(self):
        """Test IPv4 without CIDR gets /32."""
        extractor = IPExtractor(extract_cidr=True)
        text = "Host: 192.168.1.1"
        result = extractor.extract(text)
        assert ("192.168.1.1", "32") in result

    def test_ipv6_with_cidr(self):
        """Test IPv6 with CIDR notation."""
        extractor = IPExtractor(extract_cidr=True)
        text = "Network: 2001:db8::/32"
        result = extractor.extract(text)
        assert ("2001:db8::", "32") in result

    def test_ipv6_without_cidr_gets_default(self):
        """Test IPv6 without CIDR gets /128."""
        extractor = IPExtractor(extract_cidr=True)
        text = "Host: 2001:db8::1"
        result = extractor.extract(text)
        assert ("2001:db8::1", "128") in result

    def test_invalid_cidr_rejected(self):
        """Test invalid CIDR values are rejected."""
        extractor = IPExtractor(extract_cidr=True)
        # Invalid CIDR for IPv4 (> 32)
        text = "Invalid: 192.168.1.0/33"
        result = extractor.extract(text)
        assert len(result) == 0


class TestEdgeCases:
    """Test edge cases in IP extraction."""

    def test_duplicate_ips_deduplicated(self):
        """Test that duplicate IPs are deduplicated."""
        extractor = IPExtractor()
        text = "192.168.1.1 and 192.168.1.1 again"
        result = extractor.extract(text)
        assert len(result) == 1
        assert ("192.168.1.1", None) in result

    def test_empty_text(self):
        """Test extraction from empty text."""
        extractor = IPExtractor()
        text = ""
        result = extractor.extract(text)
        assert len(result) == 0

    def test_no_ips_in_text(self):
        """Test text with no IP addresses."""
        extractor = IPExtractor()
        text = "This text has no IP addresses at all"
        result = extractor.extract(text)
        assert len(result) == 0

    def test_mixed_ipv4_ipv6(self):
        """Test text with both IPv4 and IPv6."""
        extractor = IPExtractor()
        text = "IPv4: 192.168.1.1 and IPv6: 2001:db8::1"
        result = extractor.extract(text)
        assert len(result) == 2
        assert ("192.168.1.1", None) in result
        assert ("2001:db8::1", None) in result

    def test_ip_port_notation(self):
        """Test IP with port notation."""
        extractor = IPExtractor()
        text = "Server at 192.168.1.1:8080"
        result = extractor.extract(text)
        # Should extract just the IP, not the port
        assert ("192.168.1.1", None) in result

"""Tests for IP extraction functionality."""

import pytest
from ipgrep.extractor import IPExtractor

@pytest.mark.local
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

@pytest.mark.local
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

@pytest.mark.local
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

@pytest.mark.local
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

@pytest.mark.local
class TestDefangedIPs:
    """Test defanged IP address extraction."""

    def test_square_bracket_defanged_ipv4(self):
        """Test IPv4 with square bracket defanging."""
        extractor = IPExtractor(defang=True)
        text = "Malicious IP: 192[.]168[.]1[.]100"
        result = extractor.extract(text)
        assert ("192.168.1.100", None) in result

    def test_partial_square_bracket_defanged(self):
        """Test partially defanged IPv4."""
        extractor = IPExtractor(defang=True)
        text = "IOC: 10.0[.]0[.]1"
        result = extractor.extract(text)
        assert ("10.0.0.1", None) in result

    def test_parenthesis_defanged_ipv4(self):
        """Test IPv4 with parenthesis defanging."""
        extractor = IPExtractor(defang=True)
        text = "Threat: 8(.)8(.)8(.)8"
        result = extractor.extract(text)
        assert ("8.8.8.8", None) in result

    def test_dot_text_defanged_lowercase(self):
        """Test IPv4 with [dot] text defanging."""
        extractor = IPExtractor(defang=True)
        text = "Bad IP: 1[dot]2[dot]3[dot]4"
        result = extractor.extract(text)
        assert ("1.2.3.4", None) in result

    def test_dot_text_defanged_uppercase(self):
        """Test IPv4 with [DOT] text defanging."""
        extractor = IPExtractor(defang=True)
        text = "Indicator: 172[DOT]16[DOT]0[DOT]1"
        result = extractor.extract(text)
        assert ("172.16.0.1", None) in result

    def test_dot_text_defanged_mixed_case(self):
        """Test IPv4 with mixed case [DoT] text defanging."""
        extractor = IPExtractor(defang=True)
        text = "IP: 10[DoT]20[dOt]30[DOT]40"
        result = extractor.extract(text)
        assert ("10.20.30.40", None) in result

    def test_paren_dot_text_defanged(self):
        """Test IPv4 with (dot) text defanging."""
        extractor = IPExtractor(defang=True)
        text = "C2: 203(dot)0(dot)113(dot)5"
        result = extractor.extract(text)
        assert ("203.0.113.5", None) in result

    def test_defanged_with_cidr(self):
        """Test defanged IPv4 with CIDR notation."""
        extractor = IPExtractor(extract_cidr=True, defang=True)
        text = "Network: 192[.]168[.]0[.]0/24"
        result = extractor.extract(text)
        assert ("192.168.0.0", "24") in result

    def test_multiple_defanged_ips(self):
        """Test extracting multiple defanged IPs."""
        extractor = IPExtractor(defang=True)
        text = "IPs: 10[.]0[.]0[.]1 and 192[.]168[.]1[.]1"
        result = extractor.extract(text)
        assert len(result) == 2
        assert ("10.0.0.1", None) in result
        assert ("192.168.1.1", None) in result

    def test_mixed_defanged_patterns(self):
        """Test mixed defanging patterns in same text."""
        extractor = IPExtractor(defang=True)
        text = "IPs: 1[.]2[.]3[.]4 and 5(dot)6(dot)7(dot)8"
        result = extractor.extract(text)
        assert len(result) == 2
        assert ("1.2.3.4", None) in result
        assert ("5.6.7.8", None) in result

    def test_defanged_with_enrichment(self):
        """Test defanged IP can be enriched."""
        extractor = IPExtractor(defang=True, extract_cidr=True)
        text = "Threat: 8[.]8[.]8[.]8"
        result = extractor.extract(text)
        assert ("8.8.8.8", "32") in result

    def test_defang_disabled_by_default(self):
        """Test that defanging is not applied when disabled."""
        extractor = IPExtractor(defang=False)
        text = "IP: 192[.]168[.]1[.]1"
        result = extractor.extract(text)
        # Should not extract defanged IP when defang=False
        assert len(result) == 0

    def test_normal_ips_still_work_with_defang_enabled(self):
        """Test that normal IPs still work when defang is enabled."""
        extractor = IPExtractor(defang=True)
        text = "Normal IP: 192.168.1.1"
        result = extractor.extract(text)
        assert ("192.168.1.1", None) in result

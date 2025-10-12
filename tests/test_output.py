"""Tests for output plugins."""

import json
import pytest
from ipgrep.plugins.output.plain import PlainOutput
from ipgrep.plugins.output.csv import CSVOutput
from ipgrep.plugins.output.json import JSONOutput
from ipgrep.plugins.output.space_delimited import SpaceDelimitedOutput
from ipgrep.plugins.output.pipe_delimited import PipeDelimitedOutput


class TestPlainOutput:
    """Test plain text output plugin."""

    def test_simple_output(self):
        """Test simple plain output."""
        plugin = PlainOutput()
        ip_data = [{"ip": "192.168.1.1"}, {"ip": "10.0.0.1"}]
        result = plugin.format(ip_data)
        assert "192.168.1.1" in result
        assert "10.0.0.1" in result
        lines = result.split("\n")
        assert len(lines) == 2

    def test_output_with_cidr(self):
        """Test plain output with CIDR."""
        plugin = PlainOutput()
        ip_data = [{"ip": "192.168.1.0", "cidr": "24"}]
        result = plugin.format(ip_data)
        assert "192.168.1.0/24" in result

    def test_empty_list(self):
        """Test output with empty list."""
        plugin = PlainOutput()
        result = plugin.format([])
        assert result == ""


class TestCSVOutput:
    """Test CSV output plugin."""

    def test_simple_csv(self):
        """Test simple CSV output."""
        plugin = CSVOutput()
        ip_data = [{"ip": "192.168.1.1"}, {"ip": "10.0.0.1"}]
        result = plugin.format(ip_data)
        lines = result.split("\n")
        assert "ip" in lines[0]  # Header
        assert "192.168.1.1" in result
        assert "10.0.0.1" in result

    def test_csv_with_enrichment(self):
        """Test CSV with enrichment fields."""
        plugin = CSVOutput()
        ip_data = [
            {"ip": "192.168.1.1", "classification": "private"},
            {"ip": "8.8.8.8", "classification": "global"},
        ]
        result = plugin.format(ip_data)
        lines = result.split("\n")
        # Header should include both fields
        assert "ip" in lines[0]
        assert "classification" in lines[0]
        assert "private" in result
        assert "global" in result

    def test_csv_with_cidr(self):
        """Test CSV with CIDR notation."""
        plugin = CSVOutput()
        ip_data = [{"ip": "192.168.1.0", "cidr": "24"}]
        result = plugin.format(ip_data)
        assert "ip" in result
        assert "cidr" in result
        assert "24" in result

    def test_csv_empty_list(self):
        """Test CSV with empty list."""
        plugin = CSVOutput()
        result = plugin.format([])
        assert result == ""


class TestJSONOutput:
    """Test JSON output plugin."""

    def test_simple_json(self):
        """Test simple JSON output."""
        plugin = JSONOutput()
        ip_data = [{"ip": "192.168.1.1"}, {"ip": "10.0.0.1"}]
        result = plugin.format(ip_data)
        parsed = json.loads(result)
        assert len(parsed) == 2
        assert parsed[0]["ip"] == "192.168.1.1"
        assert parsed[1]["ip"] == "10.0.0.1"

    def test_json_with_enrichment(self):
        """Test JSON with enrichment fields."""
        plugin = JSONOutput()
        ip_data = [
            {"ip": "192.168.1.1", "classification": "private"},
        ]
        result = plugin.format(ip_data)
        parsed = json.loads(result)
        assert parsed[0]["ip"] == "192.168.1.1"
        assert parsed[0]["classification"] == "private"

    def test_json_empty_list(self):
        """Test JSON with empty list."""
        plugin = JSONOutput()
        result = plugin.format([])
        parsed = json.loads(result)
        assert parsed == []


class TestSpaceDelimitedOutput:
    """Test space delimited output plugin."""

    def test_simple_space_delimited(self):
        """Test simple space delimited output."""
        plugin = SpaceDelimitedOutput()
        ip_data = [{"ip": "192.168.1.1"}, {"ip": "10.0.0.1"}]
        result = plugin.format(ip_data)
        lines = result.split("\n")
        assert len(lines) == 2
        assert "192.168.1.1" in lines[0]
        assert "10.0.0.1" in lines[1]

    def test_space_delimited_with_enrichment(self):
        """Test space delimited with enrichment."""
        plugin = SpaceDelimitedOutput()
        ip_data = [
            {"ip": "192.168.1.1", "classification": "private"},
        ]
        result = plugin.format(ip_data)
        assert "192.168.1.1" in result
        assert "private" in result
        assert " " in result  # Should have space delimiter

    def test_space_delimited_with_cidr(self):
        """Test space delimited with CIDR."""
        plugin = SpaceDelimitedOutput()
        ip_data = [{"ip": "192.168.1.0", "cidr": "24"}]
        result = plugin.format(ip_data)
        assert "192.168.1.0/24" in result

    def test_space_delimited_empty_list(self):
        """Test space delimited with empty list."""
        plugin = SpaceDelimitedOutput()
        result = plugin.format([])
        assert result == ""


class TestPipeDelimitedOutput:
    """Test pipe delimited output plugin."""

    def test_simple_pipe_delimited(self):
        """Test simple pipe delimited output."""
        plugin = PipeDelimitedOutput()
        ip_data = [{"ip": "192.168.1.1"}, {"ip": "10.0.0.1"}]
        result = plugin.format(ip_data)
        lines = result.split("\n")
        assert len(lines) == 2
        assert "192.168.1.1" in lines[0]
        assert "10.0.0.1" in lines[1]

    def test_pipe_delimited_with_enrichment(self):
        """Test pipe delimited with enrichment."""
        plugin = PipeDelimitedOutput()
        ip_data = [
            {"ip": "192.168.1.1", "classification": "private"},
        ]
        result = plugin.format(ip_data)
        assert "192.168.1.1" in result
        assert "private" in result
        assert "|" in result  # Should have pipe delimiter

    def test_pipe_delimited_with_cidr(self):
        """Test pipe delimited with CIDR."""
        plugin = PipeDelimitedOutput()
        ip_data = [{"ip": "192.168.1.0", "cidr": "24"}]
        result = plugin.format(ip_data)
        assert "192.168.1.0/24" in result

    def test_pipe_delimited_empty_list(self):
        """Test pipe delimited with empty list."""
        plugin = PipeDelimitedOutput()
        result = plugin.format([])
        assert result == ""

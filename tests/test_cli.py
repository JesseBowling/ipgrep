"""Tests for CLI functionality."""

import pytest
import sys
import io
from unittest.mock import patch, mock_open
from ipgrep.cli import main


@pytest.mark.local
class TestCLIBasicUsage:
    """Test basic CLI argument parsing and execution."""

    def test_help_message(self):
        """Test that --help displays usage information."""
        with patch("sys.argv", ["ipgrep", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_stdin_input(self):
        """Test reading from stdin."""
        test_input = "Server at 192.168.1.1 is online"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.1" in output

    def test_file_input(self):
        """Test reading from file."""
        test_content = "IP: 192.168.1.1"
        with patch("sys.argv", ["ipgrep", "-f", "test.txt"]):
            with patch("builtins.open", mock_open(read_data=test_content)):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.1" in output

    def test_file_not_found(self):
        """Test error handling for missing file."""
        with patch("sys.argv", ["ipgrep", "-f", "nonexistent.txt"]):
            with patch("builtins.open", side_effect=IOError("File not found")):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    assert exc_info.value.code == 1
                    stderr_output = mock_stderr.getvalue()
                    assert "Error reading file" in stderr_output

    def test_empty_input(self):
        """Test handling of empty input."""
        with patch("sys.stdin", io.StringIO("")):
            with patch("sys.argv", ["ipgrep"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert output == ""

    def test_no_ips_in_input(self):
        """Test handling when no IPs are found."""
        test_input = "No IP addresses in this text"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert output == ""

    def test_multiple_ips(self):
        """Test extracting multiple IPs."""
        test_input = "Server 192.168.1.1 and 10.0.0.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.1" in output
                    assert "10.0.0.1" in output


@pytest.mark.local
class TestCLIFlags:
    """Test CLI flag combinations."""

    def test_cidr_flag_short(self):
        """Test -c flag for CIDR notation."""
        test_input = "Network: 192.168.1.0/24"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-c"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.0/24" in output

    def test_cidr_flag_long(self):
        """Test --cidr flag for CIDR notation."""
        test_input = "Host: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "--cidr"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.1/32" in output

    def test_defang_flag_short(self):
        """Test -g flag for defanged IPs."""
        test_input = "Malicious: 192[.]168[.]1[.]1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-g"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.1" in output

    def test_defang_flag_long(self):
        """Test --defang flag for defanged IPs."""
        test_input = "IOC: 8[dot]8[dot]8[dot]8"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "--defang"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "8.8.8.8" in output

    def test_cidr_and_defang_combined(self):
        """Test combining -c and -g flags."""
        test_input = "Network: 192[.]168[.]1[.]0/24"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-c", "-g"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.0/24" in output

    def test_file_flag_short(self):
        """Test -f flag for file input."""
        test_content = "IP: 10.0.0.1"
        with patch("sys.argv", ["ipgrep", "-f", "input.txt"]):
            with patch("builtins.open", mock_open(read_data=test_content)):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "10.0.0.1" in output

    def test_file_flag_long(self):
        """Test --file flag for file input."""
        test_content = "IP: 172.16.0.1"
        with patch("sys.argv", ["ipgrep", "--file", "data.txt"]):
            with patch("builtins.open", mock_open(read_data=test_content)):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "172.16.0.1" in output


@pytest.mark.local
class TestCLIEnrichments:
    """Test enrichment plugin options."""

    def test_single_enrichment_short(self):
        """Test -e flag with single enrichment."""
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.1" in output
                    assert "private" in output

    def test_single_enrichment_long(self):
        """Test --enrich flag with single enrichment."""
        test_input = "IP: 8.8.8.8"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "--enrich", "ipaddress"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "8.8.8.8" in output
                    assert "global" in output

    def test_multiple_enrichments(self):
        """Test chaining multiple enrichments."""
        test_input = "IP: 8.8.8.8"
        with patch("sys.stdin", io.StringIO(test_input)):
            # Chain the same enrichment twice to test chaining mechanism
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress", "-e", "ipaddress"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "8.8.8.8" in output

    def test_unknown_enrichment_plugin(self):
        """Test error handling for unknown enrichment."""
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-e", "nonexistent"]):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    assert exc_info.value.code == 1
                    stderr_output = mock_stderr.getvalue()
                    assert "Unknown enrichment plugin" in stderr_output
                    assert "nonexistent" in stderr_output

    def test_enrichment_with_cidr(self):
        """Test enrichment combined with CIDR flag."""
        test_input = "Network: 192.168.1.0/24"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-c", "-e", "ipaddress"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.0" in output
                    assert "24" in output

    def test_enrichment_with_defang(self):
        """Test enrichment combined with defang flag."""
        test_input = "Threat: 192[.]168[.]1[.]1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-g", "-e", "ipaddress"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.1" in output
                    assert "private" in output


@pytest.mark.local
class TestCLIOutputFormats:
    """Test output format options."""

    def test_plain_output_default(self):
        """Test plain output is default without enrichments."""
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert output.strip() == "192.168.1.1"

    def test_csv_output_default_with_enrichment(self):
        """Test CSV is default when using enrichments."""
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "ip,classification" in output
                    assert "192.168.1.1,private" in output

    def test_json_output_short_flag(self):
        """Test -o json output format."""
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress", "-o", "json"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert output.strip().startswith("[")
                    assert "192.168.1.1" in output

    def test_json_output_long_flag(self):
        """Test --output json format."""
        test_input = "IP: 8.8.8.8"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress", "--output", "json"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert '"ip": "8.8.8.8"' in output

    def test_csv_output_explicit(self):
        """Test explicit CSV output."""
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress", "-o", "csv"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    lines = output.strip().split("\n")
                    assert len(lines) == 2  # Header + data
                    assert "ip,classification" in lines[0]

    def test_space_output(self):
        """Test space-delimited output."""
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress", "-o", "space"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.1 private" in output

    def test_pipe_output(self):
        """Test pipe-delimited output."""
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress", "-o", "pipe"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.1|private" in output

    def test_plain_output_explicit(self):
        """Test explicit plain output."""
        test_input = "IP: 192.168.1.1 and 10.0.0.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-o", "plain"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    lines = output.strip().split("\n")
                    assert "192.168.1.1" in lines
                    assert "10.0.0.1" in lines

    def test_unknown_output_format(self):
        """Test error handling for unknown output format."""
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-o", "nonexistent"]):
                with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    assert exc_info.value.code == 1
                    stderr_output = mock_stderr.getvalue()
                    assert "Unknown output format" in stderr_output
                    assert "nonexistent" in stderr_output

    def test_output_override_default(self):
        """Test that explicit output overrides default."""
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            # With enrichment, default would be CSV, but we override to JSON
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress", "-o", "json"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert output.strip().startswith("[")
                    assert "ip,classification" not in output  # Not CSV


@pytest.mark.local
class TestCLIListCommands:
    """Test --list commands."""

    def test_list_enrichments(self):
        """Test --list-enrichments command."""
        with patch("sys.argv", ["ipgrep", "--list-enrichments"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0
                output = mock_stdout.getvalue()
                assert "Available enrichment plugins:" in output
                assert "ipaddress" in output

    def test_list_outputs(self):
        """Test --list-outputs command."""
        with patch("sys.argv", ["ipgrep", "--list-outputs"]):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0
                output = mock_stdout.getvalue()
                assert "Available output plugins:" in output
                assert "plain" in output
                assert "csv" in output
                assert "json" in output
                assert "space" in output
                assert "pipe" in output

    def test_list_enrichments_exits_before_processing(self):
        """Test that --list-enrichments exits without processing input."""
        # Even with stdin input, should exit before reading it
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "--list-enrichments"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    assert exc_info.value.code == 0
                    output = mock_stdout.getvalue()
                    # Should show plugin list, not process IPs
                    assert "Available enrichment plugins:" in output
                    assert "192.168.1.1" not in output

    def test_list_outputs_exits_before_processing(self):
        """Test that --list-outputs exits without processing input."""
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "--list-outputs"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    assert exc_info.value.code == 0
                    output = mock_stdout.getvalue()
                    assert "Available output plugins:" in output
                    assert "192.168.1.1" not in output


@pytest.mark.local
class TestCLIIntegration:
    """End-to-end CLI integration tests."""

    def test_full_pipeline_file_cidr_enrichment_csv(self):
        """Test complete pipeline: file input, CIDR, enrichment, CSV output."""
        test_content = "Network: 192.168.1.0/24\nHost: 8.8.8.8"
        with patch("sys.argv", ["ipgrep", "-f", "test.txt", "-c", "-e", "ipaddress"]):
            with patch("builtins.open", mock_open(read_data=test_content)):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    # Check for both IPs
                    assert "192.168.1.0" in output
                    assert "8.8.8.8" in output
                    # Check for classifications
                    assert "private" in output
                    assert "global" in output
                    # Check for CIDR
                    assert "24" in output

    def test_defanged_with_enrichment_json(self):
        """Test defanged IPs with enrichment and JSON output."""
        test_input = "Threat: 8[.]8[.]8[.]8"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-g", "-e", "ipaddress", "-o", "json"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "8.8.8.8" in output
                    assert "global" in output
                    assert output.strip().startswith("[")

    def test_multiple_flags_and_enrichments(self):
        """Test combining multiple flags with multiple enrichments."""
        test_content = "IOC: 192[.]168[.]1[.]0/24"
        with patch("sys.argv", [
            "ipgrep",
            "-f", "threats.txt",
            "-c",
            "-g",
            "-e", "ipaddress",
            "-o", "space"
        ]):
            with patch("builtins.open", mock_open(read_data=test_content)):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.0" in output
                    assert "24" in output
                    assert "private" in output

    def test_stdin_pipeline_with_multiple_ips(self):
        """Test stdin with multiple IPs and enrichment."""
        test_input = "Servers: 192.168.1.1, 10.0.0.1, 8.8.8.8"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress", "-o", "csv"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    lines = output.strip().split("\n")
                    # Should have header + 3 data lines
                    assert len(lines) == 4
                    assert "ip,classification" in lines[0]
                    # All IPs should be present
                    output_text = "\n".join(lines[1:])
                    assert "192.168.1.1" in output_text
                    assert "10.0.0.1" in output_text
                    assert "8.8.8.8" in output_text

    def test_file_with_no_ips(self):
        """Test file input with no IPs."""
        test_content = "This file has no IP addresses at all"
        with patch("sys.argv", ["ipgrep", "-f", "empty.txt"]):
            with patch("builtins.open", mock_open(read_data=test_content)):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert output == ""

    def test_cidr_without_enrichment(self):
        """Test CIDR extraction without enrichment (plain output)."""
        test_input = "Network: 10.0.0.0/8 and host 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-c"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "10.0.0.0/8" in output
                    assert "192.168.1.1/32" in output

    def test_ipv6_addresses(self):
        """Test extracting IPv6 addresses."""
        test_input = "IPv6: 2001:db8::1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "2001:db8::1" in output

    def test_mixed_ipv4_ipv6(self):
        """Test extracting mixed IPv4 and IPv6 addresses."""
        test_input = "Servers: 192.168.1.1 and 2001:db8::1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    assert "192.168.1.1" in output
                    assert "2001:db8::1" in output
                    assert "private" in output  # Both should be private

    def test_enrichment_error_handling(self):
        """Test that enrichment errors don't crash the CLI."""
        # Private IPs may return errors from some enrichments, should still work
        test_input = "IP: 192.168.1.1"
        with patch("sys.stdin", io.StringIO(test_input)):
            with patch("sys.argv", ["ipgrep", "-e", "ipaddress", "-o", "json"]):
                with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                    main()
                    output = mock_stdout.getvalue()
                    # Should complete successfully even if some enrichment fails
                    assert "192.168.1.1" in output

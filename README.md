# ipgrep

A modular command line utility for extracting and enriching IP addresses (IPv4 and IPv6) from arbitrary text.

## Features

- Extract IPv4 and IPv6 addresses from any text (stdin or files)
- Optional CIDR notation support
- Modular plugin architecture for enrichment and output formatting
- Built-in enrichment using Python's `ipaddress` library for IP classification
- Multiple output formats: plain, CSV, JSON, space-delimited, pipe-delimited
- Chainable enrichments for complex data processing
- Comprehensive test coverage
- Type-safe and well-documented

## Installation

### Using uv (recommended)

```bash
git clone https://github.com/yourusername/ipgrep.git
cd ipgrep
uv sync
```

### Using pip

```bash
pip install .
```

### Development Installation

```bash
uv sync --all-extras
```

## Building a Distributable Package

To create a package that can be installed on a fresh machine:

### Build the Package

Using uv (recommended):
```bash
uv build
```

This creates distribution files in the `dist/` directory:
- `ipgrep-0.1.0-py3-none-any.whl` (wheel - preferred format)
- `ipgrep-0.1.0.tar.gz` (source distribution)

Alternatively, using standard Python build tools:
```bash
pip install build
python -m build
```

### Install on a Fresh Machine

Transfer the built package to the target machine and install:

**Using the wheel (recommended):**
```bash
pip install ipgrep-0.1.0-py3-none-any.whl
```

**Using the source distribution:**
```bash
pip install ipgrep-0.1.0.tar.gz
```

**Direct from the dist directory:**
```bash
pip install dist/ipgrep-0.1.0-py3-none-any.whl
```

After installation, the `ipgrep` command will be available system-wide:
```bash
ipgrep --help
```

### Verifying the Installation

Test that the package works correctly:
```bash
echo "Test: 192.168.1.1" | ipgrep
# Expected output: 192.168.1.1

echo "IPs: 192.168.1.1, 8.8.8.8" | ipgrep -e ipaddress -o json
# Expected output: JSON with IP classifications
```

### Publishing to PyPI (Optional)

To make the package publicly available via PyPI:

1. Install twine:
```bash
pip install twine
```

2. Upload to PyPI:
```bash
twine upload dist/*
```

3. Install from PyPI:
```bash
pip install ipgrep
```

**Note:** You'll need a PyPI account and proper credentials configured.

## Quick Start

### Basic Usage

Extract IP addresses from stdin:
```bash
cat logfile.txt | ipgrep
# Output:
# 192.168.1.1
# 10.0.0.1
```

Extract from a file:
```bash
ipgrep -f logfile.txt
```

### CIDR Notation

Extract with CIDR notation (adds /32 or /128 for host IPs):
```bash
ipgrep -c -f network_config.txt
# Output:
# 192.168.1.0/24
# 192.168.1.1/32
# 2001:db8::/32
```

### Enrichment

Enrich IPs with classification data:
```bash
ipgrep -e ipaddress -f logfile.txt
# Output:
# 192.168.1.1
# 10.0.0.1
# 8.8.8.8
```

View classification with JSON output:
```bash
ipgrep -e ipaddress -o json -f logfile.txt
# Output:
# [
#   {
#     "ip": "192.168.1.1",
#     "classification": "private"
#   },
#   {
#     "ip": "8.8.8.8",
#     "classification": "global"
#   }
# ]
```

### Output Formats

**CSV output:**
```bash
ipgrep -e ipaddress -o csv -f logfile.txt
# Output:
# ip,classification
# 192.168.1.1,private
# 8.8.8.8,global
```

**Space-delimited output:**
```bash
ipgrep -e ipaddress -o space -f logfile.txt
# Output:
# 192.168.1.1 private
# 8.8.8.8 global
```

**Pipe-delimited output:**
```bash
ipgrep -e ipaddress -o pipe -f logfile.txt
# Output:
# 192.168.1.1|private
# 8.8.8.8|global
```

### Chaining Enrichments

Chain multiple enrichments together:
```bash
ipgrep -e ipaddress -e another_enrichment -o json -f logfile.txt
```

### List Available Plugins

List enrichment plugins:
```bash
ipgrep --list-enrichments
```

List output formats:
```bash
ipgrep --list-outputs
```

## IP Address Classification

The built-in `ipaddress` enrichment plugin classifies IPs using Python's `ipaddress` library:

- `multicast` - Multicast addresses
- `private` - Private/RFC1918 addresses
- `global` - Global/public addresses
- `reserved` - Reserved addresses
- `loopback` - Loopback addresses (127.0.0.0/8, ::1)
- `link_local` - Link-local addresses
- `unspecified` - Unspecified addresses (0.0.0.0, ::)

Multiple classifications are joined with a pipe delimiter (configurable).

## ASN Enrichment

ipgrep includes three enrichment plugins that query ASN (Autonomous System Number) information using the [Shadowserver API](https://www.shadowserver.org/what-we-do/network-reporting/api-documentation/):

- **origin**: Lookup origin ASN information for an IP
- **peer**: Query peer ASN relationships
- **prefix**: Query prefix information (automatically calls origin first)

### Features

- **Bulk lookups**: Automatically batches IPs for efficient API requests (10 IPs per request)
- **Rate limiting**: Respects Shadowserver's 10 IPs/request limit with 1-second delays between batches
- **Retry logic**: Exponential backoff retry (0.5s, 1s, 2s, 4s) with 10-second max timeout
- **IPv6 support**: Full support for both IPv4 and IPv6 addresses
- **CIDR handling**: Uses first host IP when CIDR notation is present
- **Field prefixing**: All fields are prefixed with plugin name to avoid conflicts

### Origin Enrichment

Queries origin ASN information for an IP address.

**Usage:**
```bash
echo "8.8.8.8" | ipgrep -e origin -o json
```

**Output fields:**
- `origin_asn` - Origin ASN number
- `origin_as_name` - AS name/organization
- `origin_prefix` - Network prefix
- `origin_cc` - Country code
- `origin_registry` - Regional Internet Registry (ARIN, RIPE, etc.)
- `origin_error` - Error indicator if lookup fails

**Example output (JSON):**
```json
[
  {
    "ip": "8.8.8.8",
    "origin_asn": "15169",
    "origin_as_name": "GOOGLE",
    "origin_prefix": "8.8.8.0/24",
    "origin_cc": "US",
    "origin_registry": "arin"
  }
]
```

**Example output (CSV):**
```bash
echo "8.8.8.8" | ipgrep -e origin -o csv
# ip,origin_asn,origin_as_name,origin_cc,origin_prefix,origin_registry
# 8.8.8.8,15169,GOOGLE,US,8.8.8.0/24,arin
```

### Peer Enrichment

Queries peer ASN relationships for an IP address.

**Usage:**
```bash
echo "8.8.8.8" | ipgrep -e peer -o json
```

**Output fields:**
- `peer_asns` - Pipe-delimited list of peer ASN numbers
- `peer_names` - Pipe-delimited list of peer AS names
- `peer_count` - Number of peers
- `peer_asn` - Origin ASN (if included in response)
- `peer_prefix` - Network prefix (if included in response)
- `peer_cc` - Country code (if included in response)
- `peer_error` - Error indicator if lookup fails

**Example output (JSON):**
```json
[
  {
    "ip": "8.8.8.8",
    "peer_asns": "174|3356|1299",
    "peer_names": "COGENT|LEVEL3|TELIA",
    "peer_count": "3"
  }
]
```

### Prefix Enrichment

Queries prefix information for an ASN. This plugin automatically calls the origin plugin first to determine the ASN, then queries prefix data for that ASN.

**Usage:**
```bash
echo "8.8.8.8" | ipgrep -e prefix -o json
```

**Output fields:**
- All `origin_*` fields from the origin lookup
- `prefix_list` - Pipe-delimited list of prefixes for the ASN
- `prefix_count` - Number of prefixes
- `prefix_countries` - Pipe-delimited list of countries
- `prefix_registries` - Pipe-delimited list of registries
- `prefix_error` - Error indicator if lookup fails

**Example output (JSON):**
```json
[
  {
    "ip": "8.8.8.8",
    "origin_asn": "15169",
    "origin_as_name": "GOOGLE",
    "origin_prefix": "8.8.8.0/24",
    "origin_cc": "US",
    "origin_registry": "arin",
    "prefix_list": "8.8.8.0/24|8.8.4.0/24|8.35.200.0/21",
    "prefix_count": "3",
    "prefix_countries": "US",
    "prefix_registries": "arin"
  }
]
```

### Chaining ASN Enrichments

You can chain multiple ASN enrichments together with other enrichments:

```bash
# Combine origin and peer information
echo "8.8.8.8 1.1.1.1" | ipgrep -e origin -e peer -o csv

# Combine IP classification with ASN data
echo "8.8.8.8" | ipgrep -e ipaddress -e origin -o json

# Get complete ASN data including prefixes
echo "8.8.8.8" | ipgrep -e prefix -o json
# Note: prefix automatically includes origin data
```

### ASN Enrichment with CIDR

When using CIDR notation, ASN enrichment uses only the first host IP:

```bash
echo "8.8.8.0/24" | ipgrep -c -e origin -o json
# Queries origin data for 8.8.8.0 (first host)
```

### Performance Considerations

- **Bulk processing**: The ASN plugins automatically batch multiple IPs into efficient API requests
- **Rate limiting**: Shadowserver API allows 10 IPs per request with 1 request per second. The plugins automatically batch IPs in groups of 10 with 1-second delays between batches to respect this limit.
  - Example: 85 IPs will take ~8-9 seconds (9 batches with 8 delays)
- **Retry logic**: Exponential backoff handles transient errors and timeouts gracefully
- **Timeout**: Maximum 10-second timeout per request to prevent hanging

### API Requirements

The ASN enrichment plugins use the public Shadowserver API, which:
- Requires no authentication
- Has no strict rate limits for reasonable use
- Supports both IPv4 and IPv6
- Returns JSON-formatted responses

For more information, see the [Shadowserver API documentation](https://www.shadowserver.org/what-we-do/network-reporting/api-documentation/).

## Plugin Development

### Creating an Enrichment Plugin

```python
from ipgrep.plugins.base import EnrichmentPlugin
from typing import Dict, Any

class MyEnrichment(EnrichmentPlugin):
    def name(self) -> str:
        return "my_enrichment"

    def enrich(self, ip_data: Dict[str, Any]) -> Dict[str, Any]:
        ip_str = ip_data['ip']
        # Add your enrichment logic here
        ip_data['my_field'] = some_value
        return ip_data
```

Register in `pyproject.toml`:
```toml
[project.entry-points."ipgrep.enrichment"]
my_enrichment = "my_package.enrichment:MyEnrichment"
```

### Creating an Output Plugin

```python
from ipgrep.plugins.base import OutputPlugin
from typing import List, Dict, Any

class MyOutput(OutputPlugin):
    def name(self) -> str:
        return "my_format"

    def format(self, ip_data_list: List[Dict[str, Any]]) -> str:
        # Format the data as needed
        return formatted_string
```

Register in `pyproject.toml`:
```toml
[project.entry-points."ipgrep.output"]
my_format = "my_package.output:MyOutput"
```

## Edge Cases

ipgrep handles various edge cases:

- **URL extraction**: IPs in URLs are forced to host CIDR (/32 or /128)
- **Bracket notation**: IPv6 addresses in brackets `[2001:db8::1]` are properly extracted
- **Punctuation**: IPs surrounded by punctuation are correctly identified
- **Validation**: All extracted IPs are validated before output
- **Deduplication**: Duplicate IPs are automatically removed

## Development

### Running Tests

```bash
uv run pytest
```

### With Coverage

```bash
uv run pytest --cov=ipgrep --cov-report=html
```

### Code Formatting

```bash
uv run black src tests
```

## Project Structure

```
ipgrep/
   src/
      ipgrep/
          __init__.py
          cli.py                 # CLI interface
          core.py                # Core processing pipeline
          extractor.py           # IP/CIDR extraction logic
          plugins/
              base.py            # Base plugin classes
              enrichment/
                 ipaddress_enrichment.py
                 asn_base.py               # Base ASN plugin
                 asn_origin.py             # Origin ASN enrichment
                 asn_peer.py               # Peer ASN enrichment
                 asn_prefix.py             # Prefix ASN enrichment
              output/
                  plain.py
                  csv.py
                  json.py
                  space_delimited.py
                  pipe_delimited.py
   tests/
      test_core.py
      test_enrichment.py
      test_extractor.py
      test_output.py
   pyproject.toml
```

## Requirements

- Python 3.11+
- Standard library only for core functionality
- `requests` library for ASN enrichment plugins (optional)

## License

GNU General Public License v3.0 (GPL-3.0)

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass (`uv run pytest`)
2. Code is formatted with black (`uv run black src tests`)
3. New features include tests
4. Documentation is updated

## Author

Jesse Bowling <jessebowling@gmail.com>

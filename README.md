# ipgrep
[![codecov](https://codecov.io/github/JesseBowling/ipgrep/graph/badge.svg?token=X35E7AM44Q)](https://codecov.io/github/JesseBowling/ipgrep)

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

### Using pipx (recommended for system-wide installation)
Download the latest release from [GitHub](https://github.com/JesseBowling/ipgrep/releases) and install:
```bash
pipx install ipgrep-0.1.1-py3-none-any.whl
```

### Using uv (recommended for local development)

```bash
git clone https://github.com/JesseBowling/ipgrep.git
cd ipgrep
uv sync
```

### Development Installation

```bash
uv sync --all-extras
```

## Building a Distributable Package

To create a package that can be installed on a fresh machine:

### Build the Package
Update the version specification in `pyproject.toml`

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
pipx install ipgrep-0.1.0-py3-none-any.whl
```

**Using the source distribution:**
```bash
pipx install ipgrep-0.1.0.tar.gz
```

**Direct from the dist directory:**
```bash
pipx install dist/ipgrep-0.1.0-py3-none-any.whl
```

After installation, the `ipgrep` command will be available system-wide:
```bash
ipgrep --help
```

### Verifying the Installation

Test that the package works correctly:
```bash
# echo "Test: 192.168.1.1" | ipgrep
192.168.1.1

# echo "IPs: 192.168.1.1, 8.8.8.8" | ipgrep -e ipaddress
ip,classification
192.168.1.1,private
8.8.8.8,global
```

## Quick Start

### Basic Usage

Extract IP addresses from stdin:
```bash
# cat logfile.txt | ipgrep
192.168.1.1
10.0.0.1
```

Extract from a file:
```bash
ipgrep -f logfile.txt
```

### CIDR Notation

Extract with CIDR notation (adds /32 or /128 for host IPs):
```bash
# ipgrep -c -f network_config.txt
192.168.1.0/24
192.168.1.1/32
2001:db8::/32
```

### Defanged IP Addresses

Extract defanged IP addresses commonly shared in threat intelligence. The `-g` (greedy) flag handles various defanging patterns:

**Supported defanging patterns:**
- Square brackets: `192[.]168[.]1[.]1`
- Parentheses: `192(.)168(.)1(.)1`
- Text replacements: `192[dot]168[dot]1[dot]1` or `192[DOT]168[DOT]1[DOT]1`
- Mixed patterns: `192.168[.]1[.]1`

```bash
# echo "Malicious IP: 192[.]168[.]1[.]100" | ipgrep -g
192.168.1.100

# echo "IOC: 10[dot]0[dot]0[dot]1" | ipgrep -g
10.0.0.1

# Can combine with other options
# echo "Threat: 8[.]8[.]8[.]8" | ipgrep -g -e asn_origin
ip,asn_origin_as_name,asn_origin_asn,asn_origin_prefix
8.8.8.8,Google LLC,15169,8.8.8.0/24
```

### Enrichment

Enrich IPs with classification data (defaults to CSV output):
```bash
# ipgrep -e ipaddress -f logfile.txt
ip,classification
192.168.1.1,private
10.0.0.1,private
8.8.8.8,global
```

View classification with JSON output:
```bash
# ipgrep -e ipaddress -o json -f logfile.txt
[{"ip": "192.168.1.1", "classification": "private"}, {"ip": "10.0.0.1", "classification": "private"}, {"ip": "8.8.8.8", "classification": "global"}]
```

### Output Formats

**CSV output (default when using enrichments):**
```bash
# ipgrep -e ipaddress -f logfile.txt
ip,classification
192.168.1.1,private
8.8.8.8,global
```

**Space-delimited output:**
```bash
# ipgrep -e ipaddress -o space -f logfile.txt
192.168.1.1 private
8.8.8.8 global
```

**Pipe-delimited output:**
```bash
# ipgrep -e ipaddress -o pipe -f logfile.txt
192.168.1.1|private
8.8.8.8|global
```

**Plain output (default when no enrichments):**
```bash
# ipgrep -f logfile.txt
192.168.1.1
8.8.8.8
```

### Chaining Enrichments

Chain multiple enrichments together (outputs CSV by default):
```bash
# ipgrep -e ipaddress -e asn_origin -f logfile.txt
ip,classification,asn_origin_as_name,asn_origin_asn,asn_origin_prefix
8.8.8.8,global,Google LLC,15169,8.8.8.0/24
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

- **asn_origin**: Lookup origin ASN information for an IP
- **asn_peer**: Query peer ASN relationships
- **asn_prefix**: Query prefix information (automatically calls asn_origin first)

### Features

- **Bulk lookups**: Automatically batches IPs for efficient API requests (10 IPs per request)
- **Rate limiting**: Respects Shadowserver's 10 IPs/request limit with 1-second delays between batches
- **Retry logic**: Exponential backoff retry (0.5s, 1s, 2s, 4s) with 10-second max timeout
- **IPv6 support**: Full support for both IPv4 and IPv6 addresses
- **CIDR handling**: Uses first host IP when CIDR notation is present
- **Field prefixing**: All fields are prefixed with plugin name to avoid conflicts

### Origin Enrichment

Queries origin ASN information for an IP address.

**Output fields:**
- `asn_origin_asn` - Origin ASN number
- `asn_origin_as_name` - AS name/organization
- `asn_origin_prefix` - Network prefix
- `asn_origin_error` - Error indicator if lookup fails

**Example usage (CSV, default):**
```bash
# echo "8.8.8.8" | ipgrep -e asn_origin
ip,asn_origin_as_name,asn_origin_asn,asn_origin_prefix
8.8.8.8,Google LLC,15169,8.8.8.0/24
```

**Example output (JSON):**
```bash
# echo "8.8.8.8" | ipgrep -e asn_origin -o json
[{"ip": "8.8.8.8", "asn_origin_asn": "15169", "asn_origin_as_name": "Google LLC", "asn_origin_prefix": "8.8.8.0/24"}]
```

### Peer Enrichment

Queries peer ASN relationships for an IP address.

**Output fields:**
- `asn_peer_asn` - Origin ASN for this IP
- `asn_peer_asn_name` - Origin AS name
- `asn_peer_prefix` - Network prefix
- `asn_peer_asns` - Pipe-delimited list of peer ASN numbers
- `asn_peer_count` - Number of peers
- `asn_peer_error` - Error indicator if lookup fails

**Example usage (CSV, default):**
```bash
# echo "8.8.8.8" | ipgrep -e asn_peer
ip,asn_peer_asn,asn_peer_asn_name,asn_peer_asns,asn_peer_count,asn_peer_prefix
8.8.8.8,15169,Google LLC,1101|8220|29075|30781|37989|38195|47605|51088|60733,9,8.8.8.0/24
```

**Example output (JSON):**
```bash
# echo "8.8.8.8" | ipgrep -e asn_peer -o json
[{"ip": "8.8.8.8", "asn_peer_asn": "15169", "asn_peer_asn_name": "Google LLC", "asn_peer_asns": "1101|8220|29075|30781|37989|38195|47605|51088|60733", "asn_peer_count": "9", "asn_peer_prefix": "8.8.8.0/24"}]
```

### Prefix Enrichment

Queries prefix information for an ASN. This plugin automatically calls the asn_origin plugin first to determine the ASN, then queries prefix data for that ASN.

**Output fields:**
- All `asn_origin_*` fields from the origin lookup (asn, as_name, prefix)
- `asn_prefix_list` - Pipe-delimited list of prefixes for the ASN
- `asn_prefix_count` - Number of prefixes
- `asn_prefix_error` - Error indicator if lookup fails

**Example usage (CSV, default):**
```bash
# echo "8.8.8.8" | ipgrep -e asn_prefix
ip,asn_origin_as_name,asn_origin_asn,asn_origin_prefix,asn_prefix_count,asn_prefix_list
8.8.8.8,Google LLC,15169,8.8.8.0/24,983,209.85.147.0/24|209.85.128.0/17|216.239.32.0/24|...
```

**Example output (JSON, truncated):**
```bash
# echo "8.8.8.8" | ipgrep -e asn_prefix -o json
[{"ip": "8.8.8.8", "asn_origin_asn": "15169", "asn_origin_as_name": "Google LLC", "asn_origin_prefix": "8.8.8.0/24", "asn_prefix_list": "209.85.147.0/24|209.85.128.0/17|216.239.32.0/24|...", "asn_prefix_count": "983"}]
```

### Chaining ASN Enrichments

You can chain multiple ASN enrichments together with other enrichments (defaults to CSV output):

```bash
# Combine origin and peer information
# echo "8.8.8.8 1.1.1.1" | ipgrep -e asn_origin -e asn_peer
ip,asn_origin_as_name,asn_origin_asn,asn_origin_prefix,asn_peer_asn,asn_peer_asn_name,asn_peer_asns,asn_peer_count,asn_peer_prefix
8.8.8.8,Google LLC,15169,8.8.8.0/24,15169,Google LLC,1101|8220|29075|...,9,8.8.8.0/24
1.1.1.1,Cloudflare Inc,13335,1.1.1.0/24,13335,Cloudflare Inc,174|3257|3356|...,12,1.1.1.0/24

# Combine IP classification with ASN data
# echo "8.8.8.8" | ipgrep -e ipaddress -e asn_origin
ip,classification,asn_origin_as_name,asn_origin_asn,asn_origin_prefix
8.8.8.8,global,Google LLC,15169,8.8.8.0/24

# Get complete ASN data including prefixes (asn_prefix automatically includes asn_origin data)
# echo "8.8.8.8" | ipgrep -e asn_prefix
ip,asn_origin_as_name,asn_origin_asn,asn_origin_prefix,asn_prefix_count,asn_prefix_list
8.8.8.8,Google LLC,15169,8.8.8.0/24,983,209.85.147.0/24|209.85.128.0/17|<SNIP>
```

### ASN Enrichment with CIDR

When using CIDR notation, ASN enrichment uses only the first host IP:

```bash
echo "8.8.8.0/24" | ipgrep -c -e asn_origin
# Output:
# ip,cidr,asn_origin_as_name,asn_origin_asn,asn_origin_prefix
# 8.8.8.0,24,Google LLC,15169,8.8.8.0/24
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

## IPInfo Enrichment

The `ipinfo` enrichment plugin uses the [ipinfo-db Python library](https://github.com/ipinfo/python-db) to provide comprehensive IP geolocation, ASN, and organization data.

### Features

- **Automatic database management**: Downloads and caches IPInfo database locally via ipinfo-db library
- **Smart updates**: Automatically refreshes database if older than 1 day
- **Comprehensive data**: Returns all available IP details including geolocation, ASN, organization, and more
- **IPv4 and IPv6 support**: Full support for both address types
- **Field prefixing**: All fields prefixed with "ipinfo" to avoid conflicts

### Setup

The plugin requires an IPInfo.io access token, which can be obtained for free at [IPInfo.io](https://ipinfo.io/signup).

**Set the environment variable:**
```bash
export IPINFO_ACCESS_TOKEN="your_token_here"
```

**Verify the plugin is available:**
```bash
ipgrep --list-enrichments
```

### Usage

The plugin automatically downloads the IPInfo database on first use. The database is checked for freshness on each initialization, and if it's older than 1 day, a fresh copy is automatically downloaded.

**Basic usage (CSV, default):**
```bash
# echo "8.8.8.8" | ipgrep -e ipinfo
ip,ipinfo_country,ipinfo_country_name,ipinfo_continent,ipinfo_continent_name,ipinfo_asn,ipinfo_as_name,ipinfo_as_domain
8.8.8.8,US,United States,NA,North America,AS15169,Google LLC,google.com
```

**JSON output:**
```bash
# echo "8.8.8.8" | ipgrep -e ipinfo -o json
[{"ip": "8.8.8.8", "ipinfo_country": "US", "ipinfo_country_name": "United States", "ipinfo_continent": "NA", "ipinfo_continent_name": "North America", "ipinfo_asn": "AS15169", "ipinfo_as_name": "Google LLC", "ipinfo_as_domain": "google.com"}]
```

**Combine with other enrichments:**
```bash
# echo "8.8.8.8" | ipgrep -e ipaddress -e ipinfo
ip,classification,ipinfo_country,ipinfo_country_name,ipinfo_asn,ipinfo_as_name
8.8.8.8,global,US,United States,AS15169,Google LLC
```

### Output Fields

The plugin returns all available fields from the IPInfo database using the `getDetails()` method. Available fields depend on the IPInfo database tier, but typically include:

- `ipinfo_country` - Two-letter country code
- `ipinfo_country_name` - Full country name
- `ipinfo_continent` - Two-letter continent code
- `ipinfo_continent_name` - Full continent name
- `ipinfo_asn` - Autonomous System Number (e.g., AS15169)
- `ipinfo_as_name` - ASN organization name
- `ipinfo_as_domain` - ASN domain
- `ipinfo_error` - Error indicator if lookup fails

Additional fields may be available depending on your IPInfo database subscription.

### Database Management

- **Automatic downloads**: Database is downloaded automatically on first use
- **Smart refresh**: Database is checked on each plugin initialization and refreshed if older than 1 day
- **Location**: Managed by ipinfo-db library (typically in user cache directory)
- **Manual refresh**: Database will be automatically refreshed on next use after 1 day

### Error Handling

If the `IPINFO_ACCESS_TOKEN` environment variable is not set, the plugin will log an error and fail to initialize:

```
ERROR: IPINFO_ACCESS_TOKEN environment variable is required but not set. Please set it to your IPInfo.io access token.
```

If IP lookup fails, an error field will be added to the output:
- `ipinfo_error: client_not_initialized` - Client failed to initialize
- `ipinfo_error: not_found` - No data found for this IP
- `ipinfo_error: lookup_failed` - Lookup operation failed

### Requirements

- IPInfo.io access token (free tier available at https://ipinfo.io/signup)
- `ipinfo-db` Python library (automatically installed as dependency)
- Internet connection for database downloads

For more information, see:
- [IPInfo.io Documentation](https://ipinfo.io/developers)
- [ipinfo-db Python Library](https://github.com/ipinfo/python-db)

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
- **Defanged IPs**: Use `-g` flag to handle defanged IPs commonly found in threat intelligence reports (e.g., `1[.]2[.]3[.]4`, `1[dot]2[dot]3[dot]4`)

## Development

### Running Tests
Some tests are rate-limited, so you may need to run test without the `ratelimit` marker to skip them:
```bash
uv run pytest -m "not ratelimit"
```

### With Coverage

```bash
uv run pytest -m "not ratelimit" --cov=ipgrep --cov-report=html
```

### Code Formatting

```bash
uv run black src tests
```

## Project Structure

```
ipgrep/
        src/
            ipgrep/
                __init__.py
                cli.py                 # CLI interface
                core.py                # Core processing pipeline
                extractor.py           # IP/CIDR extraction logic
                plugins/
                base.py            # Base plugin classes
                    enrichment/
                        ipaddress_enrichment.py
                        asn_base.py            # Base ASN plugin
                        asn_origin.py          # Origin ASN enrichment
                        asn_peer.py            # Peer ASN enrichment
                        asn_prefix.py          # Prefix ASN enrichment
                        ipinfo.py              # IPInfo enrichment
                    output/
                        plain.py
                        csv.py
                        json.py
                        space_delimited.py
                        pipe_delimited.py
    tests/
        test_asn_enrichment.py
        test_core.py
        test_enrichment.py
        test_extractor.py
        test_output.py
pyproject.toml
README.md
```

## Requirements

- Python 3.9+
- Standard library only for core functionality
- `requests` library for ASN enrichment plugins (optional)
- `ipinfo-db` library for IPInfo enrichment plugin (optional)

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

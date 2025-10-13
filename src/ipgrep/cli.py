"""Command line interface for ipgrep."""

import argparse
import sys
from ipgrep.core import IPGrepPipeline
from ipgrep.plugins.base import PluginManager


def main():
    """Main entry point for the ipgrep CLI."""
    parser = argparse.ArgumentParser(
        description="Extract and enrich IP addresses from text",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract IPs from stdin
  cat logfile.txt | ipgrep

  # Extract IPs from file
  ipgrep -f logfile.txt

  # Extract IPs with CIDR notation
  ipgrep -c -f logfile.txt

  # Extract defanged IPs
  ipgrep -g -f threat_intel.txt

  # Enrich with ipaddress classification (defaults to CSV output)
  ipgrep -e ipaddress -f logfile.txt

  # Chain multiple enrichments (defaults to CSV output)
  ipgrep -e ipaddress -e origin -f logfile.txt

  # Output as JSON
  ipgrep -e ipaddress -o json -f logfile.txt

  # Output as space-delimited
  ipgrep -e origin -o space -f logfile.txt
        """,
    )

    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Input file to read from (default: stdin)",
    )

    parser.add_argument(
        "-c",
        "--cidr",
        action="store_true",
        help="Extract/default CIDR notation for IP addresses",
    )

    parser.add_argument(
        "-g",
        "--defang",
        action="store_true",
        help="Handle defanged IPs (e.g., 1[.]2[.]3[.]4 or 1[dot]2[dot]3[dot]4)",
    )

    parser.add_argument(
        "-e",
        "--enrich",
        action="append",
        dest="enrichments",
        help="Enrichment plugin(s) to apply (can be specified multiple times for chaining)",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Output format (default: plain, or csv when using enrichments)",
    )

    parser.add_argument(
        "--list-enrichments",
        action="store_true",
        help="List available enrichment plugins and exit",
    )

    parser.add_argument(
        "--list-outputs",
        action="store_true",
        help="List available output plugins and exit",
    )

    args = parser.parse_args()

    # Load plugins
    enrichment_plugins = PluginManager.load_enrichment_plugins()
    output_plugins = PluginManager.load_output_plugins()

    # Set output default based on whether enrichments are used
    if args.output is None:
        if args.enrichments:
            args.output = "csv"
        else:
            args.output = "plain"

    # Handle list commands
    if args.list_enrichments:
        print("Available enrichment plugins:")
        for name in sorted(enrichment_plugins.keys()):
            print(f"  {name}")
        sys.exit(0)

    if args.list_outputs:
        print("Available output plugins:")
        for name in sorted(output_plugins.keys()):
            print(f"  {name}")
        sys.exit(0)

    # Read input
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                text = f.read()
        except IOError as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Read from stdin
        text = sys.stdin.read()

    # Initialize enrichment plugins
    enrichments = []
    if args.enrichments:
        for enrich_name in args.enrichments:
            if enrich_name not in enrichment_plugins:
                print(
                    f"Error: Unknown enrichment plugin '{enrich_name}'",
                    file=sys.stderr,
                )
                print(
                    f"Available enrichments: {', '.join(sorted(enrichment_plugins.keys()))}",
                    file=sys.stderr,
                )
                sys.exit(1)
            enrichments.append(enrichment_plugins[enrich_name]())

    # Initialize output plugin
    if args.output not in output_plugins:
        print(f"Error: Unknown output format '{args.output}'", file=sys.stderr)
        print(
            f"Available formats: {', '.join(sorted(output_plugins.keys()))}",
            file=sys.stderr,
        )
        sys.exit(1)

    output_plugin = output_plugins[args.output]()

    # Create pipeline and process
    pipeline = IPGrepPipeline(
        extract_cidr=args.cidr,
        defang=args.defang,
        enrichments=enrichments,
        output_plugin=output_plugin,
    )

    result = pipeline.process(text)

    # Output result
    if result:
        print(result)


if __name__ == "__main__":
    main()

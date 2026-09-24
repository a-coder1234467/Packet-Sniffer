import argparse
import sys
from datetime import datetime

from scapy.all import conf, get_if_list, sniff, wrpcap


conf.use_pcap = True


def print_packet(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {packet.summary()}")


def main():
    parser = argparse.ArgumentParser(
        description="Capture packets from this Windows computer using Npcap."
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Npcap interface name. Omit to use the default interface.",
    )
    parser.add_argument(
        "-f",
        "--filter",
        default="ip or ip6",
        help='BPF filter, e.g. "tcp port 443" or "udp"',
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture. 0 means until Ctrl+C.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        help="Stop after this many seconds.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="capture.pcap",
        help="Output PCAP filename.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available Npcap interfaces and exit.",
    )
    args = parser.parse_args()

    if args.list_interfaces:
        print("Available interfaces:")
        for interface in get_if_list():
            print(f"  {interface}")
        return 0

    print("Starting capture.")
    print(f"Interface: {args.interface or 'default'}")
    print(f"Filter:    {args.filter}")
    print("Press Ctrl+C to stop.\n")

    packets = []

    try:
        packets = sniff(
            iface=args.interface,
            filter=args.filter,
            prn=print_packet,
            count=args.count,
            timeout=args.timeout,
            store=True,
        )
    except PermissionError:
        print(
            "Permission denied. Run PowerShell or Python as Administrator.",
            file=sys.stderr,
        )
        return 1
    except OSError as error:
        print(f"Capture failed: {error}", file=sys.stderr)
        print("Check that Npcap is installed and the interface name is valid.")
        return 1
    except KeyboardInterrupt:
        print("\nCapture stopped.")

    if packets:
        wrpcap(args.output, packets)
        print(f"\nSaved {len(packets)} packets to {args.output}")
    else:
        print("\nNo packets captured.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
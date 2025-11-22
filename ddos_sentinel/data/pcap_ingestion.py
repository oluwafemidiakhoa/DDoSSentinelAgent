"""
PCAP file ingestion for real network traffic.

Reads PCAP files and converts them to TrafficPacket format for analysis.
"""

from typing import List, Optional
from datetime import datetime
from pathlib import Path
import structlog

try:
    from scapy.all import rdpcap, Packet, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    structlog.get_logger(__name__).warning(
        "Scapy not installed. PCAP support unavailable. Install: pip install scapy"
    )

from ddos_sentinel.data.simulator import TrafficPacket

logger = structlog.get_logger(__name__)


class PCAPIngestion:
    """
    Ingest network traffic from PCAP files.

    Supports reading captured network traffic and converting to
    TrafficPacket format for analysis.
    """

    def __init__(self):
        """Initialize PCAP ingestion."""
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "Scapy is required for PCAP support. Install with: pip install scapy"
            )

    def read_pcap(
        self,
        filepath: str,
        max_packets: Optional[int] = None,
        filter_expression: Optional[str] = None
    ) -> List[TrafficPacket]:
        """
        Read packets from a PCAP file.

        Args:
            filepath: Path to PCAP file
            max_packets: Maximum number of packets to read (None = all)
            filter_expression: BPF filter (e.g., "tcp port 80")

        Returns:
            List of TrafficPacket objects

        Raises:
            FileNotFoundError: If PCAP file doesn't exist
            ValueError: If PCAP file is invalid
        """
        pcap_path = Path(filepath)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        logger.info("Reading PCAP file", filepath=filepath)

        try:
            # Read packets from PCAP
            scapy_packets = rdpcap(str(pcap_path))

            if max_packets:
                scapy_packets = scapy_packets[:max_packets]

            logger.info(
                "PCAP loaded",
                total_packets=len(scapy_packets),
                filepath=filepath
            )

            # Convert to TrafficPacket format
            traffic_packets = []
            for pkt in scapy_packets:
                traffic_pkt = self._convert_packet(pkt)
                if traffic_pkt:
                    traffic_packets.append(traffic_pkt)

            logger.info(
                "Packets converted",
                converted=len(traffic_packets),
                skipped=len(scapy_packets) - len(traffic_packets)
            )

            return traffic_packets

        except Exception as e:
            logger.error("Failed to read PCAP", error=str(e), filepath=filepath)
            raise ValueError(f"Invalid PCAP file: {e}")

    def _convert_packet(self, pkt: Packet) -> Optional[TrafficPacket]:
        """
        Convert Scapy packet to TrafficPacket.

        Args:
            pkt: Scapy packet

        Returns:
            TrafficPacket or None if packet cannot be converted
        """
        # Must have IP layer
        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]

        # Determine protocol
        protocol = "OTHER"
        source_port = 0
        dest_port = 0
        flags = []

        if pkt.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = pkt[TCP]
            source_port = tcp_layer.sport
            dest_port = tcp_layer.dport

            # Extract TCP flags
            if tcp_layer.flags:
                flag_map = {
                    'F': 'FIN',
                    'S': 'SYN',
                    'R': 'RST',
                    'P': 'PSH',
                    'A': 'ACK',
                    'U': 'URG',
                    'E': 'ECE',
                    'C': 'CWR'
                }
                flags = [flag_map.get(f, f) for f in str(tcp_layer.flags)]

        elif pkt.haslayer(UDP):
            protocol = "UDP"
            udp_layer = pkt[UDP]
            source_port = udp_layer.sport
            dest_port = udp_layer.dport

        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

        # Get timestamp (use packet time or current time)
        if hasattr(pkt, 'time'):
            timestamp = datetime.fromtimestamp(float(pkt.time))
        else:
            timestamp = datetime.now()

        # Get packet size
        packet_size = len(pkt)

        return TrafficPacket(
            timestamp=timestamp,
            source_ip=ip_layer.src,
            dest_ip=ip_layer.dst,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol,
            packet_size=packet_size,
            flags=flags
        )

    def get_pcap_stats(self, filepath: str) -> dict:
        """
        Get statistics about a PCAP file without loading all packets.

        Args:
            filepath: Path to PCAP file

        Returns:
            Dictionary with PCAP statistics
        """
        pcap_path = Path(filepath)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        # Quick stats without loading everything
        stats = {
            'filepath': str(pcap_path),
            'filesize_bytes': pcap_path.stat().st_size,
            'filesize_mb': pcap_path.stat().st_size / (1024 * 1024),
        }

        # Sample first 1000 packets for quick stats
        sample_packets = rdpcap(str(pcap_path), count=1000)
        stats['sample_size'] = len(sample_packets)

        # Protocol distribution in sample
        protocols = {}
        for pkt in sample_packets:
            if pkt.haslayer(TCP):
                protocols['TCP'] = protocols.get('TCP', 0) + 1
            elif pkt.haslayer(UDP):
                protocols['UDP'] = protocols.get('UDP', 0) + 1
            elif pkt.haslayer(ICMP):
                protocols['ICMP'] = protocols.get('ICMP', 0) + 1
            else:
                protocols['OTHER'] = protocols.get('OTHER', 0) + 1

        stats['protocol_distribution_sample'] = protocols

        return stats


class LiveCapture:
    """
    Capture live network traffic (requires root/admin privileges).

    Note: This is a placeholder for future live capture functionality.
    Requires elevated privileges and proper network interface configuration.
    """

    def __init__(self, interface: str = "eth0"):
        """
        Initialize live capture.

        Args:
            interface: Network interface to capture from
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy required for live capture")

        self.interface = interface
        logger.warning(
            "Live capture requires root/admin privileges",
            interface=interface
        )

    def start_capture(
        self,
        packet_callback,
        filter_expression: Optional[str] = None,
        packet_count: Optional[int] = None
    ):
        """
        Start capturing live traffic.

        Args:
            packet_callback: Function to call for each packet
            filter_expression: BPF filter
            packet_count: Stop after N packets (None = infinite)
        """
        from scapy.all import sniff

        logger.info(
            "Starting live capture",
            interface=self.interface,
            filter=filter_expression
        )

        def wrapped_callback(pkt):
            converter = PCAPIngestion()
            traffic_pkt = converter._convert_packet(pkt)
            if traffic_pkt:
                packet_callback(traffic_pkt)

        sniff(
            iface=self.interface,
            prn=wrapped_callback,
            filter=filter_expression,
            count=packet_count,
            store=False  # Don't store in memory
        )

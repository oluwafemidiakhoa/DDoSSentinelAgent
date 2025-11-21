"""
Traffic Simulator for DDoS Sentinel Agent.

Generates realistic network traffic patterns including normal baseline traffic
and Aisuru-like DDoS attack scenarios.
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import numpy as np
from enum import Enum


class TrafficType(Enum):
    """Types of network traffic patterns."""
    NORMAL = "normal"
    AISURU_DDOS = "aisuru_ddos"
    MIXED = "mixed"


@dataclass
class TrafficPacket:
    """Represents a network packet in our simulation."""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str  # TCP, UDP, ICMP
    packet_size: int  # bytes
    flags: List[str]  # TCP flags like SYN, ACK, etc.


@dataclass
class TrafficMetrics:
    """Aggregated traffic metrics over a time window."""
    timestamp: datetime
    total_packets: int
    total_bytes: int
    packets_per_second: float
    bytes_per_second: float
    unique_source_ips: int
    unique_dest_ips: int
    udp_ratio: float
    tcp_ratio: float
    avg_packet_size: float
    protocol_distribution: Dict[str, int]


class TrafficSimulator:
    """
    Simulates network traffic patterns for DDoS detection testing.

    Generates both normal baseline traffic and Aisuru-like DDoS attack patterns
    characterized by:
    - Massive UDP floods (95%+ UDP traffic)
    - Extremely high packets per second (100k-300k+ pps)
    - Large spikes in unique source IPs (botnet behavior)
    - Small packet sizes (typical amplification attacks)
    """

    def __init__(self, seed: Optional[int] = None):
        """
        Initialize the traffic simulator.

        Args:
            seed: Random seed for reproducibility
        """
        self.rng = np.random.default_rng(seed)
        self.packet_buffer: List[TrafficPacket] = []

    def generate_normal_traffic(
        self,
        duration_seconds: int = 60,
        base_pps: int = 1000,
        variance: float = 0.2
    ) -> List[TrafficPacket]:
        """
        Generate normal baseline network traffic.

        Args:
            duration_seconds: Duration of traffic to generate
            base_pps: Base packets per second rate
            variance: Variance in packet rate (0-1)

        Returns:
            List of simulated traffic packets
        """
        packets = []
        start_time = datetime.now()

        # Generate packets with normal distribution
        for second in range(duration_seconds):
            # Add variance to PPS
            pps = int(base_pps * (1 + self.rng.normal(0, variance)))
            pps = max(100, pps)  # Minimum threshold

            for _ in range(pps):
                timestamp = start_time + timedelta(
                    seconds=second,
                    microseconds=self.rng.integers(0, 1_000_000)
                )

                # Normal traffic: balanced protocols
                protocol = self.rng.choice(
                    ["TCP", "UDP", "ICMP"],
                    p=[0.7, 0.25, 0.05]  # Normal distribution
                )

                packet = TrafficPacket(
                    timestamp=timestamp,
                    source_ip=self._generate_normal_ip(),
                    dest_ip=self._generate_normal_ip(),
                    source_port=self.rng.integers(1024, 65535),
                    dest_port=self._generate_normal_port(protocol),
                    protocol=protocol,
                    packet_size=self._generate_normal_packet_size(protocol),
                    flags=self._generate_tcp_flags() if protocol == "TCP" else []
                )
                packets.append(packet)

        self.packet_buffer.extend(packets)
        return packets

    def generate_aisuru_ddos_traffic(
        self,
        duration_seconds: int = 60,
        attack_pps: int = 150000,
        botnet_size: int = 5000,
        target_ip: str = "192.168.1.100"
    ) -> List[TrafficPacket]:
        """
        Generate Aisuru-like DDoS attack traffic.

        Characteristics:
        - Massive UDP floods (95%+ UDP)
        - Extremely high PPS (100k-300k+)
        - Large number of unique source IPs (botnet)
        - Small packet sizes (amplification attacks)

        Args:
            duration_seconds: Duration of attack
            attack_pps: Packets per second during attack
            botnet_size: Number of unique attacking IPs
            target_ip: Target IP address

        Returns:
            List of attack traffic packets
        """
        packets = []
        start_time = datetime.now()

        # Generate botnet IPs
        botnet_ips = [self._generate_botnet_ip() for _ in range(botnet_size)]

        for second in range(duration_seconds):
            # Add some variance to attack intensity
            pps = int(attack_pps * (1 + self.rng.normal(0, 0.1)))

            for _ in range(pps):
                timestamp = start_time + timedelta(
                    seconds=second,
                    microseconds=self.rng.integers(0, 1_000_000)
                )

                # Aisuru characteristics: 95%+ UDP
                protocol = self.rng.choice(
                    ["UDP", "TCP", "ICMP"],
                    p=[0.96, 0.03, 0.01]
                )

                packet = TrafficPacket(
                    timestamp=timestamp,
                    source_ip=self.rng.choice(botnet_ips),
                    dest_ip=target_ip,
                    source_port=self.rng.integers(1024, 65535),
                    dest_port=self._generate_attack_port(),
                    protocol=protocol,
                    packet_size=self._generate_attack_packet_size(),
                    flags=[]
                )
                packets.append(packet)

        self.packet_buffer.extend(packets)
        return packets

    def generate_mixed_scenario(
        self,
        total_duration: int = 300,
        attack_start: int = 60,
        attack_duration: int = 120,
        normal_pps: int = 1000,
        attack_pps: int = 150000
    ) -> List[TrafficPacket]:
        """
        Generate a realistic scenario with normal traffic that transitions to DDoS.

        Args:
            total_duration: Total scenario duration in seconds
            attack_start: When attack starts (seconds)
            attack_duration: Duration of attack
            normal_pps: Normal traffic PPS
            attack_pps: Attack traffic PPS

        Returns:
            List of all traffic packets
        """
        packets = []

        # Phase 1: Normal traffic before attack
        print(f"Generating {attack_start}s of normal traffic...")
        normal_pre = self.generate_normal_traffic(
            duration_seconds=attack_start,
            base_pps=normal_pps
        )
        packets.extend(normal_pre)

        # Phase 2: DDoS attack
        print(f"Generating {attack_duration}s of DDoS attack traffic...")
        attack_traffic = self.generate_aisuru_ddos_traffic(
            duration_seconds=attack_duration,
            attack_pps=attack_pps
        )
        # Adjust timestamps
        attack_start_time = normal_pre[-1].timestamp + timedelta(seconds=1)
        for packet in attack_traffic:
            packet.timestamp = attack_start_time + (
                packet.timestamp - attack_traffic[0].timestamp
            )
        packets.extend(attack_traffic)

        # Phase 3: Recovery (normal traffic resumes)
        recovery_duration = total_duration - attack_start - attack_duration
        if recovery_duration > 0:
            print(f"Generating {recovery_duration}s of recovery traffic...")
            normal_post = self.generate_normal_traffic(
                duration_seconds=recovery_duration,
                base_pps=normal_pps
            )
            # Adjust timestamps
            recovery_start_time = attack_traffic[-1].timestamp + timedelta(seconds=1)
            for packet in normal_post:
                packet.timestamp = recovery_start_time + (
                    packet.timestamp - normal_post[0].timestamp
                )
            packets.extend(normal_post)

        self.packet_buffer = packets
        return packets

    def _generate_normal_ip(self) -> str:
        """Generate a realistic IP from normal network ranges."""
        network = self.rng.choice([
            "192.168",
            "10.0",
            "172.16"
        ])
        return f"{network}.{self.rng.integers(0, 255)}.{self.rng.integers(1, 254)}"

    def _generate_botnet_ip(self) -> str:
        """Generate diverse IPs representing a global botnet."""
        return f"{self.rng.integers(1, 223)}.{self.rng.integers(0, 255)}." \
               f"{self.rng.integers(0, 255)}.{self.rng.integers(1, 254)}"

    def _generate_normal_port(self, protocol: str) -> int:
        """Generate typical destination ports for normal traffic."""
        if protocol == "TCP":
            # Common TCP services
            common_ports = [80, 443, 22, 21, 25, 110, 143, 3306, 5432, 8080]
            if self.rng.random() < 0.7:
                return self.rng.choice(common_ports)
        elif protocol == "UDP":
            # Common UDP services
            common_ports = [53, 123, 161, 500, 4500]
            if self.rng.random() < 0.6:
                return self.rng.choice(common_ports)

        return self.rng.integers(1024, 65535)

    def _generate_attack_port(self) -> int:
        """Generate ports typical in DDoS attacks."""
        # Common DDoS target ports
        attack_ports = [80, 443, 53, 123, 8080]
        if self.rng.random() < 0.8:
            return self.rng.choice(attack_ports)
        return self.rng.integers(1, 1024)

    def _generate_normal_packet_size(self, protocol: str) -> int:
        """Generate realistic packet sizes for normal traffic."""
        if protocol == "TCP":
            # TCP packets tend to be larger (web, file transfer)
            return int(self.rng.lognormal(7.5, 1.5))  # Mean ~1800 bytes
        elif protocol == "UDP":
            # UDP more varied
            return int(self.rng.lognormal(6.0, 1.0))  # Mean ~400 bytes
        else:  # ICMP
            return self.rng.integers(64, 512)

    def _generate_attack_packet_size(self) -> int:
        """Generate small packet sizes typical of amplification attacks."""
        # Aisuru attacks typically use small packets for max PPS
        return self.rng.integers(64, 256)

    def _generate_tcp_flags(self) -> List[str]:
        """Generate realistic TCP flags."""
        # Normal TCP flag distributions
        flag_sets = [
            ["SYN"],
            ["SYN", "ACK"],
            ["ACK"],
            ["PSH", "ACK"],
            ["FIN", "ACK"],
            ["RST"],
        ]
        return self.rng.choice(flag_sets).copy()

    def clear_buffer(self) -> None:
        """Clear the packet buffer."""
        self.packet_buffer = []

#!/usr/bin/env python3
"""
DOS Attack Detector - Kali Linux / Debian
A Blue Team defensive tool for detecting Denial of Service attacks
Optimized for Linux systems
"""

import sys
import time
import os
from scapy.all import sniff, IP, TCP, ICMP, get_if_list, conf
from collections import defaultdict, deque
from datetime import datetime
import threading

class DOSDetector:
    """
    DOS Detection Engine - Monitors network traffic for attack patterns
    """
    
    def __init__(self, interface=None):
        """
        Initialize detector with configurable thresholds
        
        Args:
            interface: Network interface (eth0, wlan0, lo, etc.)
        """
        # Auto-detect interface if not provided
        self.interface = interface if interface else self.detect_interface()
        
        # Detection thresholds (tune these for your network)
        self.SYN_THRESHOLD = 100      # SYN packets from single IP
        self.PACKET_THRESHOLD = 200   # Total packets per second from single IP
        self.TIME_WINDOW = 10         # Time window in seconds
        
        # Tracking data structures
        self.syn_count = defaultdict(int)
        self.packet_count = defaultdict(int)
        self.timestamps = defaultdict(lambda: deque(maxlen=1000))
        
        # Statistics
        self.total_packets = 0
        self.alerts_triggered = 0
        self.start_time = time.time()
        
        # Display banner
        self.print_banner()
    
    def detect_interface(self):
        """
        Auto-detect active network interface
        
        Returns:
            str: Interface name
        """
        interfaces = get_if_list()
        
        # Prefer common interfaces
        for iface in ['eth0', 'wlan0', 'ens33', 'enp0s3', 'lo']:
            if iface in interfaces:
                return iface
        
        # Return first non-loopback interface
        for iface in interfaces:
            if iface != 'lo':
                return iface
        
        # Fallback to loopback
        return 'lo'
    
    def print_banner(self):
        """Display startup banner"""
        print("=" * 70)
        print("🛡️  DOS ATTACK DETECTOR - BLUE TEAM DEFENSIVE TOOL")
        print("=" * 70)
        print(f"Interface:          {self.interface}")
        print(f"SYN Threshold:      {self.SYN_THRESHOLD} packets")
        print(f"Packet Threshold:   {self.PACKET_THRESHOLD} packets/sec")
        print(f"Time Window:        {self.TIME_WINDOW} seconds")
        print("=" * 70)
        print()
    
    def packet_handler(self, packet):
        """
        Analyze each captured packet
        
        Args:
            packet: Scapy packet object
        """
        self.total_packets += 1
        
        # Only process IP packets
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        current_time = time.time()
        
        # Record packet timestamp
        self.timestamps[src_ip].append(current_time)
        self.packet_count[src_ip] += 1
        
        # Detect SYN packets (SYN flood detection)
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            # Check if SYN flag is set but ACK is not (SYN without ACK)
            if tcp.flags & 0x02 and not tcp.flags & 0x10:
                self.syn_count[src_ip] += 1
                
                # Debug output every 10 SYN packets
                if self.syn_count[src_ip] % 10 == 0:
                    print(f"[DEBUG] SYN count from {src_ip}: {self.syn_count[src_ip]}")
        
        # Analyze traffic patterns
        self.analyze_traffic(src_ip, current_time)
    
    def analyze_traffic(self, src_ip, current_time):
        """
        Analyze traffic patterns and detect attacks
        
        Args:
            src_ip: Source IP address
            current_time: Current timestamp
        """
        # Clean old timestamps outside time window
        timestamps = self.timestamps[src_ip]
        while timestamps and timestamps[0] < current_time - self.TIME_WINDOW:
            timestamps.popleft()
        
        # Calculate packet rate
        packets_in_window = len(timestamps)
        packets_per_second = packets_in_window / self.TIME_WINDOW
        
        # Get current SYN count
        syn_count = self.syn_count[src_ip]
        
        # Detection: SYN Flood
        if syn_count >= self.SYN_THRESHOLD:
            self.trigger_alert("SYN_FLOOD", src_ip, syn_count)
            self.syn_count[src_ip] = 0  # Reset after alert
        
        # Detection: High Traffic Volume
        if packets_per_second >= self.PACKET_THRESHOLD:
            self.trigger_alert("HIGH_TRAFFIC", src_ip, int(packets_per_second))
    
    def trigger_alert(self, alert_type, src_ip, count):
        """
        Trigger DOS attack alert
        
        Args:
            alert_type: Type of attack (SYN_FLOOD, HIGH_TRAFFIC)
            src_ip: Attacker IP address
            count: Packet/event count
        """
        self.alerts_triggered += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print()
        print("=" * 70)
        if alert_type == "SYN_FLOOD":
            print(f"🚨 ALERT: SYN FLOOD DETECTED!")
            print(f"Timestamp:   {timestamp}")
            print(f"Source IP:   {src_ip}")
            print(f"SYN Count:   {count} packets (Threshold: {self.SYN_THRESHOLD})")
        elif alert_type == "HIGH_TRAFFIC":
            print(f"🚨 ALERT: HIGH TRAFFIC VOLUME DETECTED!")
            print(f"Timestamp:   {timestamp}")
            print(f"Source IP:   {src_ip}")
            print(f"Rate:        {count} packets/sec (Threshold: {self.PACKET_THRESHOLD})")
        print("=" * 70)
        print()
    
    def display_status(self):
        """Display periodic status updates"""
        while True:
            time.sleep(5)
            
            # Calculate statistics
            total_syn = sum(self.syn_count.values())
            active_ips = len([ip for ip, count in self.packet_count.items() if count > 0])
            uptime = int(time.time() - self.start_time)
            
            print(f"[OK] Traffic Normal | SYN: {total_syn} | "
                  f"Active IPs: {active_ips} | "
                  f"Packets: {self.total_packets} | "
                  f"Uptime: {uptime}s")
    
    def start(self):
        """Start packet capture and monitoring"""
        print("Monitoring for high SYN_RECV states...")
        print("Press Ctrl+C to stop monitoring")
        print()
        
        # Start status display thread
        status_thread = threading.Thread(target=self.display_status, daemon=True)
        status_thread.start()
        
        try:
            # Start packet capture
            print("📡 Capturing packets...")
            print()
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                filter="tcp or icmp",  # Only capture TCP and ICMP
                store=False            # Don't store packets in memory
            )
        except KeyboardInterrupt:
            self.print_summary()
            sys.exit(0)
        except PermissionError:
            print("\n❌ ERROR: Permission denied!")
            print("   Run with: sudo python3 monitor.py")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ ERROR: {e}")
            sys.exit(1)
    
    def print_summary(self):
        """Print final statistics"""
        uptime = int(time.time() - self.start_time)
        
        print("\n\n" + "=" * 70)
        print("🛑 MONITORING STOPPED")
        print("=" * 70)
        print(f"Total Packets Analyzed:  {self.total_packets}")
        print(f"Alerts Triggered:        {self.alerts_triggered}")
        print(f"Total Uptime:            {uptime} seconds")
        print(f"Packets per Second:      {self.total_packets / uptime if uptime > 0 else 0:.2f}")
        print("=" * 70)


def check_root():
    """Check if script is running with root privileges"""
    if os.geteuid() != 0:
        print("❌ ERROR: This script requires root privileges")
        print("   Run with: sudo python3 monitor.py [interface]")
        sys.exit(1)


def main():
    """Main entry point"""
    # Check root privileges
    check_root()
    
    # Get interface from command line or auto-detect
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    
    # Create and start detector
    detector = DOSDetector(interface=interface)
    detector.start()


if __name__ == "__main__":
    main()

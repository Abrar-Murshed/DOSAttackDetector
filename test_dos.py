#!/usr/bin/env python3
"""
DOS Attack Simulator - For Testing Only
Use this to test the DOS detector in a controlled environment
"""

import sys
import time
import os
from scapy.all import IP, TCP, send, RandShort


def check_root():
    """Check if running with root privileges"""
    if os.geteuid() != 0:
        print("❌ ERROR: This script requires root privileges")
        print("   Run with: sudo python3 test.py <target_ip>")
        sys.exit(1)


def print_banner():
    """Display banner"""
    print("=" * 70)
    print("⚠️  DOS ATTACK SIMULATOR - TESTING ONLY")
    print("=" * 70)
    print("WARNING: Only use on networks you own or have permission to test!")
    print("=" * 70)
    print()


def syn_flood_test(target_ip, count=150):
    """
    Test SYN flood detection
    
    Args:
        target_ip: Target IP address
        count: Number of SYN packets to send
    """
    print(f"[TEST 1] SYN Flood Attack Simulation")
    print(f"Target: {target_ip}")
    print(f"Packets: {count} SYN packets")
    print()
    
    print("Sending SYN packets...")
    start_time = time.time()
    
    for i in range(count):
        # Create SYN packet (flags="S")
        packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=80, flags="S")
        send(packet, verbose=False)
        
        # Small delay for reliable detection
        time.sleep(0.05)  # 20 packets/second
        
        # Progress indicator
        if (i + 1) % 25 == 0:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed
            print(f"  Sent {i + 1}/{count} packets ({rate:.1f} pkt/sec)")
    
    duration = time.time() - start_time
    print()
    print(f"✓ SYN flood test complete!")
    print(f"  Duration: {duration:.2f} seconds")
    print(f"  Average rate: {count/duration:.1f} packets/sec")
    print()


def high_traffic_test(target_ip, count=250):
    """
    Test high traffic detection
    
    Args:
        target_ip: Target IP address
        count: Number of packets to send
    """
    print(f"[TEST 2] High Traffic Volume Simulation")
    print(f"Target: {target_ip}")
    print(f"Packets: {count} TCP packets")
    print()
    
    print("Sending high volume traffic...")
    start_time = time.time()
    
    for i in range(count):
        # Create ACK packet (flags="A")
        packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=80, flags="A")
        send(packet, verbose=False)
        
        time.sleep(0.01)  # 100 packets/second
        
        if (i + 1) % 50 == 0:
            print(f"  Sent {i + 1}/{count} packets...")
    
    duration = time.time() - start_time
    print()
    print(f"✓ High traffic test complete!")
    print(f"  Duration: {duration:.2f} seconds")
    print(f"  Average rate: {count/duration:.1f} packets/sec")
    print()


def normal_traffic_test(target_ip, count=40):
    """
    Test normal traffic (should NOT trigger alerts)
    
    Args:
        target_ip: Target IP address
        count: Number of packets to send
    """
    print(f"[TEST 3] Normal Traffic Simulation")
    print(f"Target: {target_ip}")
    print(f"Packets: {count} TCP packets")
    print(f"Expected: NO alerts should trigger")
    print()
    
    print("Sending normal traffic...")
    
    for i in range(count):
        packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=80, flags="A")
        send(packet, verbose=False)
        
        time.sleep(0.2)  # 5 packets/second (normal rate)
        
        if (i + 1) % 10 == 0:
            print(f"  Sent {i + 1}/{count} packets...")
    
    print()
    print(f"✓ Normal traffic test complete!")
    print(f"  No alerts should have been triggered")
    print()


def burst_attack_test(target_ip, bursts=4, burst_size=30):
    """
    Test burst attack pattern
    
    Args:
        target_ip: Target IP address
        bursts: Number of bursts
        burst_size: Packets per burst
    """
    print(f"[TEST 4] Burst Attack Simulation")
    print(f"Target: {target_ip}")
    print(f"Bursts: {bursts} bursts of {burst_size} packets")
    print()
    
    total = bursts * burst_size
    sent = 0
    
    for burst_num in range(bursts):
        print(f"Burst {burst_num + 1}/{bursts}: Sending {burst_size} SYN packets...")
        
        for i in range(burst_size):
            packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=80, flags="S")
            send(packet, verbose=False)
            sent += 1
        
        print(f"  Sent {sent}/{total} packets total")
        
        if burst_num < bursts - 1:
            print(f"  Waiting 2 seconds...")
            time.sleep(2)
    
    print()
    print(f"✓ Burst attack test complete!")
    print()


def main():
    """Main entry point"""
    check_root()
    print_banner()
    
    # Check arguments
    if len(sys.argv) != 2:
        print("Usage: sudo python3 test.py <target_ip>")
        print("Example: sudo python3 test.py 127.0.0.1")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    
    print(f"Target IP: {target_ip}")
    print()
    print("⚠️  Make sure the detector is running in another terminal!")
    print()
    print("=" * 70)
    print()
    print("Select test to run:")
    print()
    print("1. SYN Flood Test (150 packets) - SHOULD trigger alert")
    print("2. High Traffic Test (250 packets) - SHOULD trigger alert")
    print("3. Normal Traffic Test (40 packets) - Should NOT trigger alert")
    print("4. Burst Attack Test (4 bursts) - SHOULD trigger alert")
    print("5. Run All Tests (with delays)")
    print()
    
    choice = input("Enter choice (1-5): ").strip()
    print()
    print("=" * 70)
    print()
    
    if choice == "1":
        syn_flood_test(target_ip)
    elif choice == "2":
        high_traffic_test(target_ip)
    elif choice == "3":
        normal_traffic_test(target_ip)
    elif choice == "4":
        burst_attack_test(target_ip)
    elif choice == "5":
        print("Running all tests with 10-second delays...\n")
        
        normal_traffic_test(target_ip)
        print("Waiting 10 seconds before next test...\n")
        time.sleep(10)
        
        syn_flood_test(target_ip)
        print("Waiting 10 seconds before next test...\n")
        time.sleep(10)
        
        high_traffic_test(target_ip)
        print("Waiting 10 seconds before next test...\n")
        time.sleep(10)
        
        burst_attack_test(target_ip)
    else:
        print("❌ Invalid choice!")
        sys.exit(1)
    
    print("=" * 70)
    print("🔍 Check the detector terminal for alerts!")
    print("=" * 70)


if __name__ == "__main__":
    main()

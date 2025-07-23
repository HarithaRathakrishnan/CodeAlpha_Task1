from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
def analyze_packet(packet):
    print("="*70)
    print(f"📦 Packet Captured at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        print(f"🔸 Source IP      : {src_ip}")
        print(f"🔸 Destination IP : {dst_ip}")
        protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, "Other")
        print(f"🔸 Protocol       : {proto} ({protocol_name})")

        # TCP Details
        if TCP in packet:
            tcp_layer = packet[TCP]
            print("   → TCP Segment")
            print(f"   - Source Port      : {tcp_layer.sport}")
            print(f"   - Destination Port : {tcp_layer.dport}")

        # UDP Details
        elif UDP in packet:
            udp_layer = packet[UDP]
            print("   → UDP Segment")
            print(f"   - Source Port      : {udp_layer.sport}")
            print(f"   - Destination Port : {udp_layer.dport}")

        # ICMP
        elif ICMP in packet:
            print("   → ICMP Packet")

        # Payload
        print("🔹 Payload:")
        try:
            payload = bytes(packet[IP].payload)
            decoded_payload = payload.decode("utf-8", errors="ignore")
            print(decoded_payload if decoded_payload.strip() else "[No readable payload]")
        except:
            print("[!] Failed to decode payload.")
print("🔍 Starting packet sniffing...\n(Please browse the internet or ping to generate traffic)")

# Only capture IP packets (filter avoids ARP and non-IP noise)
sniff(prn=analyze_packet, count=5, store=False, filter="ip")

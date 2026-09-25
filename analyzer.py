import pyshark
import sys
import os 
import asyncio
from collections import Counter, defaultdict
import json

def load_file(file_path):
    if not os.path.exists(file_path):
        print(f"[!] The file path {file_path} does not exist")
        sys.exit(1)


    print(f"The file path is {file_path}")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    capture = pyshark.FileCapture(file_path, eventloop=loop)

    packet_count = 0
    ip_packet_count = 0
    protocol_counts = {"TCP": 0, "UDP": 0, "UNKNOWN": 0}
    src_ip_counter = Counter()
    dst_ip_counter = Counter()
    ip_port_tracker = defaultdict(set)

    for packet in capture:
        packet_count += 1

        if "IP" in packet:
            ip_packet_count += 1
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            protocol = "UNKNOWN"
            src_port = "N/A"
            dst_port = "N/A"
            if "TCP" in packet:
                protocol = "TCP"
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
                
            else:
                protocol = "UDP"
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport

            if dst_port != "N/A":
                ip_port_tracker[src_ip].add(dst_port)

        
            
            
            protocol_counts[protocol] += 1
            src_ip_counter[src_ip] += 1
            dst_ip_counter[dst_ip] += 1
            #print(f"[{packet_count}] Protocol: {protocol} | {src_ip} : {src_port} -> {dst_ip} : {dst_port}")

    SCAN_THRESHOLD = 5
    alerts = []

    for ip , ports in ip_port_tracker.items():
                    if len(ports) > SCAN_THRESHOLD:
                        alerts.append({
                            "type": "Port Scan Detected",
                            "source_ip": ip,
                            "unique_ports_scanned": len(ports)
                        })
    if alerts:
            print("\n[!]SECURITY ALERTS:")
            for alert in alerts:
                print(f" [!]{alert["source_ip"]} performed a port scan across {alert["unique_ports_scanned"]} unique ports")
    else:
        print("\n[+] No port scanning activity detected")

    print(f"[+]Processing Complete. Total packets found: {packet_count}")
    print(f"[+]IP Packets found: {ip_packet_count}")
    print(f"[+]Protocol Sumamry:\n TCP: {protocol_counts["TCP"]}\n UDP: {protocol_counts["UDP"]}\n OTHERS: {protocol_counts["UNKNOWN"]}\n")
    print("\nTop Source IPs:")
    for ip, count in src_ip_counter.most_common(3):
        print(f"  - {ip}: {count} packets")

    print("\nTop Destination IPs:")
    for ip, count in dst_ip_counter.most_common(3):
        print(f"  - {ip}: {count} packets")

    report_analysis = {
        "total_packets" : packet_count,
        "ip_packets" : ip_packet_count,
        "protocol_summary" : protocol_counts,
        "top_source_ips" : dict(src_ip_counter.most_common(3)),
        "top_destination_ips" : dict(dst_ip_counter.most_common(3))
    }
    report_analysis["security_alerts"] = alerts
    capture.close()
    loop.close()
    export_to_json(report_analysis)

def export_to_json(data, filename="analysis_report.json"):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\n[+]Successfully exported report to {filename}")

if __name__ == "__main__":
    target_file = "sample.pcap"
    load_file(target_file)

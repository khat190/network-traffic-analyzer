# Network Traffic Analyzer

A Python-based network traffic analyzer that reads a PCAP file using PyShark and TShark, extracts packet information, summarizes the traffic, and performs a basic check for potential port-scanning activity.

I built this to understand what network traffic analysis looks like when it's implemented in Python. I was already familiar with inspecting traffic in Wireshark, but I wanted to understand how to extract the same kinds of information programmatically.

## Features

**Packet Analysis**

- Read and process PCAP files using PyShark
- Extract source and destination IP addresses
- Extract source and destination ports
- Identify TCP and UDP traffic

**Traffic Summary**

- Count IP addresses and protocols
- Display the top 3 source IPs
- Display the top 3 destination IPs
- Export analysis results to JSON

**Security Detection**

- Track unique destination ports for each source IP
- Detect potential port-scanning activity using a threshold-based rule

## How It Works

The analyzer processes the PCAP file packet by packet.

For each IP packet, it extracts the source IP, destination IP, protocol, and available port information. It then uses Python data structures to keep track of traffic statistics and unique destination ports.

The current port-scan rule is simple:

> If a source IP contacts more than 5 unique destination ports, it is flagged as a potential port scan.

Results are displayed in the terminal and saved to a JSON report.

## Technologies Used

- Python
- PyShark
- TShark
- JSON

The project uses `Counter`, `defaultdict`, `asyncio`, and PyShark for packet parsing.

## Requirements

- Python 3.x
- TShark
- PyShark

PyShark uses TShark underneath, so TShark must be installed and available on your system.

Install PyShark with:

```bash
pip install pyshark
```
Running the Analyzer

Rename your PCAP to sample.pcap, place it in the same directory as analyzer.py, then run:
```
python analyzer.py
```
The analyzer will process the PCAP and generate:
```
analysis_report.json
```
**Example Output**
For the test PCAP used during development, the analyzer processed 44 packets:
```
[+] Processing Complete. Total packets found: 44
[+] IP Packets found: 44

[+] Protocol Summary:
 TCP: 44
 UDP: 0
 OTHERS: 0

Top source and destination IPs:

Top Source IPs:
  - 172.16.5.1: 22 packets
  - 172.16.5.10: 22 packets

Top Destination IPs:
  - 172.16.5.10: 22 packets
  - 172.16.5.1: 22 packets
```
The test capture did not trigger the port-scan detection threshold.

## JSON Report

After processing the PCAP, the analyzer exports the results to analysis_report.json.

The report contains:

- Total number of packets
- Number of IP packets
- Protocol summary
- Top source IPs
- Top destination IPs
- Security alerts

The JSON is formatted with indentation for readability.

**Port Scan Detection**
The analyzer tracks unique destination ports for each source IP using:
```
ip_port_tracker = defaultdict(set)
```
The set ensures that repeatedly contacting the same port does not count as multiple unique ports.

The current threshold is:
```
SCAN_THRESHOLD = 5
```
After processing the packets, the analyzer checks how many unique destination ports each source IP contacted. If the number is greater than the threshold, a security alert is generated containing the source IP and the number of unique ports contacted.

## Future Improvements

- Add time-based detection windows for port scans
- Analyze TCP flags and connection behavior
- Track scans across multiple destination hosts
- Test against different types of PCAP files
- Add more security detection rules
- Add command-line arguments for choosing the PCAP file
- Improve reporting and visualization

## Project Structure
```
network-traffic-analyzer/
│
├── analyzer.py
├── requirements.txt
├── README.md
├── .gitignore
└── analysis_report.json
```
## Disclaimer

This project is intended for learning and experimentation with network traffic analysis. The port-scan detection is a basic heuristic and should not be treated as a complete intrusion detection system.

## Author

Khatija Fatima

Cybersecurity | Python | Network Analysis

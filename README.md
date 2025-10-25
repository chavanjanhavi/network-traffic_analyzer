# Network Traffic Analyzer

Python-based packet analysis tool to parse `.pcap` files and generate traffic insights:
- Protocol distribution (bytes & counts)
- Top talkers (by bytes & packets)
- Flow statistics (5-tuple flows, duration, bytes)
- DNS & HTTP extraction
- Basic anomaly heuristics and throughput plotting

## Features
- Uses `pyshark` (tshark) for PCAP parsing
- Aggregation and visualization via `pandas` and `matplotlib`
- Outputs CSV summaries and PNG charts

## Quickstart (local VM)
1. Install system dependency: `tshark` (Wireshark)
2. Create venv and install Python libs:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
3. Capture a PCAP on a machine you control:
sudo tshark -i eth0 -a duration:30 -w capture.pcap
4. Run:
python analyze_pcap.py capture.pcap
5. Outputs: `protocols.csv`, `flows.csv`, `top_talkers.csv`, `dns_queries.csv`, `http_requests.csv`, `time_series.csv` and PNG plots.

## License
MIT


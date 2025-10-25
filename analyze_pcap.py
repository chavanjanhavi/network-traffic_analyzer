
#!/usr/bin/env python3
# analyze_pcap.py
# Usage: python analyze_pcap.py capture.pcap
# Requires: pyshark, pandas, matplotlib, python-dateutil
# Note: make sure tshark is installed (pyshark shells out to tshark)

import pyshark
import sys
import pandas as pd
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt

PCAP = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"

print(f"Opening {PCAP} (streaming read, may take a while)...")
cap = pyshark.FileCapture(PCAP, keep_packets=False)

protocol_counts = defaultdict(int)
protocol_bytes = defaultdict(int)
flows = {}
dns_rows = []
http_rows = []
top_talkers = defaultdict(lambda: {"bytes":0, "packets":0})
time_series = []

def get_proto(pkt):
    try:
        return pkt.highest_layer
    except Exception:
        return getattr(pkt, 'transport_layer', 'UNKNOWN')

def flow_key(pkt):
    try:
        if hasattr(pkt, 'ip'):
            src = pkt.ip.src
            dst = pkt.ip.dst
        elif hasattr(pkt, 'ipv6'):
            src = pkt.ipv6.src
            dst = pkt.ipv6.dst
        else:
            return None
        proto = pkt.transport_layer or pkt.highest_layer or 'UNKNOWN'
        sport = ''
        dport = ''
        # attempt to safely get ports if transport layer present
        try:
            if pkt.transport_layer:
                layer_name = pkt.transport_layer.lower()
                sport = getattr(pkt[layer_name], 'srcport', '')
                dport = getattr(pkt[layer_name], 'dstport', '')
        except Exception:
            sport = ''
            dport = ''
        return (src, dst, sport, dport, proto)
    except Exception:
        return None

print("Parsing packets...")
for pkt in cap:
    try:
        ts = float(pkt.sniff_timestamp)
        length = int(getattr(pkt, 'length', 0) or 0)
        proto = get_proto(pkt)
        protocol_counts[proto] += 1
        protocol_bytes[proto] += length

        # IP-based stats
        if hasattr(pkt, 'ip'):
            src = pkt.ip.src
            dst = pkt.ip.dst
        elif hasattr(pkt, 'ipv6'):
            src = pkt.ipv6.src
            dst = pkt.ipv6.dst
        else:
            src = dst = None

        if src:
            top_talkers[src]['bytes'] += length
            top_talkers[src]['packets'] += 1

        # flows (5-tuple)
        k = flow_key(pkt)
        if k:
            if k not in flows:
                flows[k] = {"packets":0, "bytes":0, "start":ts, "end":ts}
            flows[k]["packets"] += 1
            flows[k]["bytes"] += length
            flows[k]["end"] = ts

        # DNS
        if 'DNS' in pkt:
            try:
                qname = getattr(pkt.dns, 'qry_name', '')
                qtype = getattr(pkt.dns, 'qry_type', '')
                dns_src = src or ''
                dns_rows.append((datetime.utcfromtimestamp(ts).isoformat(), dns_src, qname, qtype))
            except Exception:
                pass

        # HTTP
        if 'HTTP' in pkt:
            try:
                host = getattr(pkt.http, 'host', '')
                uri = getattr(pkt.http, 'request_uri', '')
                method = getattr(pkt.http, 'request_method', '')
                http_src = src or ''
                http_rows.append((datetime.utcfromtimestamp(ts).isoformat(), http_src, host, uri, method))
            except Exception:
                pass

        time_series.append((ts, length))
    except Exception:
        # skip packets that raise parse exceptions
        continue

print("Converting results to dataframes...")
protocol_df = pd.DataFrame([
    {"protocol": p, "count": c, "bytes": protocol_bytes[p]}
    for p, c in protocol_counts.items()
]).sort_values(by="bytes", ascending=False)

flows_df = pd.DataFrame([
    {"src": k[0], "dst": k[1], "sport": k[2], "dport": k[3], "proto": k[4],
     "packets": v["packets"], "bytes": v["bytes"],
     "start": datetime.utcfromtimestamp(v["start"]).isoformat(),
     "end": datetime.utcfromtimestamp(v["end"]).isoformat(),
     "duration_s": v["end"]-v["start"]}
    for k, v in flows.items()
]).sort_values(by="bytes", ascending=False)

talkers_df = pd.DataFrame([
    {"ip": ip, "bytes": stats["bytes"], "packets": stats["packets"]}
    for ip, stats in top_talkers.items()
]).sort_values(by="bytes", ascending=False)

dns_df = pd.DataFrame(dns_rows, columns=["timestamp","src","qname","qtype"])
http_df = pd.DataFrame(http_rows, columns=["timestamp","src","host","uri","method"])
time_series_df = pd.DataFrame(time_series, columns=["ts","bytes"])
time_series_df['ts_dt'] = pd.to_datetime(time_series_df['ts'], unit='s')

# Save CSVs
protocol_df.to_csv("protocols.csv", index=False)
flows_df.to_csv("flows.csv", index=False)
talkers_df.to_csv("top_talkers.csv", index=False)
dns_df.to_csv("dns_queries.csv", index=False)
http_df.to_csv("http_requests.csv", index=False)
time_series_df.to_csv("time_series.csv", index=False)

print("Saved CSVs: protocols.csv, flows.csv, top_talkers.csv, dns_queries.csv, http_requests.csv, time_series.csv")

# Basic plots
plt.figure(figsize=(10,5))
if not protocol_df.empty:
    protocol_df.head(10).plot(kind='bar', x='protocol', y='bytes', legend=False, title='Top Protocols by Bytes')
    plt.tight_layout()
    plt.savefig("protocols_by_bytes.png")
    plt.close()

if not talkers_df.empty:
    talkers_df.head(10).plot(kind='bar', x='ip', y='bytes', legend=False, title='Top Talkers by Bytes')
    plt.tight_layout()
    plt.savefig("top_talkers.png")
    plt.close()

# Throughput timeseries (bytes per second)
try:
    agg = time_series_df.set_index('ts_dt').resample('1S')['bytes'].sum().reset_index()
    agg.plot(x='ts_dt', y='bytes', kind='line', title='Bytes per second')
    plt.tight_layout()
    plt.savefig("throughput_timeseries.png")
    plt.close()
except Exception:
    pass

print("Generated plots: protocols_by_bytes.png, top_talkers.png, throughput_timeseries.png (if data present)")
print("Done.")


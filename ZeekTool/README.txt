Zeek Analysis Tools - Network Security PCAP Analyzer
This toolkit processes PCAP files using containerized Zeek to generate interactive HTML security dashboards. 
It automatically detects suspicious activities like executable downloads, unusual ports, self-signed certificates, 
and potential C2 traffic. The dashboard provides both high-level threat summaries and detailed log tables for malware 
analysis and incident response.

Run python3 zeekapp.py sample.pcap to analyze a PCAP file, or python3 zeekdash.py /path/to/logs/ to generate 
dashboards from existing Zeek logs. All files including raw logs and the HTML analysis report are saved in the 
output directory for further investigation.

Install script not yet tested.

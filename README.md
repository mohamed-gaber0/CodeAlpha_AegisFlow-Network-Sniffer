# AegisFlow DPI — Deep Packet Inspector & Threat Detection Engine

A professional-grade, multi-protocol deep packet inspector (DPI) and intrusion detection utility built in Python using **Scapy**. AegisFlow DPI captures, dissects, and audits network traffic across multiple protocol layers in real time. It features a sleek terminal interface, signature-based anomaly detection, payload extraction, hex dumps, and multi-format log archiving (including plaintext, structured JSON, and Wireshark-compatible PCAP files).

---

## 🚀 Key Security Features

*   **Multi-Protocol Deep Packet Inspection (DPI)**:
    *   **Ethernet Layer**: Dissect source and destination MAC structures.
    *   **IP Layer (IPv4 & IPv6)**: Audit TTL, IPv4/IPv6 headers, and layer boundaries.
    *   **ARP Protocol**: Map requests and responses with IP-to-MAC resolution.
    *   **TCP/UDP Protocols**: Map endpoints, trace sequence/acknowledgement lines, and monitor active flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
    *   **DNS Protocol**: Track domain queries, resource record types, and resolution payloads.
    *   **HTTP Protocol**: Extract cleartext HTTP request headers (Method, Host, Path) and response codes.
    *   **HTTPS/TLS Protocol**: Identify secure handshakes and cryptographic tunnel ports.
    *   **ICMP Protocol**: Catch diagnostic signals, unreachable hosts, and ping structures.
*   **Signature-Based Threat Alerts**:
    *   **Unencrypted Traffic Flags**: Triggers immediate alerts when vulnerable cleartext legacy protocols are used (HTTP, Telnet, FTP).
    *   **Plaintext Credential Harvesting**: Scans payloads for raw credential identifiers (`password`, `secret`, `bearer `, etc.) to alert analysts to cleartext exposure.
    *   **Exploit & Injection Signatures**: Scans raw data for injection payloads like SQL Injection (`' or 1=1`, `union select`), Cross-Site Scripting (`<script>`), and Directory Path Traversal (`../`).
*   **Wireshark-Compatible PCAP Export**:
    *   Saves packet structures directly to an industry-standard binary PCAP file for forensic audit in **Wireshark** or **tcpdump**.
*   **Double Structured Metadata Logs**:
    *   Exports readable `.txt` diagnostics and structured `.json` datasets for ingestion into external SIEM tools.
*   **Intelligent Windows Resolution**:
    *   Supports dynamic interface mapping. Feed it standard name aliases like `"Wi-Fi"`, and it will automatically resolve it to Scapy's hardware driver interface ID.

---

## 🛠️ Installation & Setup

### 1. Install Dependencies
Run the following command in your terminal:
```bash
pip install scapy colorama
```

### 2. Administrator Privileges
Network interface binding requires raw socket access:
*   **Windows**: Run your command prompt or PowerShell as **Administrator**.
*   **Linux/macOS**: Prefix commands with `sudo`:
    ```bash
    sudo python3 sniffer.py
    ```

---

## 📖 CLI Usage & Examples

### 1. Diagnostic Interface Listing
```bash
python sniffer.py --list-ifaces
```

### 2. Capture Traffic on a Specific Interface
```bash
python sniffer.py -i "Wi-Fi"
```

### 3. Capture a Specific Count of Packets
```bash
python sniffer.py -c 50
```

### 4. Capture and Extract Decoded ASCII Payloads
```bash
python sniffer.py --payload
```

### 5. Deep Security Audit with Hex Dump
```bash
python sniffer.py -f "tcp port 80" --hexdump
```

---

## 📂 Project Architecture

```directory
aegisflow_dpi/
│
├── sniffer.py         # Primary inspector, parsing engine, and threat rules
├── README.md          # Comprehensive platform documentation
└── logs/              # Forensic outputs directory (created automatically)
    ├── capture_[ts].txt    # Readable standard text logs
    ├── capture_[ts].json   # Detailed structured packet objects
    └── capture_[ts].pcap   # Binary Wireshark-compatible capture records
```

---

## 📊 Summary Auditing (Sample Output)

```text
================================================================================
  📊  EXECUTIVE SECURITY METRICS REPORT
================================================================================
  Total Packets Processed       : 20
  Total Data Captured           : 14.52 KB
  Execution Duration            : 0:00:12

  ── Protocol Distribution ──
  TCP           20  ████████████████████████████████████████

  ── Top 5 Source Hosts ──
  127.0.0.1                 20 packets

  ── Top 5 Targeted Services/Ports ──
  64204        (Unknown        ) 10 packets
  63155        (Unknown        ) 10 packets

  🚨  ── Security Threats & Vulnerability Alerts ──
  [x3] HIGH: Plaintext credential keywords matching 'password' identified in payload.
================================================================================
```
## 🎥 Video Demonstration
Check out the automated threat simulation and DPI engine in action!
**[▶️ Watch the Demo on Google Drive]((https://drive.google.com/file/d/1SDARG4fRZCyeOYDHi4ZZu3Iw6PzNv5NY/view?usp=drive_link))**

---



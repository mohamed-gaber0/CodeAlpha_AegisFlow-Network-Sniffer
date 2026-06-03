#!/usr/bin/env python3
"""
AegisFlow — Deep Packet Inspector & Behavioral IDS
Enterprise Security Analysis & Auditing Platform
Version: 4.5 (Production Optimized)
"""

import os
import sys
import csv
import json
import time
import signal
import socket
import datetime
import textwrap
import argparse
import logging
import threading
from logging.handlers import RotatingFileHandler
from collections import defaultdict, Counter

import urllib.request
import ipaddress

try:
    from scapy.all import (
        AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, ARP,
        DNS, DNSQR, DNSRR, Raw, Ether,
        get_if_list, conf
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    sys.exit("[!] Error: Scapy library not found. Run: pip install scapy")

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    sys.exit("[!] Error: Colorama library not found. Run: pip install colorama")

# ────────────────────────── Geo-IP Tracker ────────────────────────
class GeoLocator:
    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()
        
    def get_location(self, ip_addr) -> str:
        if not ip_addr:
            return ""
            
        with self.lock:
            if ip_addr in self.cache:
                return self.cache[ip_addr]
        
        try:
            ip_obj = ipaddress.ip_address(ip_addr)
            if ip_obj.is_private or ip_obj.is_loopback:
                with self.lock:
                    self.cache[ip_addr] = "Local"
                return "Local"
        except ValueError:
            return ""
            
        # Put resolving placeholder
        with self.lock:
            self.cache[ip_addr] = ""
            
        threading.Thread(target=self._resolve, args=(ip_addr,), daemon=True).start()
        return ""
        
    def _resolve(self, ip_addr):
        try:
            url = f"http://ip-api.com/json/{ip_addr}?fields=countryCode"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=2.0) as response:
                data = json.loads(response.read().decode('utf-8'))
                loc = data.get('countryCode', '')
                with self.lock:
                    self.cache[ip_addr] = loc
        except Exception:
            with self.lock:
                self.cache[ip_addr] = ""

GEO = GeoLocator()

# ─────────────────────────── Constants ──────────────────────────
VERSION = "4.6"
BANNER = f"""{Fore.CYAN}AegisFlow DPI & Behavioral IDS (v{VERSION}){Style.RESET_ALL}"""

PROTO_COLORS = {
    "TCP"   : Fore.GREEN,
    "UDP"   : Fore.YELLOW,
    "ICMP"  : Fore.MAGENTA,
    "ARP"   : Fore.CYAN,
    "DNS"   : Fore.BLUE,
    "HTTP"  : Fore.RED,
    "HTTPS" : Fore.RED + Style.BRIGHT,
    "IPv6"  : Fore.WHITE,
    "OTHER" : Fore.WHITE,
}

WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
}


# ─────────────────────── Statistics Tracker ─────────────────────
class Stats:
    """Collects traffic statistics and aggregates threat metrics."""

    def __init__(self):
        self.total          = 0
        self.protocols      = Counter()
        self.src_ips        = Counter()
        self.dst_ips        = Counter()
        self.src_ports      = Counter()
        self.dst_ports      = Counter()
        self.total_bytes    = 0
        self.threat_alerts  = []
        self.start_time     = datetime.datetime.now()
        self.packets_log    = []

    def update(self, record: dict, store_packets: bool = False):
        self.total += 1
        self.protocols[record["protocol"]] += 1
        self.total_bytes += record.get("length", 0)
        
        if record.get("src_ip"):
            self.src_ips[record["src_ip"]] += 1
        if record.get("dst_ip"):
            self.dst_ips[record["dst_ip"]] += 1
        if record.get("src_port"):
            self.src_ports[record["src_port"]] += 1
        if record.get("dst_port"):
            self.dst_ports[record["dst_port"]] += 1
        if record.get("threats"):
            for threat in record["threats"]:
                self.threat_alerts.append(threat)
                
        if store_packets:
            self.packets_log.append(record)

    def elapsed(self) -> str:
        delta = datetime.datetime.now() - self.start_time
        return str(delta).split(".")[0]

    def summary(self) -> str:
        lines = [
            f"\n{Fore.CYAN}--- AegisFlow Security Metrics Summary ---",
            f"  Packets Audited         : {self.total}",
            f"  Bandwidth Processed     : {self._fmt_bytes(self.total_bytes)}",
            f"  Audit Duration          : {self.elapsed()}",
            "\n  --- Protocol Breakdown ---",
        ]
        for proto, count in self.protocols.most_common():
            bar   = "█" * min(max(1, int(count * 20 / max(1, self.total))), 20)
            color = PROTO_COLORS.get(proto, Fore.WHITE)
            lines.append(f"  {color}{proto:<10}{Style.RESET_ALL} {count:>5}  {color}{bar}")

        lines += ["\n  --- Top Source IPs ---"]
        for ip, cnt in self.src_ips.most_common(3):
            lines.append(f"  {ip:<20} : {cnt} packets")

        lines += ["\n  --- Top Targeted Ports ---"]
        for port, cnt in self.dst_ports.most_common(3):
            service = WELL_KNOWN_PORTS.get(port, "Unknown")
            lines.append(f"  Port {port:<6} ({service:<10}) : {cnt} packets")

        if self.threat_alerts:
            lines += [f"\n  {Fore.RED}🚨  --- Real-time Behavioral & Signature Warnings ---"]
            for alert, cnt in Counter(self.threat_alerts).most_common(5):
                lines.append(f"  {Fore.RED}[x{cnt}] {alert}")
        else:
            lines += [f"\n  {Fore.GREEN}🛡️  --- No threats or unencrypted leaks identified."]

        return "\n".join(lines)

    @staticmethod
    def _fmt_bytes(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.2f} {unit}"
            n /= 1024
        return f"{n:.2f} TB"


# ─────────────────────── Packet Analyzer ────────────────────────
class PacketAnalyzer:
    """Performs deep packet inspection and flags signature and behavioral alerts."""

    def __init__(self, show_payload: bool = False, show_hex: bool = False):
        self.show_payload = show_payload or show_hex
        self.show_hex     = show_hex
        
        # Threat State Trackers
        self.port_scan_tracker = defaultdict(set)
        self.syn_flood_tracker = Counter()
        self._last_alert_time  = {}  # Cooldown rate-limiter: alert_key -> timestamp

    def analyze(self, pkt) -> dict:
        record = {
            "timestamp" : datetime.datetime.now().isoformat(timespec="milliseconds"),
            "length"    : len(pkt),
            "protocol"  : "OTHER",
            "src_ip"    : None,
            "dst_ip"    : None,
            "src_port"  : None,
            "dst_port"  : None,
            "info"      : "",
            "payload"   : None,
            "threats"   : []
        }

        if pkt.haslayer(Ether):
            record["src_mac"] = pkt[Ether].src
            record["dst_mac"] = pkt[Ether].dst

        if pkt.haslayer(ARP):
            self._parse_arp(pkt, record)
        elif pkt.haslayer(IP):
            record["src_ip"]  = pkt[IP].src
            record["dst_ip"]  = pkt[IP].dst
            record["ttl"]     = pkt[IP].ttl
            record["ip_ver"]  = 4

            if pkt.haslayer(TCP):
                self._parse_tcp(pkt, record)
            elif pkt.haslayer(UDP):
                self._parse_udp(pkt, record)
            elif pkt.haslayer(ICMP):
                self._parse_icmp(pkt, record)
            else:
                record["protocol"] = "IP"
        elif pkt.haslayer(IPv6):
            record["src_ip"]  = pkt[IPv6].src
            record["dst_ip"]  = pkt[IPv6].dst
            record["ip_ver"]  = 6

            if pkt.haslayer(TCP):
                self._parse_tcp(pkt, record)
            elif pkt.haslayer(UDP):
                self._parse_udp(pkt, record)
            else:
                record["protocol"] = "IPv6"

        if pkt.haslayer(Raw):
            raw = pkt[Raw].load
            record["payload"] = self._safe_decode(raw)
            if self.show_hex:
                record["hex_dump"] = self._hex_dump(raw)

        record["threats"] = self._detect_threats(pkt, record)

        return record

    def _parse_arp(self, pkt, record):
        arp        = pkt[ARP]
        op         = "Request" if arp.op == 1 else "Reply"
        record["protocol"] = "ARP"
        record["src_ip"]   = arp.psrc
        record["dst_ip"]   = arp.pdst
        record["info"]     = f"ARP {op} | {arp.psrc} -> {arp.pdst}"

    def _parse_tcp(self, pkt, record):
        tcp = pkt[TCP]
        record["src_port"] = tcp.sport
        record["dst_port"] = tcp.dport
        flags              = self._tcp_flags(tcp.flags)
        service            = self._port_service(tcp.sport, tcp.dport)

        if pkt.haslayer(HTTPRequest):
            record["protocol"] = "HTTP"
            req = pkt[HTTPRequest]
            method = self._safe_decode(getattr(req, "Method", "?"))
            host   = self._safe_decode(getattr(req, "Host", "?"))
            path   = self._safe_decode(getattr(req, "Path", "/"))
            record["info"] = f"HTTP {method} {host}{path}"
        elif pkt.haslayer(HTTPResponse):
            record["protocol"] = "HTTP"
            resp = pkt[HTTPResponse]
            code = self._safe_decode(getattr(resp, "Status_Code", "?"))
            record["info"] = f"HTTP Response {code}"
        elif tcp.dport == 443 or tcp.sport == 443:
            record["protocol"] = "HTTPS"
            record["info"]     = f"TLS/HTTPS [{flags}]"
        else:
            record["protocol"] = "TCP"
            record["info"]     = f"{service} | Flags: [{flags}] | Seq: {tcp.seq} | Ack: {tcp.ack}"

    def _parse_udp(self, pkt, record):
        udp  = pkt[UDP]
        record["src_port"] = udp.sport
        record["dst_port"] = udp.dport

        if pkt.haslayer(DNS):
            self._parse_dns(pkt, record)
        else:
            service          = self._port_service(udp.sport, udp.dport)
            record["protocol"] = "UDP"
            record["info"]     = f"{service} | Len: {udp.len}"

    def _parse_dns(self, pkt, record):
        dns = pkt[DNS]
        record["protocol"] = "DNS"

        if dns.qr == 0 and dns.qdcount > 0:
            try:
                qname = self._safe_decode(dns.qd.qname).rstrip(".")
                record["info"] = f"DNS Query  → {qname}"
            except Exception:
                record["info"] = "DNS Query"
        elif dns.qr == 1 and dns.ancount > 0:
            answers = []
            try:
                for i in range(min(dns.ancount, 10)):
                    rr = dns.an[i]
                    if hasattr(rr, "rdata"):
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            rdata = self._safe_decode(rdata)
                        answers.append(str(rdata))
            except Exception:
                pass
            record["info"] = f"DNS Reply  ← {', '.join(answers[:3])}"
        else:
            record["info"] = "DNS"

    def _parse_icmp(self, pkt, record):
        icmp = pkt[ICMP]
        type_map = {0: "Echo Reply", 3: "Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
        type_name          = type_map.get(icmp.type, f"Type {icmp.type}")
        record["protocol"] = "ICMP"
        record["info"]     = f"ICMP {type_name}"

    def _detect_threats(self, pkt, record) -> list:
        raw_alerts = []
        proto = record.get("protocol", "OTHER")
        port_dst = record.get("dst_port")
        port_src = record.get("src_port")
        src_ip = record.get("src_ip")
        info = record.get("info", "")

        # Unencrypted protocol signatures
        if proto == "HTTP":
            raw_alerts.append(("unencrypted_http", "VULN: Insecure unencrypted HTTP communication in use."))
        elif port_dst == 21 or port_src == 21:
            raw_alerts.append(("insecure_ftp", "VULN: Insecure FTP communication. Cleartext credentials vulnerable."))
        elif port_dst == 23 or port_src == 23:
            raw_alerts.append(("legacy_telnet", "VULN: Legacy Telnet protocol detected. Session unencrypted."))

        # Port Scan detection
        if src_ip and port_dst:
            self.port_scan_tracker[src_ip].add(port_dst)
            if len(self.port_scan_tracker[src_ip]) > 15:
                raw_alerts.append(("port_scan", f"ATTACK: Port Scan detected from {src_ip} (targeted >15 ports)."))

        # SYN Flood DoS detection
        if src_ip and proto == "TCP" and "SYN" in info and "ACK" not in info:
            self.syn_flood_tracker[src_ip] += 1
            if self.syn_flood_tracker[src_ip] > 30:
                raw_alerts.append(("syn_flood", f"ATTACK: Potential SYN Flood DoS from {src_ip} (>30 SYN packets)."))

        # Payload Inspection
        payload_str = ""
        if pkt.haslayer(Raw):
            # Many protocols like HTTP URL-encode payloads or have distinct formatting
            payload_raw = pkt[Raw].load
            payload_str = self._safe_decode(payload_raw).lower()

        # Check for credentials in both Payload and Info (which contains HTTP GET URL)
        import urllib.parse
        target_text = urllib.parse.unquote(payload_str + " " + info.lower())
        cred_patterns = ["password=", "passwd=", "pass=", "secret=", "pwd="]
        for keyword in cred_patterns:
            if keyword in target_text:
                raw_alerts.append(("credential_leak", f"HIGH: Plaintext credential leak matching '{keyword}'."))
                break

        sqli_indicators = ["' or 1=1", "union select", "select * from"]
        for indicator in sqli_indicators:
            if indicator in target_text:
                raw_alerts.append(("sqli", f"EXPLOIT: SQL Injection signature '{indicator}' detected."))
                break

        xss_indicators = ["<script>", "javascript:", "onload="]
        for indicator in xss_indicators:
            if indicator in target_text:
                raw_alerts.append(("xss", f"EXPLOIT: Cross-Site Scripting signature '{indicator}' detected."))
                break

        if "../" in target_text or "..\\" in target_text:
            raw_alerts.append(("path_traversal", "EXPLOIT: Directory Path Traversal detected."))

        # Rate Limiter: Filter alerts with a 10-second cooldown per alert type per IP
        filtered_alerts = []
        current_time = time.time()
        for alert_type, alert_message in raw_alerts:
            alert_key = (src_ip, alert_type)
            if current_time - self._last_alert_time.get(alert_key, 0) >= 3.0: # Reduced cooldown to 3 seconds for better responsiveness
                filtered_alerts.append(alert_message)
                self._last_alert_time[alert_key] = current_time

        return filtered_alerts

    @staticmethod
    def _tcp_flags(flags) -> str:
        flag_map = {"S":"SYN","A":"ACK","F":"FIN","R":"RST","P":"PSH","U":"URG"}
        try:
            s = str(flags)
            return " ".join(flag_map.get(c, c) for c in s if c in flag_map) or str(flags)
        except Exception:
            return str(flags)

    @staticmethod
    def _port_service(sport: int, dport: int) -> str:
        return WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport) or f"Port {sport}→{dport}"

    @staticmethod
    def _safe_decode(raw) -> str:
        if isinstance(raw, str):
            return raw
        if isinstance(raw, bytes):
            try:
                return raw.decode("utf-8", errors="replace")
            except Exception:
                return repr(raw)
        return str(raw) if raw is not None else ""

    @staticmethod
    def _hex_dump(data, width: int = 16) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8", errors="ignore")
        elif not isinstance(data, (bytes, bytearray)):
            return ""
        lines = []
        for i in range(0, len(data), width):
            chunk   = data[i:i+width]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_s = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"  {i:04x}   {hex_str:<{width*3}}  |{ascii_s}|")
        return "\n".join(lines)


# ──────────────────────── Display Engine ─────────────────────────
class Display:
    """Prints diagnostic lines and alert alerts cleanly."""
    _lock = threading.Lock()

    @staticmethod
    def packet_line(count: int, record: dict):
        proto  = record.get("protocol", "OTHER")
        color  = PROTO_COLORS.get(proto, Fore.WHITE)
        ts     = record["timestamp"][11:]
        length = record.get("length", 0)

        src_ip = str(record.get("src_ip", "N/A"))
        dst_ip = str(record.get("dst_ip", "N/A"))
        
        src_loc = GEO.get_location(src_ip)
        dst_loc = GEO.get_location(dst_ip)
        
        src_disp = f"{src_ip}[{src_loc}]" if src_loc and src_loc != "Local" else src_ip
        dst_disp = f"{dst_ip}[{dst_loc}]" if dst_loc and dst_loc != "Local" else dst_ip
        
        src = f"{src_disp}:{record['src_port']}" if record.get("src_port") else src_disp
        dst = f"{dst_disp}:{record['dst_port']}" if record.get("dst_port") else dst_disp

        info = record.get("info", "")

        out_lines = []
        out_lines.append(
            f"{Fore.WHITE}[{count:>5}] "
            f"{Fore.BLUE}{ts}  "
            f"{color}{proto:<8}{Style.RESET_ALL} "
            f"{Fore.WHITE}{src:<25}→  {dst:<25}  "
            f"{Fore.WHITE}{length:>5}B  "
            f"{color}{info}{Style.RESET_ALL}"
        )

        if record.get("threats"):
            for threat in record["threats"]:
                out_lines.append(f"         {Fore.RED}{Style.BRIGHT}[!] ALERT: {Fore.YELLOW}{threat}{Style.RESET_ALL}")

        if record.get("payload"):
            snippet = record["payload"][:200].replace("\n", "↵")
            out_lines.append(f"         {Fore.WHITE}Payload: {Fore.YELLOW}{snippet}{Style.RESET_ALL}")

        if record.get("hex_dump"):
            out_lines.append(f"{Fore.CYAN}{record['hex_dump']}{Style.RESET_ALL}")
            
        with Display._lock:
            for line in out_lines:
                print(line)

    @staticmethod
    def header():
        with Display._lock:
            print(f"\n{'#'}     {'Time':<10}  {'Proto':<8} {'Source':<25}    {'Destination':<25}  {'Len':>5}  Details")
            print("·" * 100)


# ──────────────────────────── Logger ─────────────────────────────
class Logger:
    """Manages rotating file handlers, JSON log exporting, and CSV dumps."""

    def __init__(self, log_dir: str = "logs"):
        os.makedirs(log_dir, exist_ok=True)
        ts            = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.json_path = os.path.join(log_dir, f"capture_{ts}.json")
        self.txt_path  = os.path.join(log_dir, f"capture_{ts}.txt")
        self.csv_path  = os.path.join(log_dir, f"capture_{ts}.csv")
        self.pcap_path = os.path.join(log_dir, f"capture_{ts}.pcap")
        
        self.file_logger = logging.getLogger("AegisFlow")
        self.file_logger.setLevel(logging.INFO)
        if not self.file_logger.handlers:
            handler = RotatingFileHandler(
                self.txt_path, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8"
            )
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.file_logger.addHandler(handler)

    def write(self, record: dict):
        line = (
            f"[{record['timestamp']}] "
            f"{record.get('protocol','?'):<8} "
            f"{record.get('src_ip','?')}:{record.get('src_port','?')} -> "
            f"{record.get('dst_ip','?')}:{record.get('dst_port','?')} "
            f"| {record.get('length',0)}B | {record.get('info','')}"
        )
        if record.get("threats"):
            for threat in record["threats"]:
                line += f"\n  -> ALERT: {threat}"
        self.file_logger.info(line)

    def save_json(self, packets: list):
        with open(self.json_path, "w", encoding="utf-8") as f:
            json.dump(packets, f, indent=2, default=str)

    def close(self, packets_log: list, scapy_packets: list = None, save_json: bool = False, save_pcap: bool = False):
        for handler in list(self.file_logger.handlers):
            handler.close()
            self.file_logger.removeHandler(handler)
            
        json_info = ""
        csv_info = ""
        if save_json:
            self.save_json(packets_log)
            json_info = f"\n     JSON: {self.json_path}"
            try:
                with open(self.csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Timestamp", "Length", "Protocol", "Source IP", "Destination IP", "Source Port", "Destination Port", "Info", "Vulnerabilities"])
                    for r in packets_log:
                        threats_str = " | ".join(r.get("threats", []))
                        writer.writerow([
                            r.get("timestamp"), r.get("length"), r.get("protocol"),
                            r.get("src_ip"), r.get("dst_ip"), r.get("src_port"),
                            r.get("dst_port"), r.get("info"), threats_str
                        ])
                csv_info = f"\n     CSV : {self.csv_path}"
            except Exception as e:
                csv_info = f"\n     CSV export failed: {e}"

        pcap_info = ""
        if save_pcap and scapy_packets:
            try:
                from scapy.all import wrpcap
                wrpcap(self.pcap_path, scapy_packets)
                pcap_info = f"\n     PCAP: {self.pcap_path}"
            except Exception as e:
                pcap_info = f"\n     PCAP export failed: {e}"

        print(
            f"\n{Fore.GREEN}[✔] Logs completed:"
            f"\n     TXT : {self.txt_path}{json_info}{csv_info}{pcap_info}{Style.RESET_ALL}"
        )


# ──────────────────────── Core Sniffer ───────────────────────────
class NetworkSniffer:
    """Orchestrates non-blocking packet sniff handlers and graceful shutdowns."""

    def __init__(self, args):
        self.args          = args
        self.stats         = Stats()
        self.analyzer      = PacketAnalyzer(
            show_payload=args.payload,
            show_hex=args.hexdump
        )
        self.logger        = Logger(args.log_dir)
        self.count         = 0
        self.scapy_packets = []
        self._finished     = False
        self._running      = True

        self._resolve_interface(args)
        signal.signal(signal.SIGINT, self._on_exit)

    def _resolve_interface(self, args):
        if not args.iface:
            return

        try:
            from scapy.interfaces import resolve_iface
            resolve_iface(args.iface)
            return
        except Exception:
            pass

        try:
            query = args.iface.lower()
            for iface_id, iface in conf.ifaces.items():
                name = getattr(iface, "name", "").lower()
                desc = getattr(iface, "description", "").lower()
                guid = getattr(iface, "guid", "").lower()

                if query in name or query in desc or query in guid:
                    resolved = getattr(iface, "pcap_name", None) or getattr(iface, "guid", None) or getattr(iface, "name", None)
                    if resolved:
                        if resolved.startswith("{"):
                            resolved = f"\\Device\\NPF_{resolved}"
                        friendly_name = getattr(iface, "description", None) or getattr(iface, "name", "Interface")
                        print(f"{Fore.GREEN}[✔] Resolved interface '{args.iface}' -> {friendly_name}{Style.RESET_ALL}")
                        args.iface = resolved
                        return
        except Exception as e:
            print(f"{Fore.RED}[!] Interface resolver error: {e}{Style.RESET_ALL}")

    def _process(self, pkt):
        try:
            if self.args.save_pcap:
                self.scapy_packets.append(pkt)

            record = self.analyzer.analyze(pkt)
            self.stats.update(record, store_packets=self.args.save_json)
            self.logger.write(record)
            self.count += 1

            if self.args.proto:
                if record["protocol"].lower() != self.args.proto.lower():
                    return

            if not self.args.quiet:
                Display.packet_line(self.count, record)

        except Exception as e:
            print(f"{Fore.RED}[!] Parse exception: {e}{Style.RESET_ALL}")

    def start(self):
        print(BANNER)
        self._print_config()
        if not self.args.quiet:
            Display.header()

        self.sniffer = AsyncSniffer(
            iface   = self.args.iface or None,
            filter  = self.args.filter or None,
            prn     = self._process,
            count   = self.args.count,
            store   = False
        )
        self.sniffer.start()

        try:
            while self._running:
                if self.args.count and self.count >= self.args.count:
                    break
                time.sleep(0.05)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[⚠] Keyboard interrupt detected.{Style.RESET_ALL}")
            self._finish()
            os._exit(0)

        self._finish()

    def _on_exit(self, *_):
        self._finish()
        os._exit(0)

    def _finish(self):
        if self._finished:
            return
        self._finished = True
        self._running = False
        
        if hasattr(self, "sniffer") and self.sniffer.running:
            self.sniffer.stop()

        self.logger.close(self.stats.packets_log, self.scapy_packets, self.args.save_json, self.args.save_pcap)
        print(self.stats.summary())

    def _print_config(self):
        iface   = self.args.iface  or "System Default"
        bpf     = self.args.filter or "None"
        limit   = str(self.args.count) if self.args.count else "Continuous"
        proto_f = self.args.proto or "All"

        print(f"  Interface     : {iface}")
        print(f"  BPF Filter    : {bpf}")
        print(f"  Packet Limit  : {limit}")
        print(f"  Protocols     : {proto_f}")
        print(f"  Quiet Mode    : {self.args.quiet}")
        print(f"  PCAP Saving   : {self.args.save_pcap}")
        print(f"  JSON Saving   : {self.args.save_json}")
        print("-" * 50)


# ──────────────────────── CLI Interface ──────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffer.py",
        description="Deep Packet Inspection (DPI) & Intrusion Detection System"
    )
    parser.add_argument("-i", "--iface", help="Network interface to sniff")
    parser.add_argument("-f", "--filter", help="BPF filter string (e.g. 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Total packets to sniff")
    parser.add_argument("--proto", help="Display only this protocol layer")
    parser.add_argument("--payload", action="store_true", help="Show payload representation")
    parser.add_argument("--hexdump", action="store_true", help="Show hex payload representation")
    parser.add_argument("--save-json", action="store_true", help="Store and export structured JSON/CSV data sheets")
    parser.add_argument("--save-pcap", action="store_true", help="Store and save standard PCAP captures")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode. Suppress console printing")
    parser.add_argument("--log-dir", default="logs", help="Saves folder directory path")
    parser.add_argument("--list-ifaces", action="store_true", help="Show interfaces")
    return parser


# ─────────────────────────── Entry Point ─────────────────────────
def main():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except Exception:
            pass

    parser = build_parser()
    args   = parser.parse_args()

    if args.list_ifaces:
        print(f"\nActive Network Interfaces:")
        try:
            for iface_id, iface in conf.ifaces.items():
                name = getattr(iface, "description", None) or getattr(iface, "name", str(iface_id))
                dev = getattr(iface, "guid", None) or getattr(iface, "name", str(iface_id))
                ip = getattr(iface, "ip", "Unassigned")
                print(f"  * {name:<40} (GUID: {dev}) - {ip}")
        except Exception:
            for iface in get_if_list():
                print(f"  * {iface}")
        print()
        sys.exit(0)

    try:
        is_admin = (os.geteuid() == 0)
    except AttributeError:
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = True

    if not is_admin:
        if sys.platform == "win32":
            import ctypes
            print(f"[!] Requesting Admin privileges...")
            try:
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(f'"{a}"' for a in sys.argv), None, 1
                )
                if ret > 32:
                    sys.exit(0)
                else:
                    print(f"[✘] UAC request declined. Run as Administrator.")
                    sys.exit(1)
            except Exception as e:
                print(f"[✘] Elevation trigger failed: {e}")
                sys.exit(1)
        else:
            sys.exit("[✘] Root privileges required. Run with sudo.")

    sniffer = NetworkSniffer(args)
    sniffer.start()


if __name__ == "__main__":
    main()

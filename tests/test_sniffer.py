import sys
import os
import pytest

# Ensure parent directory is in path to import sniffer components
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sniffer import PacketAnalyzer

class MockPacket:
    """Mocking Scapy Packet objects for unit testing."""
    def __init__(self, layers, raw_payload=None):
        self.layers_list = layers
        self.raw_payload = raw_payload

    def haslayer(self, layer_class):
        return layer_class in self.layers_list

    def __getitem__(self, layer_class):
        class MockLayer:
            def __init__(self, payload):
                self.load = payload
                self.src = "00:11:22:33:44:55"
                self.dst = "66:77:88:99:aa:bb"
        return MockLayer(self.raw_payload)


def test_safe_decode():
    """Verify that safe decoding parses strings, bytes, and None safely without throwing errors."""
    from sniffer import PacketAnalyzer
    analyzer = PacketAnalyzer()
    
    assert analyzer._safe_decode("test_str") == "test_str"
    assert analyzer._safe_decode(b"test_bytes") == "test_bytes"
    assert analyzer._safe_decode(None) == ""


def test_insecure_protocol_http():
    """Verify signature engine flags insecure HTTP traffic."""
    from sniffer import PacketAnalyzer
    analyzer = PacketAnalyzer()
    
    record = {
        "protocol": "HTTP",
        "src_ip": "192.168.1.10",
        "dst_ip": "1.2.3.4",
        "dst_port": 80,
        "info": "HTTP GET /index.html"
    }
    
    # Mocking standard Scapy packet without raw layer
    mock_pkt = MockPacket([])
    
    threats = analyzer._detect_threats(mock_pkt, record)
    assert any("unencrypted HTTP" in t for t in threats)


def test_behavioral_port_scan():
    """Verify behavioral engine flags potential port scans (>15 unique targeted ports)."""
    from sniffer import PacketAnalyzer
    analyzer = PacketAnalyzer()
    
    # Simulate a single source IP scanning 17 unique ports
    all_threats = []
    mock_pkt = MockPacket([])
    
    for port in range(1, 18):
        record = {
            "protocol": "TCP",
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.1",
            "src_port": 50000,
            "dst_port": port,
            "info": "TCP Syn Connection Attempt"
        }
        threats = analyzer._detect_threats(mock_pkt, record)
        all_threats.extend(threats)
        
    # Check if a port scan warning was generated during the loop
    assert any("Port Scan" in t for t in all_threats)


def test_behavioral_syn_flood():
    """Verify behavioral engine flags potential SYN flood DoS attacks (>30 raw SYN packets)."""
    from sniffer import PacketAnalyzer
    analyzer = PacketAnalyzer()
    
    all_threats = []
    mock_pkt = MockPacket([])
    
    for _ in range(35):
        record = {
            "protocol": "TCP",
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.1.1",
            "src_port": 50000,
            "dst_port": 80,
            "info": "Flags: [SYN] | Sequence 123456"
        }
        threats = analyzer._detect_threats(mock_pkt, record)
        all_threats.extend(threats)
        
    assert any("SYN Flood" in t for t in all_threats)


def test_credential_leak_signature():
    """Verify signature engine flags raw password transmissions in packet payloads."""
    from sniffer import PacketAnalyzer
    from scapy.all import Raw
    analyzer = PacketAnalyzer()
    
    record = {
        "protocol": "TCP",
        "src_ip": "192.168.1.10",
        "dst_ip": "1.2.3.4",
        "dst_port": 80,
        "info": "HTTP POST /login"
    }
    
    # Mock packet with unencrypted password payload
    mock_pkt = MockPacket([Raw], raw_payload=b"user=admin&password=SuperSecretPassword123")
    
    threats = analyzer._detect_threats(mock_pkt, record)
    assert any("Plaintext credential" in t for t in threats)

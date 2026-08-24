"""
Traffic Miner Agent  —  Multi-Agent Edition
============================================
Lightweight distributed agent for capturing packet streams, computing flow metrics,
and reporting real-time telemetry to the central GarudaRush server.

Environment variables:
    SERVER_URL      Base URL of server (default: http://localhost:5000)
    AGENT_ID        Identifier for this agent (default: hostname-<8 hex chars>)
    AGENT_LOCATION  Location / segment description (default: hostname)
    INTERFACE       Network interface (default: primary default interface)
    WINDOW_SIZE     Aggregation window in seconds (default: 5)
    API_KEY         Shared secret sent as X-API-Key header (default: empty = disabled)
    LOG_LEVEL       Logging level (default: INFO)
"""

import os
import sys
import time
import signal
import logging
import threading
import math
import socket
import uuid
import requests
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.arch import get_if_list

# ═══════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════
_hostname = socket.gethostname()
_uid_suffix = uuid.uuid4().hex[:8]

SERVER_URL = os.getenv("SERVER_URL", "http://localhost:5000")
AGENT_ID = os.getenv("AGENT_ID", f"{_hostname}-{_uid_suffix}")
AGENT_LOCATION = os.getenv("AGENT_LOCATION", _hostname)
WINDOW_SIZE = int(os.getenv("WINDOW_SIZE", 5))
INTERFACE = os.getenv("INTERFACE") or (get_if_list()[0] if get_if_list() else "eth0")
API_KEY = os.getenv("API_KEY", "")
MAX_QUEUE_SIZE = 1000
RETRY_INTERVAL = 10
HEARTBEAT_INTERVAL = 20
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

FLOW_URL = f"{SERVER_URL}/api/flow"
REGISTER_URL = f"{SERVER_URL}/api/agents/register"
HEARTBEAT_URL = f"{SERVER_URL}/api/agents/heartbeat"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format=f"%(asctime)s - [AGENT:{AGENT_ID[:12]}] - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

_adapter = requests.adapters.HTTPAdapter(max_retries=1)
session = requests.Session()
session.mount("http://", _adapter)
session.mount("https://", _adapter)

if API_KEY:
    session.headers.update({"X-API-Key": API_KEY})
    logger.info("API key authentication enabled.")


def calculate_entropy(counter_dict: dict) -> float:
    total = sum(counter_dict.values())
    if total == 0:
        return -1.0
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counter_dict.values()
        if c > 0
    )


class TrafficMiner:
    def __init__(self, interface: str):
        self.interface = interface
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.retry_queue: list = []

        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
            logger.error("Must run as root to capture network packets.")
            sys.exit(1)

        self._reset_window()

    def _reset_window(self):
        self.start_time = time.time()
        self.packet_count = 0
        self.byte_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.syn_count = 0
        self.ack_count = 0
        self.fragment_count = 0
        self.http_requests = 0
        self.src_ip_counter = Counter()
        self.dst_port_counter = Counter()
        self.icmp_type_counter = Counter()

    def extract_features(self, packet):
        if self.stop_event.is_set() or IP not in packet:
            return
        try:
            with self.lock:
                self.packet_count += 1
                self.byte_count += len(packet)
                self.src_ip_counter[packet[IP].src] += 1

                if packet[IP].flags.MF or packet[IP].frag > 0:
                    self.fragment_count += 1

                if ICMP in packet:
                    self.icmp_count += 1
                    self.icmp_type_counter[packet[ICMP].type] += 1

                if TCP in packet:
                    self._process_tcp(packet)

                if UDP in packet:
                    self.udp_count += 1
                    self.dst_port_counter[packet[UDP].dport] += 1

        except Exception as e:
            logger.warning(f"Feature extraction error: {e}", exc_info=True)

    def _process_tcp(self, packet):
        tcp = packet[TCP]
        self.tcp_count += 1
        if tcp.flags & 0x02:
            self.syn_count += 1
        if tcp.flags & 0x10:
            self.ack_count += 1
        self.dst_port_counter[tcp.dport] += 1
        if tcp.dport in (80, 443) and Raw in packet:
            pl = bytes(packet[Raw].load)
            if b"GET " in pl or b"POST " in pl:
                self.http_requests += 1

    def _build_payload(self, duration: float) -> dict:
        safe_dur = duration if duration > 0 else 1e-6

        syn_ack_ratio = (
            self.syn_count / self.ack_count
            if self.ack_count > 0
            else min(float(self.syn_count), 999.0)
        )

        src_ip_entropy = calculate_entropy(self.src_ip_counter)

        return {
            "agent_id": AGENT_ID,
            "agent_location": AGENT_LOCATION,
            "interface": self.interface,
            "duration": round(duration, 4),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "packet_rate": round(self.packet_count / safe_dur, 4),
            "byte_rate": round(self.byte_count / safe_dur, 4),
            "tcp_count": self.tcp_count,
            "udp_count": self.udp_count,
            "icmp_count": self.icmp_count,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "syn_ack_ratio": round(syn_ack_ratio, 4),
            "fragment_count": self.fragment_count,
            "http_requests": self.http_requests,
            "src_ip_entropy": round(src_ip_entropy, 4),
            "unique_src_ips": len(self.src_ip_counter),
            "icmp_type_distribution": dict(self.icmp_type_counter),
            "top_destination_ports": dict(self.dst_port_counter.most_common(10)),
        }

    def _send_flow(self, data: dict) -> bool:
        try:
            resp = session.post(FLOW_URL, json=data, timeout=5)
            resp.raise_for_status()
            result = resp.json().get("ml_prediction", {})
            if result.get("is_ddos"):
                logger.warning(
                    f"⚠ DDoS DETECTED type={result.get('attack_type')} "
                    f"conf={result.get('confidence', 0):.2%} "
                    f"pkt/s={data.get('packet_rate', 0):.0f}"
                )
            else:
                logger.info(
                    f"Window sent — {data['packet_count']} pkts "
                    f"pkt/s={data.get('packet_rate', 0):.0f} "
                    f"ddos={result.get('is_ddos', '?')} "
                    f"conf={result.get('confidence', 0):.2%}"
                )
            return True
        except requests.RequestException as e:
            logger.warning(f"Send failed ({e}), queuing for retry")
            with self.lock:
                if len(self.retry_queue) >= MAX_QUEUE_SIZE:
                    logger.error("Retry queue full — dropping oldest entry")
                    self.retry_queue.pop(0)
                self.retry_queue.append(data)
            return False

    def _register(self):
        payload = {
            "agent_id": AGENT_ID,
            "agent_location": AGENT_LOCATION,
            "interface": INTERFACE,
            "hostname": _hostname,
            "window_size": WINDOW_SIZE,
        }
        attempt = 0
        while not self.stop_event.is_set():
            try:
                resp = session.post(REGISTER_URL, json=payload, timeout=5)
                resp.raise_for_status()
                logger.info(f"Registered with server as '{AGENT_ID}'")
                return
            except requests.RequestException as e:
                attempt += 1
                wait = min(5 * attempt, 30)
                logger.warning(f"Registration failed ({e}), retrying in {wait}s...")
                time.sleep(wait)

    def _heartbeat_worker(self):
        while not self.stop_event.is_set():
            try:
                session.post(
                    HEARTBEAT_URL,
                    json={"agent_id": AGENT_ID},
                    timeout=3,
                )
                logger.debug("Heartbeat sent")
            except Exception as e:
                logger.debug(f"Heartbeat failed: {e}")
            time.sleep(HEARTBEAT_INTERVAL)

    def _monitor_loop(self):
        while not self.stop_event.is_set():
            time.sleep(WINDOW_SIZE)
            with self.lock:
                duration = time.time() - self.start_time
                if duration <= 0:
                    continue
                payload = self._build_payload(duration)
                self._reset_window()
            self._send_flow(payload)

    def _retry_worker(self):
        while not self.stop_event.is_set():
            time.sleep(RETRY_INTERVAL)
            with self.lock:
                if not self.retry_queue:
                    continue
                pending, self.retry_queue = self.retry_queue, []

            failed = [item for item in pending if not self._send_flow(item)]
            if failed:
                with self.lock:
                    self.retry_queue[:0] = failed
                logger.debug(f"Retry queue: {len(self.retry_queue)} items pending")

    def start(self):
        logger.info(
            f"Starting Traffic Miner agent={AGENT_ID} "
            f"iface={self.interface} window={WINDOW_SIZE}s"
        )
        logger.info(f"Server: {SERVER_URL} | location={AGENT_LOCATION}")

        self._register()

        threads = [
            threading.Thread(target=self._monitor_loop, daemon=True, name="monitor"),
            threading.Thread(target=self._retry_worker, daemon=True, name="retry"),
            threading.Thread(target=self._heartbeat_worker, daemon=True, name="heartbeat"),
        ]
        for t in threads:
            t.start()

        try:
            while not self.stop_event.is_set():
                try:
                    sniff(
                        iface=self.interface,
                        prn=self.extract_features,
                        store=False,
                        filter="ip",
                        timeout=1,
                    )
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    logger.warning(f"Sniffer error (retry in 2s): {e}")
                    time.sleep(2)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        logger.info("Stopping agent...")
        self.stop_event.set()
        time.sleep(1)
        sys.exit(0)


if __name__ == "__main__":
    miner = TrafficMiner(INTERFACE)
    signal.signal(signal.SIGINT, lambda s, f: miner.stop())
    signal.signal(signal.SIGTERM, lambda s, f: miner.stop())
    miner.start()

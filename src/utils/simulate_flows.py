"""
GarudaRush Traffic Flow Simulation Utility
===========================================
Simulates multi-vector network traffic patterns (Normal, SYN Flood, ICMP Flood, HTTP Flood)
and posts flow windows to the central Flask ingestion server for testing.
"""
import os
import requests
import time

SERVER_URL = os.getenv("SERVER_URL", "http://localhost:5000/api/flow")


def send_test_flow(name: str, data: dict):
    print(f"\n--- Injecting {name} simulation ---")
    try:
        data.update({
            "agent_id": "manual-test-agent",
            "agent_location": "Internal Simulation Engine",
            "interface": "lo0",
            "duration": 5.0
        })

        if "packet_rate" not in data:
            data["packet_rate"] = data["packet_count"] / data["duration"]
        if "byte_rate" not in data:
            data["byte_rate"] = data["byte_count"] / data["duration"]

        resp = requests.post(SERVER_URL, json=data, timeout=5)
        if resp.status_code == 200:
            result = resp.json().get("ml_prediction", {})
            is_ddos = result.get("is_ddos", False)
            print(f"[SUCCESS] Status: {resp.status_code}")
            print(f"Prediction: {'⚠ DDOS DETECTED' if is_ddos else 'Clean Traffic'}")
            print(f"Confidence: {result.get('confidence', 0):.2%}")
            print(f"Attack Type: {result.get('attack_type', 'none')}")
        else:
            print(f"[FAILED] Status: {resp.status_code} | Error: {resp.text}")

    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")


normal_data = {
    "packet_count": 800,
    "byte_count": 45000,
    "syn_count": 12,
    "ack_count": 11,
    "syn_ack_ratio": 1.09,
    "icmp_count": 2,
    "udp_count": 35,
    "tcp_count": 120,
    "fragment_count": 0,
    "http_requests": 25,
    "src_ip_entropy": 3.42,
    "top_destination_ports": {"80": 200, "443": 150, "53": 50}
}

syn_flood_data = {
    "packet_count": 12000,
    "byte_count": 850000,
    "syn_count": 11500,
    "ack_count": 150,
    "syn_ack_ratio": 76.6,
    "icmp_count": 5,
    "udp_count": 20,
    "tcp_count": 11800,
    "fragment_count": 0,
    "http_requests": 10,
    "src_ip_entropy": 1.15,
    "top_destination_ports": {"80": 11000}
}

icmp_flood_data = {
    "packet_count": 8500,
    "byte_count": 420000,
    "syn_count": 4,
    "ack_count": 2,
    "syn_ack_ratio": 1.0,
    "icmp_count": 8400,
    "udp_count": 15,
    "tcp_count": 10,
    "fragment_count": 250,
    "http_requests": 2,
    "src_ip_entropy": 1.38,
    "top_destination_ports": {"0": 8400}
}

http_flood_data = {
    "packet_count": 5000,
    "byte_count": 900000,
    "syn_count": 1200,
    "ack_count": 800,
    "syn_ack_ratio": 1.5,
    "icmp_count": 5,
    "udp_count": 10,
    "tcp_count": 4800,
    "fragment_count": 0,
    "http_requests": 4500,
    "src_ip_entropy": 2.8,
    "top_destination_ports": {"80": 2500, "443": 2000}
}

def run_simulation():
    print("=== Starting GarudaRush Traffic Simulation Engine ===")
    print(f"Target Server: {SERVER_URL}")

    send_test_flow("NORMAL WEB TRAFFIC", normal_data)
    time.sleep(1)

    send_test_flow("SYN FLOOD ATTACK", syn_flood_data)
    time.sleep(1)

    send_test_flow("ICMP FLOOD ATTACK", icmp_flood_data)
    time.sleep(1)

    send_test_flow("HTTP GET FLOOD", http_flood_data)
    print("\nSimulation complete. View dashboard at http://localhost:5000 for live alerts.")


if __name__ == "__main__":
    run_simulation()

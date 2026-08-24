"""
GarudaRush Traffic Miner Agent Launcher
========================================
Main entry point for starting the edge network traffic sniffer agent.
Must be run with root/admin privileges to capture raw socket frames.
"""
from src.agent.agent import TrafficMiner, INTERFACE
import signal

if __name__ == "__main__":
    miner = TrafficMiner(INTERFACE)
    signal.signal(signal.SIGINT, lambda s, f: miner.stop())
    signal.signal(signal.SIGTERM, lambda s, f: miner.stop())
    miner.start()

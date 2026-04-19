<div align="center">
  <h1>🦅 GarudaRush</h1>
  <p><strong>Intelligent, Real-Time DDoS Detection & Network Analysis System</strong></p>
</div>

---

## ⚡ Overview

**GarudaRush** is an end-to-end network security solution engineered for real-time traffic monitoring and DDoS attack detection. By leveraging a high-performance **Scapy** agent and a **Random Forest** supervised learning model trained on continuous traffic flows, GarudaRush secures networked systems dynamically.

## 🏗 System Architecture

1. **Intelligent Agent (`agent.py`)** 
   - A lightweight packet sniffer deployed on edge nodes.
   - Computes statistical flow features.
   - Pushes summarized telemetry to the backend server in real-time.

2. **Detection Engine (`server.py` & `ml_model.py`)**
   - A robust **Flask** backend that acts as the centralized brain for the ecosystem.
   - Feeds incoming traffic telemetry to a pre-trained **Machine Learning Model**.
   - Archives structured logs into a **MongoDB** database for historical analysis.

3. **Analytics Dashboard (`dashboard.html`)**
   - An intuitive front-end interface built to monitor the security posture.
   - Visualizes live network flow metrics and spots detected attack spikes on-the-fly.

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- MongoDB instance running centrally

### Installation

1. **Clone the project:**
   ```bash
   git clone https://github.com/rinwasourav/GarudaRush.git
   cd GarudaRush
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## 🛠 Usage

1. **Deploy the Central Backend:**
   Launch the Flask server to start receiving and analyzing traffic telemetry.
   ```bash
   python server.py
   ```

2. **Monitor the Dashboard:**
   Open `dashboard.html` in your favorite web browser to see the live metrics updating locally.

3. **Launch the Agent:**
   On the network interfaces you wish to protect, start the agent. *(Note: requires root privileges to configure raw interface sockets).*
   ```bash
   sudo python agent.py
   ```

## 🧪 Simulation

If you want to validate the pipeline without live malicious traffic, you can inject simulated flow data:
```bash
python simulate_flows.py
```

## 🛡 Disclaimer
*This project is built for educational and research purposes under the Capstone framework. Always seek authorization before monitoring network flows.*

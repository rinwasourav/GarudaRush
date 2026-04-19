# DDoS Detection Project

This project implements a DDoS Detection System using Machine Learning.

## Components

- **Agent (`agent.py`)**: A network packet sniffer that collects traffic data, extracts flow features using Scapy, and sends them to the server for analysis.
- **Server (`server.py`)**: A Flask backend that receives network flows, passes them through the machine learning model to detect DDoS attacks, and stores the results in a MongoDB database.
- **Machine Learning Model (`ml_model.py`)**: Uses a Random Forest classifier trained on network flow datasets (e.g., CICIDS2017) to classify traffic as benign or malicious.
- **Dashboard (`dashboard.html`)**: A web interface that visualizes the network traffic and detected anomalies in real-time.
- **Simulation script (`simulate_flows.py`)**: Script to simulate network flow data for testing purposes.

## Requirements

To run this project, install the dependencies using:

```bash
pip install -r requirements.txt
```

You will also need a running MongoDB instance.

## Usage

1. Start the Flask server:
```bash
python server.py
```

2. Open `dashboard.html` in your web browser.

3. Run the packet sniffing agent (requires administrator/root privileges to sniff packets):
```bash
sudo python agent.py
```

## Note

Datasets (`*.csv`) and large environment directories like `venv` are ignored from version control by default.

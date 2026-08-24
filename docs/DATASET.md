# 📊 GarudaRush Dataset Guide

GarudaRush supports training on both **real-world intrusion detection benchmarks** and **on-the-fly synthetic flow datasets**.

---

## 1. CICIDS2017 Dataset

GarudaRush is pre-configured to load and train on the **CICIDS2017 (Canadian Institute for Cybersecurity)** benchmark dataset.

### Download Instructions

1. Download the official CICIDS2017 CSV dataset files from UNB:
   - [UNB CICIDS2017 Dataset Page](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Extract the CSV files into the root project directory:
   - `Monday-WorkingHours.pcap_ISCX.csv` (Benign baseline)
   - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (DDoS evaluation)
   - `Wednesday-workingHours.pcap_ISCX.csv` (DoS / DDoS flows)
   - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`

### Feature Extracted Columns

When CSV files are present in the directory, `ml_model.py` automatically extracts:
- `Flow Packets/s` & `Flow Bytes/s`
- `SYN Flag Count` & `ACK Flag Count`
- `Total Fwd Packets` & `Total Backward Packets`
- `Destination Port`
- `Label` (Mapped: `BENIGN` -> 0, Attack -> 1)

---

## 2. Synthetic Dataset Generator

If no CSV benchmark files are present, `ml_model.py` automatically falls back to an **in-memory synthetic flow generator**.

The synthetic engine uses statistical distributions matching real network telemetry:
- **SYN Flood**: Poisson packet rate ~8,000 pkts/s, high SYN/ACK ratio (>50), low source IP entropy.
- **UDP Flood**: High packet rate ~12,000 pkts/s, high byte rate (~5MB/s), high destination port spread.
- **ICMP Flood**: Continuous ICMP echo request bursts ~6,000 pkts/s.
- **HTTP Flood**: High HTTP request density (~2,500 reqs/s) targeting ports 80/443.

### Training the Model

```bash
# Train on synthetic data or automatically detected CSV files
python ml_model.py

# Run prediction sanity test after training
python ml_model.py --test
```

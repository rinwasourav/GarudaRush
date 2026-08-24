"""
GarudaRush ML Model Launcher
============================
Imports and runs the Random Forest DDoS detection model trainer/predictor.
"""
from src.model.ml_model import DDoSDetector, train, generate_dataset, FEATURE_COLUMNS, MODEL_PATH, SCALER_PATH

if __name__ == "__main__":
    import argparse
    import logging

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - [ML] - %(message)s")
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="DDoS RF Model Trainer")
    parser.add_argument("--test", action="store_true", help="Run quick prediction test after training")
    parser.add_argument("--n-normal", type=int, default=50000)
    parser.add_argument("--n-ddos", type=int, default=50000)
    args = parser.parse_args()

    model, scaler = train(args.n_normal, args.n_ddos)

    if args.test:
        detector = DDoSDetector()
        normal_flow = {
            "packet_rate": 180, "byte_rate": 45000, "syn_count": 12,
            "syn_ack_ratio": 1.1, "icmp_count": 3, "udp_count": 35,
            "tcp_count": 120, "fragment_count": 2, "http_requests": 20,
            "src_ip_entropy": 3.4, "top_destination_ports": {"80": 30, "443": 20},
        }
        ddos_flow = {
            "packet_rate": 9500, "byte_rate": 700_000, "syn_count": 6000,
            "syn_ack_ratio": 65, "icmp_count": 5, "udp_count": 10,
            "tcp_count": 8500, "fragment_count": 3, "http_requests": 5,
            "src_ip_entropy": 1.1, "top_destination_ports": {"80": 9000},
        }
        logger.info(f"Normal flow prediction: {detector.predict(normal_flow)}")
        logger.info(f"DDoS flood prediction:   {detector.predict(ddos_flow)}")

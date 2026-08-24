"""
GarudaRush Flask Server Launcher
================================
Main entry point for launching the central ingestion server and dashboard.
"""
from src.server.server import app, PORT

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, use_reloader=False, debug=False)

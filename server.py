"""
Traffic Analysis Server  —  Multi-Agent Edition
================================================
Central server for N distributed Traffic Miner agents.
Each agent registers on startup, sends heartbeats, and POSTs flow windows.
All data is tagged with agent_id and stored in MongoDB.
The GarudaRush dashboard is served at /.

Endpoints:
    POST /api/agents/register       – agent self-registration
    POST /api/agents/heartbeat      – agent liveness ping
    GET  /api/agents                – list all known agents + online status
    GET  /api/agents/<id>/stats     – per-agent aggregated stats (redirect)
    POST /api/flow                  – ingest a flow window (requires agent_id)
    GET  /api/flows?agent_id=       – paginated flows, optional filter by agent
    GET  /api/alerts?agent_id=      – recent DDoS alerts, optional filter
    GET  /api/stats?agent_id=       – aggregated stats (omit agent_id = global)
    GET  /api/flows/export?agent_id= – CSV export, optional filter
    GET  /api/health                – liveness / readiness probe

Environment variables:
    MONGO_URI    – MongoDB connection string  (default: mongodb://localhost:27017/)
    MODEL_PATH   – path to trained RF model   (default: ddos_rf_model.pkl)
    SCALER_PATH  – path to fitted scaler      (default: ddos_scaler.pkl)
    API_KEY      – shared secret; if set, all non-public endpoints require
                   the header  X-API-Key: <value>  (default: empty = disabled)
    PORT         – listening port             (default: 5000)
"""

import os
import time
import logging
import csv
import threading
from io import StringIO, BytesIO

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from pymongo import MongoClient, errors, DESCENDING

# ── ML model ──────────────────────────────────────────────────────
try:
    from ml_model import DDoSDetector
    _detector = DDoSDetector(
        model_path  = os.getenv("MODEL_PATH",  "ddos_rf_model.pkl"),
        scaler_path = os.getenv("SCALER_PATH", "ddos_scaler.pkl"),
    )
except ImportError:
    _detector = None
    logging.warning("ml_model.py not found — ML detection disabled.")

# ═══════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════
BASE_DIR           = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_FILE     = os.path.join(BASE_DIR, "dashboard.html")
MONGO_URI          = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME            = "traffic_data"
COL_FLOWS          = "features"
COL_ALERTS         = "ddos_alerts"
COL_AGENTS         = "agents"
PORT               = int(os.getenv("PORT", 5000))
AGENT_OFFLINE_SEC  = 60   # agent is "offline" if no heartbeat within this window
API_KEY            = os.getenv("API_KEY", "")   # FIX #1: shared secret

# Public endpoints that bypass key auth
_PUBLIC_PATHS = {"/", "/api/health"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [SERVER] - %(message)s")
logger = logging.getLogger(__name__)

if API_KEY:
    logger.info("API key authentication is ENABLED.")
else:
    logger.warning("API_KEY not set — server is running WITHOUT authentication.")

# ═══════════════════════════════════════════
# Flask
# ═══════════════════════════════════════════
app = Flask(__name__)
CORS(app)


# ═══════════════════════════════════════════
# FIX #1 — Authentication middleware
# ═══════════════════════════════════════════
@app.before_request
def check_api_key():
    """
    When API_KEY is configured, every non-public request must carry
    the header  X-API-Key: <key>.  Public paths (/ and /api/health)
    are always accessible so the dashboard and health-checks still work.
    """
    if not API_KEY:
        return  # auth disabled — let all requests through
    if request.path in _PUBLIC_PATHS:
        return  # public endpoint — no key needed
    if request.headers.get("X-API-Key") != API_KEY:
        logger.warning(
            f"Rejected unauthenticated request: {request.method} {request.path} "
            f"from {request.remote_addr}"
        )
        return jsonify({"error": "Unauthorized — missing or invalid X-API-Key"}), 401


# ═══════════════════════════════════════════
# Thread-safe MongoDB
# ═══════════════════════════════════════════
_db_lock = threading.Lock()
_client  = None
_flows   = None
_alerts  = None
_agents  = None


def get_db():
    """
    Lazy-init MongoDB connection.
    Returns (flows, alerts, agents) collections — any may be None on failure.
    """
    global _client, _flows, _alerts, _agents
    with _db_lock:
        try:
            if _client is None:
                _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
                _client.admin.command("ping")
                db      = _client[DB_NAME]
                _flows  = db[COL_FLOWS]
                _alerts = db[COL_ALERTS]
                _agents = db[COL_AGENTS]
                # Compound indexes for fast agent-scoped queries
                _flows.create_index([("timestamp", DESCENDING)])
                _flows.create_index([("agent_id", 1), ("timestamp", DESCENDING)])
                # FIX #9: index DDoS flag so per-agent ddos counts are fast
                _flows.create_index([("agent_id", 1), ("ml_prediction.is_ddos", 1)])
                _alerts.create_index([("timestamp", DESCENDING)])
                _alerts.create_index([("agent_id", 1), ("timestamp", DESCENDING)])
                _agents.create_index("agent_id", unique=True)
                logger.info("MongoDB connected and indexes ensured")
            else:
                _client.admin.command("ping")
            return _flows, _alerts, _agents
        except errors.PyMongoError as e:
            logger.error(f"DB error: {e}")
            _client = _flows = _alerts = _agents = None
            return None, None, None


# ═══════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════
def _agent_filter(req):
    """Return a MongoDB filter dict from ?agent_id= query param (may be empty)."""
    aid = req.args.get("agent_id", "").strip()
    return {"agent_id": aid} if aid else {}


def _is_online(agent_doc: dict) -> bool:
    return (time.time() - agent_doc.get("last_seen", 0)) < AGENT_OFFLINE_SEC


def _enrich_agent(doc: dict) -> dict:
    """Add computed online status + seconds-since-last-seen to an agent document."""
    doc = {k: v for k, v in doc.items() if k != "_id"}
    doc["online"]        = _is_online(doc)
    doc["last_seen_ago"] = round(time.time() - doc.get("last_seen", 0))
    return doc


def _compute_threat(ddos_events: int, total_flows: int) -> str:
    ratio = ddos_events / total_flows if total_flows else 0
    if ratio > 0.5:
        return "critical"
    if ratio > 0.2:
        return "high"
    if ratio > 0.05:
        return "medium"
    return "low"


# ═══════════════════════════════════════════
# Routes — Static
# ═══════════════════════════════════════════

@app.route("/", methods=["GET"])
def index():
    if os.path.exists(DASHBOARD_FILE):
        return send_file(DASHBOARD_FILE)
    return jsonify({"error": f"dashboard.html not found at {DASHBOARD_FILE}"}), 404


@app.route("/api/health", methods=["GET"])
def health():
    flows, _, agents = get_db()
    db_ok = flows is not None
    ml_ok = bool(_detector and _detector.is_ready())
    online_agents = 0
    if agents is not None:
        try:
            online_agents = agents.count_documents(
                {"last_seen": {"$gte": time.time() - AGENT_OFFLINE_SEC}}
            )
        except Exception:
            pass
    return jsonify({
        "status":        "ok" if db_ok else "down",
        "ml_model":      "ready" if ml_ok else "unavailable",
        "online_agents": online_agents,
        "timestamp":     time.time(),
    }), 200 if db_ok else 503


# ═══════════════════════════════════════════
# Routes — Agent Management
# ═══════════════════════════════════════════

@app.route("/api/agents/register", methods=["POST"])
def register_agent():
    """
    Called by each agent on startup.
    Upserts the agent record — preserves registered_at on re-registration.
    """
    _, _, agents = get_db()
    if agents is None:
        return jsonify({"error": "Database unavailable"}), 503

    data = request.get_json()
    if not data or not data.get("agent_id"):
        return jsonify({"error": "agent_id required"}), 400

    now = time.time()
    agents.update_one(
        {"agent_id": data["agent_id"]},
        {
            "$set": {
                "agent_id":       data["agent_id"],
                "agent_location": data.get("agent_location", data["agent_id"]),
                "interface":      data.get("interface", "unknown"),
                "hostname":       data.get("hostname", ""),
                "window_size":    data.get("window_size", 5),
                "last_seen":      now,
                "online":         True,
            },
            # registered_at is only written once — on first insert
            "$setOnInsert": {
                "registered_at": now,
            },
        },
        upsert=True,
    )
    logger.info(f"Agent registered: {data['agent_id']} @ {data.get('agent_location')}")
    return jsonify({"status": "registered", "agent_id": data["agent_id"]}), 200


@app.route("/api/agents/heartbeat", methods=["POST"])
def agent_heartbeat():
    """Update last_seen timestamp for a live agent."""
    _, _, agents = get_db()
    if agents is None:
        return jsonify({"error": "Database unavailable"}), 503

    data = request.get_json()
    if not data or not data.get("agent_id"):
        return jsonify({"error": "agent_id required"}), 400

    agents.update_one(
        {"agent_id": data["agent_id"]},
        {"$set": {"last_seen": time.time(), "online": True}},
        upsert=True,
    )
    return jsonify({"status": "ok"}), 200


@app.route("/api/agents", methods=["GET"])
def list_agents():
    """List all known agents with computed online status and DDoS event counts."""
    flows, alerts, agents = get_db()
    if agents is None:
        return jsonify({"error": "Database unavailable"}), 503

    try:
        docs = [_enrich_agent(d) for d in agents.find({}, {"_id": 0})]

        # Attach per-agent DDoS event count and threat level
        if flows is not None:
            for doc in docs:
                aid = doc["agent_id"]
                doc["total_flows"] = flows.count_documents({"agent_id": aid})
                doc["ddos_events"] = flows.count_documents(
                    {"agent_id": aid, "ml_prediction.is_ddos": True}
                )
                doc["threat_level"] = _compute_threat(
                    doc["ddos_events"], doc["total_flows"]
                )

        total_online = sum(1 for d in docs if d["online"])
        return jsonify({"agents": docs, "total": len(docs), "online": total_online}), 200

    except Exception as e:
        logger.error(f"list_agents error: {e}", exc_info=True)
        return jsonify({"error": "Failed to list agents"}), 500


# ═══════════════════════════════════════════
# Routes — Flow Ingestion
# ═══════════════════════════════════════════

@app.route("/api/flow", methods=["POST"])
def store_flow():
    """
    Ingest a flow window from an agent.
    Required body fields: agent_id, packet_count, byte_count, duration
    """
    flows, alerts, agents = get_db()
    if flows is None:
        return jsonify({"error": "Database unavailable"}), 503

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    required = ["agent_id", "packet_count", "byte_count", "duration"]
    missing  = [k for k in required if k not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    data["timestamp"] = time.time()

    # ── ML Prediction ─────────────────────────────────────────────
    ml_result = {"is_ddos": False, "confidence": 0.0, "attack_type": "none"}
    if _detector and _detector.is_ready():
        try:
            ml_result = _detector.predict(data)
            data["ml_prediction"] = ml_result
            if ml_result["is_ddos"]:
                logger.warning(
                    f"⚠ DDoS [{data['agent_id']}]  "
                    f"type={ml_result['attack_type']}  "
                    f"conf={ml_result['confidence']:.2%}  "
                    f"pkt/s={data.get('packet_rate', 0):.0f}"
                )
        except Exception as e:
            logger.error(f"ML predict error: {e}", exc_info=True)
            data["ml_prediction"] = {"error": str(e)}
    else:
        data["ml_prediction"] = {"status": "model_unavailable"}

    # ── Store Flow ────────────────────────────────────────────────
    # FIX #2: insert a shallow copy so insert_one's _id injection does
    # not mutate the original `data` dict (avoids ObjectId leaking into
    # later log statements or the ml_result response).
    try:
        flows.insert_one({**data})
    except Exception as e:
        logger.error(f"Flow insert failed: {e}")
        return jsonify({"error": "DB write failed"}), 500

    # ── Store Alert ───────────────────────────────────────────────
    if ml_result.get("is_ddos") and alerts is not None:
        try:
            alerts.insert_one({
                "timestamp":      data["timestamp"],
                "agent_id":       data["agent_id"],
                "agent_location": data.get("agent_location", ""),
                "attack_type":    ml_result["attack_type"],
                "confidence":     ml_result["confidence"],
                "packet_rate":    data.get("packet_rate",    0),
                "byte_rate":      data.get("byte_rate",      0),
                "syn_count":      data.get("syn_count",      0),
                "src_ip_entropy": data.get("src_ip_entropy", 0),
                "features":       ml_result.get("features", {}),
            })
        except Exception as e:
            logger.warning(f"Alert insert failed: {e}")

    # ── Update agent last_seen ────────────────────────────────────
    if agents is not None:
        try:
            agents.update_one(
                {"agent_id": data["agent_id"]},
                {"$set": {"last_seen": data["timestamp"]}},
            )
        except Exception:
            pass

    return jsonify({"status": "saved", "ml_prediction": ml_result}), 200


# ═══════════════════════════════════════════
# Routes — Queries
# ═══════════════════════════════════════════

@app.route("/api/flows", methods=["GET"])
def view_flows():
    """Paginated flows. Optional ?agent_id= to filter."""
    flows, _, _ = get_db()
    if flows is None:
        return jsonify({"error": "Database unavailable"}), 503

    try:
        page  = max(request.args.get("page",  1,  type=int), 1)
        limit = min(request.args.get("limit", 20, type=int), 100)
        skip  = (page - 1) * limit
        filt  = _agent_filter(request)

        docs  = list(
            flows.find(filt, {"_id": 0})
                 .sort("timestamp", DESCENDING)
                 .skip(skip)
                 .limit(limit)
        )
        total = flows.count_documents(filt)

        return jsonify({"flows": docs, "total": total, "page": page, "limit": limit}), 200

    except Exception as e:
        logger.error(f"view_flows error: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve flows"}), 500


@app.route("/api/alerts", methods=["GET"])
def view_alerts():
    """Recent DDoS alerts. Optional ?agent_id= to filter."""
    _, alert_col, _ = get_db()
    if alert_col is None:
        return jsonify({"error": "Database unavailable"}), 503

    try:
        limit = min(request.args.get("limit", 50, type=int), 500)
        filt  = _agent_filter(request)

        docs  = list(
            alert_col.find(filt, {"_id": 0})
                      .sort("timestamp", DESCENDING)
                      .limit(limit)
        )
        total = alert_col.count_documents(filt)

        return jsonify({"alerts": docs, "total": total}), 200

    except Exception as e:
        logger.error(f"view_alerts error: {e}", exc_info=True)
        return jsonify({"error": "Failed to retrieve alerts"}), 500


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Aggregated stats. Pass ?agent_id= for per-agent stats, omit for global."""
    flows, alert_col, agent_col = get_db()
    if flows is None:
        return jsonify({"error": "Database unavailable"}), 503

    try:
        filt = _agent_filter(request)

        # Traffic aggregates
        traffic = list(flows.aggregate([
            {"$match": filt},
            {"$group": {
                "_id":             None,
                "total_packets":   {"$sum": "$packet_count"},
                "total_bytes":     {"$sum": "$byte_count"},
                "avg_packet_rate": {"$avg": "$packet_rate"},
                "avg_byte_rate":   {"$avg": "$byte_rate"},
                "max_syn_count":   {"$max": "$syn_count"},
            }}
        ]))
        base = {k: v for k, v in (traffic[0] if traffic else {}).items() if k != "_id"}

        # DDoS by type
        ddos_agg = list(flows.aggregate([
            {"$match": {**filt, "ml_prediction.is_ddos": True}},
            {"$group": {
                "_id":            "$ml_prediction.attack_type",
                "count":          {"$sum": 1},
                "avg_confidence": {"$avg": "$ml_prediction.confidence"},
            }},
        ]))
        ddos_by_type = {
            d["_id"]: {"count": d["count"], "avg_confidence": round(d["avg_confidence"], 4)}
            for d in ddos_agg if d["_id"]
        }

        total_ddos   = sum(v["count"] for v in ddos_by_type.values())
        total_alerts = alert_col.count_documents(filt) if alert_col is not None else 0
        total_flows  = flows.count_documents(filt)

        # Per-agent breakdown (global view only)
        agent_breakdown = []
        if not filt and agent_col is not None:
            for adoc in agent_col.find({}, {"_id": 0}):
                aid    = adoc["agent_id"]
                af     = {"agent_id": aid}
                aflows = flows.count_documents(af)
                addos  = flows.count_documents({**af, "ml_prediction.is_ddos": True})
                agent_breakdown.append({
                    "agent_id":       aid,
                    "agent_location": adoc.get("agent_location", aid),
                    "online":         _is_online(adoc),
                    "total_flows":    aflows,
                    "ddos_events":    addos,
                    "threat_level":   _compute_threat(addos, aflows),
                })

        return jsonify({
            **base,
            "total_flows":        total_flows,
            "total_ddos_events":  total_ddos,
            "ddos_by_type":       ddos_by_type,
            "total_alerts_saved": total_alerts,
            "ml_model_ready":     bool(_detector and _detector.is_ready()),
            "agent_breakdown":    agent_breakdown,
        }), 200

    except Exception as e:
        logger.error(f"get_stats error: {e}", exc_info=True)
        return jsonify({"error": "Failed to compute stats"}), 500


@app.route("/api/agents/<agent_id>/stats", methods=["GET"])
def agent_stats(agent_id: str):
    """Convenience wrapper — redirects to /api/stats?agent_id=<id>."""
    from flask import redirect, url_for
    return redirect(url_for("get_stats", agent_id=agent_id))


# ═══════════════════════════════════════════
# Routes — Export
# ═══════════════════════════════════════════

@app.route("/api/flows/export", methods=["GET"])
def export_flows():
    """Export up to 1000 flow records as CSV. Optional ?agent_id= filter."""
    flows, _, _ = get_db()
    if flows is None:
        return jsonify({"error": "Database unavailable"}), 503

    try:
        filt = _agent_filter(request)
        docs = list(
            flows.find(filt, {"_id": 0})
                 .sort("timestamp", DESCENDING)
                 .limit(1000)
        )
        if not docs:
            return jsonify({"message": "No flows to export"}), 204

        flat = []
        for f in docs:
            row = {
                k: v for k, v in f.items()
                if k not in ("ml_prediction", "icmp_type_distribution", "top_destination_ports")
            }
            pred = f.get("ml_prediction", {})
            row["ml_is_ddos"]     = pred.get("is_ddos",     "")
            row["ml_confidence"]  = pred.get("confidence",  "")
            row["ml_attack_type"] = pred.get("attack_type", "")
            flat.append(row)

        out = StringIO()
        w   = csv.DictWriter(out, fieldnames=flat[0].keys())
        w.writeheader()
        w.writerows(flat)

        fname = f"flows_{request.args.get('agent_id', 'all')}.csv"
        return send_file(
            BytesIO(out.getvalue().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name=fname,
        )

    except Exception as e:
        logger.error(f"export_flows error: {e}", exc_info=True)
        return jsonify({"error": "Export failed"}), 500


# ═══════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, use_reloader=False, debug=False)

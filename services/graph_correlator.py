"""
Guardient Graph Correlator Service
====================================
Consumes : risk_scores
Publishes: graph_scores

Attack Graph Engine — detects lateral movement by correlating anomalies
across multiple devices into attack chains.

Graph model
-----------
  Nodes : device_id  (keyed by device_id string)
  Edges : directed edge A → B when an event at A carries a signal that
          references or implies access to B (ssh, login, privilege_escalation,
          process_injection, rdp, lateral_move).

Edge signals extracted from:
  • detection type  (e.g. 'ssh_activity', 'privilege_escalation')
  • event_type      (e.g. 'login', 'rdp_session', 'process_spawn')
  • anomaly_reasons (any string containing 'ssh', 'rdp', 'login', etc.)

Algorithm
---------
  1. When a risk event arrives for device D with risk_score > RISK_THRESHOLD:
       a. Add/refresh D as a node with its current risk_score + timestamp.
       b. Infer any implied edge targets from signals (best-effort).
       c. DFS from D to find the longest path through nodes that are
          *also* actively anomalous (last_seen < STALE_WINDOW seconds ago
          AND risk_score > RISK_THRESHOLD).
  2. Compute graph_caf = 1 + γ × path_length   (γ = 0.3)
  3. Publish the enriched event to graph_scores.

Math
----
  CAF_graph = 1 + 0.3 × attack_path_length

  path_length = 0 → CAF_graph = 1.00  (no chain, no amplification)
  path_length = 1 → CAF_graph = 1.30  (one hop)
  path_length = 3 → CAF_graph = 1.90  (phishing → server → DC)
  path_length = 6 → CAF_graph = 2.80  (full kill-chain)
"""

from __future__ import annotations
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.producer import publish_event
from pipeline.consumer import BaseConsumer
from pipeline.topics  import RISK_SCORES, GRAPH_SCORES
from db.db import insert_graph_event

# ── Tuning ──────────────────────────────────────────────────────────────────
GAMMA          = 0.3    # CAF amplification factor per hop
RISK_THRESHOLD = 20     # Minimum risk_score for a node to count as "active"
STALE_WINDOW   = 600    # Seconds — nodes older than this are dormant (10 min)
MAX_GRAPH_SIZE = 500    # Max nodes kept in memory (LRU-style cap)
MAX_DFS_DEPTH  = 10     # DFS depth limiter to prevent infinite loops

# Edge-implying detection types / event patterns (source → type of lateral move)
LATERAL_SIGNALS: set[str] = {
    "ssh_activity", "rdp", "login", "credential_stuffing",
    "brute_force", "privilege_escalation", "process_injection",
    "lateral_move", "login_anomaly", "login_failure",
}


# ── In-memory Attack Graph ───────────────────────────────────────────────────

class AttackGraph:
    """
    Lightweight directed adjacency graph of device nodes.

    node_data[device_id] = {
        "risk_score": int,
        "last_seen":  float (unix timestamp),
        "detection":  str,
    }
    edges[src_id] = set of dst_id strings
    """

    def __init__(self):
        self.node_data: dict[str, dict] = {}
        self.edges: dict[str, set[str]] = defaultdict(set)
        # FIFO for LRU cap
        self._order: deque[str] = deque()

    def _evict(self):
        """Remove oldest node if graph exceeds MAX_GRAPH_SIZE."""
        while len(self.node_data) > MAX_GRAPH_SIZE:
            old = self._order.popleft()
            self.node_data.pop(old, None)
            self.edges.pop(old, None)
            # Also remove any edges pointing to old
            for s in list(self.edges):
                self.edges[s].discard(old)

    def upsert_node(self, device_id: str, risk_score: int, detection: str):
        if device_id not in self.node_data:
            self._order.append(device_id)
        self.node_data[device_id] = {
            "risk_score": risk_score,
            "last_seen":  time.time(),
            "detection":  detection,
        }
        self._evict()

    def add_edge(self, src: str, dst: str):
        """Add a directed edge src → dst (lateral movement path)."""
        if src != dst and src in self.node_data:
            self.edges[src].add(dst)

    def is_active(self, device_id: str) -> bool:
        node = self.node_data.get(device_id)
        if node is None:
            return False
        age = time.time() - node["last_seen"]
        return node["risk_score"] >= RISK_THRESHOLD and age <= STALE_WINDOW

    def longest_attack_path(self, start: str) -> list[str]:
        """
        DFS to find the longest active path starting from `start`.
        Returns the ordered list of device_ids in the path.
        """
        best: list[str] = [start]

        def dfs(node: str, visited: set, path: list):
            nonlocal best
            if len(path) > len(best):
                best = list(path)
            if len(path) >= MAX_DFS_DEPTH:
                return
            for neighbor in self.edges.get(node, set()):
                if neighbor not in visited and self.is_active(neighbor):
                    visited.add(neighbor)
                    path.append(neighbor)
                    dfs(neighbor, visited, path)
                    path.pop()
                    visited.discard(neighbor)

        dfs(start, {start}, [start])
        return best


# Singleton graph instance shared by TrustEngine consumer calls
_GRAPH = AttackGraph()


# ── Signal parsers ───────────────────────────────────────────────────────────

def _extract_lateral_targets(event: dict) -> list[str]:
    """
    Best-effort extraction of implied edge targets.

    Strategy: look for device_ids in enrichment or features that appear
    as peer references. In practice the current pipeline does not carry
    explicit dst_device_id fields, so we rely on ip-to-device cross-reference
    via enrichment.  For now we emit edges when:
      a) The detection is a lateral-move signal AND
      b) A destination IP is present (future: resolved to device_id via registry)

    Returns a list of candidate device_id strings (may be empty).
    """
    targets: list[str] = []
    detection   = event.get("detection", "")
    event_type  = str(event.get("event_type", "")).lower()
    reasons     = event.get("anomaly_reasons", [])

    is_lateral = (
        detection in LATERAL_SIGNALS
        or any(sig in event_type for sig in ("ssh", "rdp", "login", "lateral"))
        or any(sig in str(r).lower() for r in reasons for sig in ("ssh", "rdp", "login"))
    )

    if is_lateral:
        # If there's an explicit peer device_id hint, use it
        peer = (
            event.get("enrichment", {}).get("peer_device_id")
            or event.get("features", {}).get("peer_device_id")
        )
        if peer:
            targets.append(str(peer))

        # Fallback: destination IP as a proxy edge (best-effort)
        dst_ip = (
            event.get("enrichment", {}).get("dest_ip")
            or event.get("features", {}).get("destination_ip")
            or event.get("ip")
        )
        if dst_ip and dst_ip != event.get("ip"):
            # Use IP as a pseudo node-id — will create a provisional node
            targets.append(f"ip:{dst_ip}")

    return targets


# ── Kafka Consumer ────────────────────────────────────────────────────────────

class GraphCorrelator(BaseConsumer):
    """
    Consumes risk_scores, enriches each event with lateral-movement
    graph analysis, and publishes to graph_scores.
    """
    topic        = RISK_SCORES
    group_id     = "graph-correlator-v1"
    service_name = "GraphCorrelator"

    def process(self, event: dict):
        device_id  = str(event.get("device_id", "unknown"))
        risk_score = int(event.get("risk_score", 0))
        detection  = event.get("detection", "behavior_anomaly")
        timestamp  = event.get("timestamp") or datetime.now(tz=timezone.utc).isoformat()

        # 1. Upsert this device as a graph node
        _GRAPH.upsert_node(device_id, risk_score, detection)

        # 2. Infer lateral movement edges
        targets = _extract_lateral_targets(event)
        for t in targets:
            # Register target as a provisional node if unknown
            if t not in _GRAPH.node_data:
                _GRAPH.upsert_node(t, RISK_THRESHOLD, "lateral_target")
            _GRAPH.add_edge(device_id, t)

        # 3. DFS to find longest attack chain through active nodes
        attack_path  = _GRAPH.longest_attack_path(device_id)
        path_length  = len(attack_path) - 1   # hops (0 = isolated event)
        graph_caf    = round(1.0 + GAMMA * path_length, 4)

        # 4. Build and publish the enriched graph event
        graph_event = {
            **event,                          # carry all risk_engine fields
            "graph_caf":    graph_caf,
            "attack_path":  attack_path,
            "path_length":  path_length,
        }
        publish_event(GRAPH_SCORES, graph_event)

        # 5. Persist to DB (non-critical)
        try:
            insert_graph_event({
                "event_id":    event.get("event_id"),
                "device_id":   device_id,
                "timestamp":   timestamp,
                "attack_path": attack_path,
                "path_length": path_length,
                "graph_caf":   graph_caf,
                "risk_score":  risk_score,
            })
        except Exception as exc:
            print(f"[Graph] DB write skipped: {exc}")

        # Console output
        if path_length > 0:
            chain_str = " → ".join(str(n)[:12] for n in attack_path)
            icon = "🔗" if path_length == 1 else "⛓️ " if path_length == 2 else "🚨"
            print(
                f"[Graph] {icon} CHAIN DETECTED | path={path_length} hops "
                f"| CAF={graph_caf:.2f} | {chain_str}"
            )
        else:
            print(
                f"[Graph] ○  isolated | risk={risk_score:3d} "
                f"| {detection[:30]:30s} | {device_id[:16]}"
            )


if __name__ == "__main__":
    print("=" * 70)
    print("  Guardient Graph Correlator — Lateral Movement Detection")
    print("=" * 70)
    print(f"  Consuming : risk_scores")
    print(f"  Publishing: graph_scores")
    print(f"  CAF_graph  = 1 + {GAMMA} × attack_path_length")
    print(f"  Active window: {STALE_WINDOW}s | Risk threshold: {RISK_THRESHOLD}")
    print("=" * 70 + "\n")
    GraphCorrelator().run()

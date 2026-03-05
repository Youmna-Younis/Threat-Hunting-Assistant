"""
astar.py - A* Search over the security event graph.

A* extends UCS by adding a heuristic h(n) that estimates the remaining
cost to reach a goal.  The heap is sorted by f(n) = g(n) + h(n) instead
of just g(n).  A good heuristic guides the search toward the goal early,
reducing the number of nodes expanded vs plain UCS.

ADMISSIBILITY: both heuristics provided here never overestimate the true
remaining cost, so A* is guaranteed to find an optimal path.

Two built-in heuristics:
  - suspiciousness  : assign lower h to "more suspicious" nodes so they are
                      explored first.  Suspicious node types get h=0 (free to
                      expand), less suspicious nodes cost more.
  - hop_count       : estimate remaining hops via a BFS pre-computation.
                      Multiplied by the minimum possible edge cost (1) so
                      it remains admissible.

Trace output shows both g(n) and h(n) components for each heap pop.
"""

import heapq
from collections import deque
from typing import List, Optional, Callable
from src.graph.graph_store import GraphStore


# ── Heuristic functions ───────────────────────────────────────────────────────

def heuristic_suspiciousness(node_id: str, goal_set: set, graph: GraphStore) -> float:
    """
    Returns a LOW value for suspicious nodes (we want to explore them FIRST).

    Admissibility: minimum real edge cost is 1 (SPAWNED / READ_FILE / DELETED).
    We never return a value greater than 1 for non-goal nodes so we never
    overestimate the true remaining cost of at least 1 hop.

    Suspicious indicators get h=0 so the f-score equals g(n) – same priority
    as UCS – which is safe (UCS is already optimal).
    """
    if node_id in goal_set:
        return 0.0   # at goal – no remaining cost

    node = graph.get_node(node_id)
    if node is None:
        return 1.0

    name_lower = node.name.lower()

    # Suspicious process names → explore eagerly
    suspicious_procs = ["powershell", "cmd", "wscript", "cscript", "mshta", "nc", "ncat"]
    if node.type == "process" and any(p in name_lower for p in suspicious_procs):
        return 0.0   # treat as if goal is one free hop away

    # Executable files are high-risk
    if node.type == "file" and name_lower.endswith(".exe"):
        return 0.0

    # External network connections
    if node.type == "network":
        return 0.0

    return 1.0   # generic estimate: at least 1 more hop


def heuristic_hop_count(node_id: str, goal_set: set, graph: GraphStore) -> float:
    """
    Estimate remaining distance to any goal using a quick BFS from *node_id*.

    Multiplied by 1 (minimum edge cost) → admissible.
    Returns 0 if node_id is already a goal.

    Note: this BFS is bounded to depth 20 for performance; nodes beyond that
    return h=0 (conservative / admissible).
    """
    if node_id in goal_set:
        return 0.0

    # Mini-BFS to find shortest hop distance to nearest goal
    visited: set[str] = {node_id}
    queue: deque      = deque([(node_id, 0)])

    while queue:
        current, depth = queue.popleft()
        if depth > 20:
            return 0.0   # give up – conservative fallback

        for edge in graph.get_outgoing_edges(current):
            nid = edge.target_id
            if nid in goal_set:
                return float(depth + 1)  # found – distance is depth+1 hops
            if nid not in visited:
                visited.add(nid)
                queue.append((nid, depth + 1))

    return 0.0   # goal not reachable from here – admissible to return 0


# ── A* core ───────────────────────────────────────────────────────────────────

DEFAULT_COST_CONFIG: dict[str, float] = {
    "SPAWNED":              1.0,
    "LOGGED_INTO":          2.0,
    "READ_FILE":            1.0,
    "WROTE_TO":             3.0,
    "CONNECTED_TO":         5.0,
    "DOWNLOADED":           4.0,
    "DELETED":              1.0,
    "MODIFIED_PERMISSIONS": 3.0,
}

HEURISTICS = {
    "suspiciousness": heuristic_suspiciousness,
    "hop_count":      heuristic_hop_count,
}


def astar_find_path(
    graph: GraphStore,
    start_node_id: str,
    goal_node_ids: List[str],
    cost_config: Optional[dict] = None,
    heuristic: str = "suspiciousness",
    trace: bool = True,
) -> dict:
    """
    A* search from *start_node_id* to the cheapest-to-reach goal.

    Parameters
    ----------
    graph         : Populated GraphStore.
    start_node_id : Source node ID.
    goal_node_ids : List of acceptable goal node IDs.
    cost_config   : Edge cost table.  Defaults to DEFAULT_COST_CONFIG.
    heuristic     : Name of heuristic to use ("suspiciousness" | "hop_count").
    trace         : Print heap operations when True.

    Returns
    -------
    dict with keys:
      path           – list of node IDs from start to goal
      total_cost     – g(n) of the goal node
      nodes_explored – heap pops (lower = more efficient than UCS)
      path_found     – bool
      heuristic_used – name of the heuristic function
    """

    costs    = cost_config if cost_config else DEFAULT_COST_CONFIG
    goal_set = set(goal_node_ids)
    h_fn: Callable = HEURISTICS.get(heuristic, heuristic_suspiciousness)

    # ── Validate ─────────────────────────────────────────────────────
    if graph.get_node(start_node_id) is None:
        print(f"[A*] ERROR: start node '{start_node_id}' not found.")
        return {"path": [], "total_cost": 0, "nodes_explored": 0,
                "path_found": False, "heuristic_used": heuristic}

    if trace:
        print(f"\n{'='*60}")
        print(f"[A*] Start     : {graph.get_node(start_node_id)}")
        print(f"[A*] Goals     : {goal_node_ids}")
        print(f"[A*] Heuristic : {heuristic}")
        print(f"{'='*60}")

    # ── Priority queue ────────────────────────────────────────────────
    # Entry: (f_score, tie_break, node_id, g_score, path)
    counter  = 0
    h_start  = h_fn(start_node_id, goal_set, graph)
    heap: list = [(h_start, counter, start_node_id, 0.0, [start_node_id])]

    best_g: dict[str, float] = {start_node_id: 0.0}
    nodes_explored = 0

    # ── Main A* loop ──────────────────────────────────────────────────
    while heap:
        f, _, current_id, g, path = heapq.heappop(heap)
        nodes_explored += 1

        current_node = graph.get_node(current_id)
        h = f - g   # recover h from f = g + h

        if trace:
            print(f"  [pop]  f={f:.2f}  g={g:.2f}  h={h:.2f}  node={current_node}")

        # ── Goal test ─────────────────────────────────────────────────
        if current_id in goal_set:
            if trace:
                print(f"\n[A*] ★ GOAL: {current_node}  g={g:.2f}  nodes_explored={nodes_explored}")
            return {
                "path":           path,
                "total_cost":     g,
                "nodes_explored": nodes_explored,
                "path_found":     True,
                "heuristic_used": heuristic,
            }

        # ── Stale entry check ─────────────────────────────────────────
        if g > best_g.get(current_id, float("inf")):
            if trace:
                print(f"         ↩ stale, skip")
            continue

        # ── Expand neighbours ─────────────────────────────────────────
        for edge in graph.get_outgoing_edges(current_id):
            neighbor_id = edge.target_id
            edge_cost   = costs.get(edge.action, 1.0)
            new_g       = g + edge_cost
            new_h       = h_fn(neighbor_id, goal_set, graph)
            new_f       = new_g + new_h

            if new_g < best_g.get(neighbor_id, float("inf")):
                best_g[neighbor_id] = new_g
                counter += 1
                new_path = path + [neighbor_id]

                if trace:
                    neighbor = graph.get_node(neighbor_id)
                    print(f"         → push [{edge.action}] {neighbor}  "
                          f"g={new_g:.1f}  h={new_h:.2f}  f={new_f:.2f}")

                heapq.heappush(heap, (new_f, counter, neighbor_id, new_g, new_path))

    if trace:
        print(f"\n[A*] No path found.  Nodes explored: {nodes_explored}")

    return {"path": [], "total_cost": 0, "nodes_explored": nodes_explored,
            "path_found": False, "heuristic_used": heuristic}

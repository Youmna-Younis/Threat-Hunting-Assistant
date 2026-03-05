"""
ucs.py - Uniform Cost Search over the security event graph.

UCS always expands the node with the *lowest cumulative path cost* first.
This is Dijkstra's algorithm restricted to a single goal (or earliest-found
among multiple goals).  In threat hunting the cost of each edge represents
the suspiciousness / risk of that relationship type (e.g., CONNECTED_TO is
more suspicious than READ_FILE).

A min-heap (priority queue) keeps track of the frontier sorted by g(n)
(cost from start to n).

Trace output shows each node popped from the heap so you can see why UCS
always returns the optimal-cost path.
"""

import heapq
from typing import List, Optional
from src.graph.graph_store import GraphStore


# Default cost table – can be overridden per query call.
DEFAULT_COST_CONFIG: dict[str, float] = {
    "SPAWNED":             1.0,
    "LOGGED_INTO":         2.0,
    "READ_FILE":           1.0,
    "WROTE_TO":            3.0,
    "CONNECTED_TO":        5.0,
    "DOWNLOADED":          4.0,
    "DELETED":             1.0,
    "MODIFIED_PERMISSIONS": 3.0,
}


def ucs_find_cheapest_path(
    graph: GraphStore,
    start_node_id: str,
    goal_node_ids: List[str],
    cost_config: Optional[dict] = None,
    trace: bool = True,
) -> dict:
    """
    Find the minimum-cost path from *start_node_id* to the nearest goal node.

    The algorithm pops the cheapest frontier entry from a min-heap.
    Once a goal node is popped (meaning we've committed to the cheapest
    path to it) we stop and return that path.

    Parameters
    ----------
    graph         : Populated GraphStore.
    start_node_id : Source node ID.
    goal_node_ids : One or more target node IDs.  First cheapest reached wins.
    cost_config   : Dict mapping action verb -> cost.  Defaults to DEFAULT_COST_CONFIG.
    trace         : Print heap operations when True.

    Returns
    -------
    dict with keys:
      path           – list of node IDs from start to goal (empty if not found)
      total_cost     – accumulated cost along the path
      nodes_explored – number of nodes popped from the heap
      path_found     – True if any goal was reachable
    """

    costs = cost_config if cost_config else DEFAULT_COST_CONFIG
    goal_set = set(goal_node_ids)

    # ── Validate ─────────────────────────────────────────────────────
    if graph.get_node(start_node_id) is None:
        print(f"[UCS] ERROR: start node '{start_node_id}' not found.")
        return {"path": [], "total_cost": 0, "nodes_explored": 0, "path_found": False}

    if trace:
        print(f"\n{'='*60}")
        print(f"[UCS] Start : {graph.get_node(start_node_id)}")
        print(f"[UCS] Goals : {goal_node_ids}")
        print(f"{'='*60}")

    # ── Priority queue ────────────────────────────────────────────────
    # Each entry: (cumulative_cost, tie_break_counter, node_id, path_list)
    # tie_break_counter keeps the heap consistent when costs are equal.
    counter = 0
    heap: list = [(0.0, counter, start_node_id, [start_node_id])]

    # Best known cost to reach each node (prevents re-expanding with worse cost)
    best_cost: dict[str, float] = {start_node_id: 0.0}

    nodes_explored = 0

    # ── Main UCS loop ──────────────────────────────────────────────────
    while heap:
        g, _, current_id, path = heapq.heappop(heap)
        nodes_explored += 1

        current_node = graph.get_node(current_id)

        if trace:
            print(f"  [pop]  cost={g:.1f}  node={current_node}  path_len={len(path)}")

        # ── Goal test ─────────────────────────────────────────────────
        if current_id in goal_set:
            if trace:
                print(f"\n[UCS] ★ GOAL REACHED: {current_node}  total cost={g:.1f}")
                print(f"[UCS] Nodes explored: {nodes_explored}")
            return {
                "path":           path,
                "total_cost":     g,
                "nodes_explored": nodes_explored,
                "path_found":     True,
            }

        # ── Stale entry check ─────────────────────────────────────────
        # If we already found a cheaper way to this node, skip this entry.
        if g > best_cost.get(current_id, float("inf")):
            if trace:
                print(f"         ↩ stale entry (better cost already recorded), skip")
            continue

        # ── Expand neighbours ─────────────────────────────────────────
        for edge in graph.get_outgoing_edges(current_id):
            neighbor_id = edge.target_id
            edge_cost   = costs.get(edge.action, 1.0)   # default cost = 1 for unknown actions
            new_cost    = g + edge_cost

            if new_cost < best_cost.get(neighbor_id, float("inf")):
                best_cost[neighbor_id] = new_cost
                counter += 1
                new_path = path + [neighbor_id]

                if trace:
                    neighbor = graph.get_node(neighbor_id)
                    print(f"         → push [{edge.action}, cost={edge_cost}] "
                          f"{neighbor}  cumulative={new_cost:.1f}")

                heapq.heappush(heap, (new_cost, counter, neighbor_id, new_path))

    if trace:
        print(f"\n[UCS] No path found to any goal.  Nodes explored: {nodes_explored}")

    return {"path": [], "total_cost": 0, "nodes_explored": nodes_explored, "path_found": False}

"""
bfs.py - Breadth-First Search over the security event graph.

BFS explores nodes level by level (hop by hop from the start node).
This makes it ideal for "blast radius" analysis where we want to know
everything reachable within N hops of a compromised entity.

Trace output (enabled by default) prints each node as it is discovered
so you can follow the algorithm step-by-step.
"""

from collections import deque
from typing import Optional
from src.graph.graph_store import GraphStore


def bfs_traverse(
    graph: GraphStore,
    start_node_id: str,
    max_depth: int = 3,
    action_filter: Optional[str] = None,
    trace: bool = True,
) -> dict:
    """
    Breadth-First traversal starting from *start_node_id*.

    The algorithm uses a FIFO queue.  Each entry in the queue is a tuple
    ``(node_id, depth, path_so_far)``.  Nodes are marked visited before
    they are enqueued so each node is processed exactly once.

    Parameters
    ----------
    graph         : The populated GraphStore to search.
    start_node_id : ID of the node to start from.
    max_depth     : Maximum number of hops to follow (default 3).
    action_filter : If set, only traverse edges with this action verb.
    trace         : Print step-by-step discovery messages when True.

    Returns
    -------
    dict with keys:
      visited_nodes   – list of Node objects in discovery order
      traversal_order – list of node IDs in discovery order
      depth_map       – {node_id: depth_at_which_it_was_discovered}
      paths           – {node_id: [node_id_path_from_start]}
    """

    # ── Validate start node ──────────────────────────────────────────
    start_node = graph.get_node(start_node_id)
    if start_node is None:
        print(f"[BFS] ERROR: start node '{start_node_id}' not found in graph.")
        return {"visited_nodes": [], "traversal_order": [], "depth_map": {}, "paths": {}}

    if trace:
        print(f"\n{'='*60}")
        print(f"[BFS] Starting traversal from: {start_node}")
        print(f"[BFS] Max depth: {max_depth}  |  Action filter: {action_filter or 'none'}")
        print(f"{'='*60}")

    # ── Data structures ──────────────────────────────────────────────
    visited:        set[str]         = set()       # node IDs already enqueued
    queue:          deque            = deque()     # (node_id, depth, path)
    visited_nodes:  list             = []          # ordered list of Node objects
    traversal_order: list[str]       = []          # ordered list of node IDs
    depth_map:      dict[str, int]   = {}          # node_id -> depth
    paths:          dict[str, list]  = {}          # node_id -> [node_ids]

    # ── Seed the queue with the start node (depth 0) ─────────────────
    visited.add(start_node_id)
    queue.append((start_node_id, 0, [start_node_id]))

    # ── Main BFS loop ─────────────────────────────────────────────────
    while queue:
        current_id, depth, current_path = queue.popleft()
        current_node = graph.get_node(current_id)

        # Record discovery
        visited_nodes.append(current_node)
        traversal_order.append(current_id)
        depth_map[current_id] = depth
        paths[current_id] = current_path

        if trace:
            indent = "  " * depth
            print(f"{indent}[depth {depth}] Visiting: {current_node}")

        # Do not expand beyond max_depth
        if depth >= max_depth:
            if trace:
                print(f"{'  ' * depth}          └─ max depth reached, not expanding further")
            continue

        # ── Expand neighbours ─────────────────────────────────────────
        edges = graph.get_outgoing_edges(current_id, action_filter)

        for edge in edges:
            neighbor_id = edge.target_id

            if neighbor_id in visited:
                if trace:
                    neighbor = graph.get_node(neighbor_id)
                    print(f"{'  ' * (depth+1)}  ↳ [{edge.action}] {neighbor} (already visited, skip)")
                continue

            neighbor_node = graph.get_node(neighbor_id)
            if neighbor_node is None:
                continue  # dangling edge reference – skip safely

            if trace:
                print(f"{'  ' * (depth+1)}  ↳ [{edge.action}] discovered: {neighbor_node}")

            # Mark visited *before* enqueue to prevent duplicate queuing
            visited.add(neighbor_id)
            queue.append((neighbor_id, depth + 1, current_path + [neighbor_id]))

    if trace:
        print(f"\n[BFS] Traversal complete.")
        print(f"[BFS] Nodes discovered: {len(visited_nodes)}  |  Max depth reached: {max(depth_map.values(), default=0)}")

    return {
        "visited_nodes":    visited_nodes,
        "traversal_order":  traversal_order,
        "depth_map":        depth_map,
        "paths":            paths,
    }

"""
dfs.py - Depth-First Search over the security event graph.

DFS dives as deep as possible along each branch before backtracking.
In threat hunting this helps reconstruct the full attack chain –
the complete sequence of events from a root process down to its
deepest side-effects.

Trace output (enabled by default) shows the DFS stack and backtracking
so the algorithm's behaviour is transparent.
"""

from typing import Optional
from src.graph.graph_store import GraphStore


def dfs_find_paths(
    graph: GraphStore,
    start_node_id: str,
    target_node_id: Optional[str] = None,
    max_depth: int = 10,
    action_filter: Optional[str] = None,
    trace: bool = True,
) -> dict:
    """
    Depth-First traversal / path-finding starting from *start_node_id*.

    If *target_node_id* is given the search collects every simple path
    (no repeated nodes) that leads from start to target.
    If no target is given the search fully explores the reachable subgraph
    up to *max_depth*.

    The algorithm is implemented iteratively using an explicit stack to
    avoid Python's recursion limit on large graphs.

    Each stack frame is a tuple: (node_id, depth, path_so_far, visited_on_path)
    where *visited_on_path* is a frozenset of IDs already on this branch –
    this gives per-path cycle avoidance while still letting us visit a node
    via a different route.

    Parameters
    ----------
    graph          : The populated GraphStore.
    start_node_id  : ID of the node to start from.
    target_node_id : Optional goal node ID.  If None, traverse everything.
    max_depth      : Maximum path length (default 10).
    action_filter  : If set, only follow edges with this action verb.
    trace          : Print step-by-step stack operations when True.

    Returns
    -------
    dict with keys:
      paths               – list of paths, each path is a list of node IDs
      traversal_order     – all node IDs in the order first visited
      nodes_visited_count – total number of (node, path) expansions performed
    """

    # ── Validate start node ──────────────────────────────────────────
    start_node = graph.get_node(start_node_id)
    if start_node is None:
        print(f"[DFS] ERROR: start node '{start_node_id}' not found.")
        return {"paths": [], "traversal_order": [], "nodes_visited_count": 0}

    if trace:
        goal_label = graph.get_node(target_node_id) if target_node_id else "any (full traversal)"
        print(f"\n{'='*60}")
        print(f"[DFS] Start : {start_node}")
        print(f"[DFS] Target: {goal_label}")
        print(f"[DFS] Max depth: {max_depth}  |  Action filter: {action_filter or 'none'}")
        print(f"{'='*60}")

    # ── Data structures ──────────────────────────────────────────────
    # Stack entries: (node_id, depth, path_list, visited_on_path_frozenset)
    stack: list = [(start_node_id, 0, [start_node_id], frozenset([start_node_id]))]

    traversal_order: list[str]  = []      # first-visit order across all branches
    first_seen: set[str]        = set()   # track which nodes we have ever output in trace
    paths_found: list[list]     = []      # complete paths to target (or all leaf paths)
    expansions: int             = 0       # total stack pops = "work done"

    # ── Main DFS loop ─────────────────────────────────────────────────
    while stack:
        current_id, depth, path, visited_on_path = stack.pop()
        expansions += 1

        current_node = graph.get_node(current_id)

        # First time we reach this node ID overall → record it
        if current_id not in first_seen:
            traversal_order.append(current_id)
            first_seen.add(current_id)

        if trace:
            indent = "  " * depth
            print(f"{indent}[depth {depth}] Expanding: {current_node}")

        # ── Goal check ───────────────────────────────────────────────
        if target_node_id and current_id == target_node_id:
            if trace:
                print(f"{'  ' * depth}  ★ TARGET REACHED – path length {len(path)}")
            paths_found.append(list(path))
            continue  # keep searching for other paths to the same target

        # ── Depth limit ──────────────────────────────────────────────
        if depth >= max_depth:
            if trace:
                print(f"{'  ' * depth}  └─ max depth, backtracking")
            if not target_node_id:
                # Treat current node as a "leaf" when doing full traversal
                paths_found.append(list(path))
            continue

        # ── Expand neighbours ─────────────────────────────────────────
        edges = graph.get_outgoing_edges(current_id, action_filter)
        has_unvisited = False

        for edge in edges:
            neighbor_id = edge.target_id

            if neighbor_id in visited_on_path:
                if trace:
                    neighbor = graph.get_node(neighbor_id)
                    print(f"{'  ' * (depth+1)}  ↩ [{edge.action}] {neighbor} (cycle, skip)")
                continue

            neighbor_node = graph.get_node(neighbor_id)
            if neighbor_node is None:
                continue

            if trace:
                print(f"{'  ' * (depth+1)}  → [{edge.action}] pushing: {neighbor_node}")

            has_unvisited = True
            new_path    = path + [neighbor_id]
            new_visited = visited_on_path | {neighbor_id}
            stack.append((neighbor_id, depth + 1, new_path, new_visited))

        # If no children and doing full traversal, record path as leaf
        if not has_unvisited and not target_node_id:
            paths_found.append(list(path))
            if trace:
                print(f"{'  ' * depth}  └─ leaf node, recording path")

    if trace:
        print(f"\n[DFS] Complete.  Expansions: {expansions}  |  Paths found: {len(paths_found)}")

    return {
        "paths":               paths_found,
        "traversal_order":     traversal_order,
        "nodes_visited_count": expansions,
    }

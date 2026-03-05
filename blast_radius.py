"""
blast_radius.py - Blast Radius Analysis using BFS.

"Blast radius" answers the question:
  "If entity X is compromised, what other entities can it reach within N hops?"

We run BFS from the given start node up to max_depth hops and then group
the discovered nodes by entity type and depth level for a clear summary.
"""

from src.graph.graph_store import GraphStore
from src.search.bfs import bfs_traverse


def blast_radius_analysis(
    graph: GraphStore,
    start_node_id: str,
    max_depth: int = 2,
    trace: bool = True,
) -> dict:
    """
    Find every entity reachable within *max_depth* hops of *start_node_id*.

    Parameters
    ----------
    graph         : Populated GraphStore.
    start_node_id : The compromised / suspicious entity to start from.
    max_depth     : Number of hops to follow (default 2).
    trace         : Show BFS step trace.

    Returns
    -------
    dict with keys:
      start_node     – the Node object for the start
      by_depth       – { depth: { entity_type: [Node, ...] } }
      all_nodes      – flat list of all discovered Nodes (excluding start)
      total_count    – total entities discovered (excluding start)
      bfs_result     – raw BFS output dict
    """

    start_node = graph.get_node(start_node_id)
    if start_node is None:
        print(f"[BlastRadius] ERROR: node '{start_node_id}' not found.")
        return {}

    # Run BFS
    bfs_result = bfs_traverse(graph, start_node_id, max_depth=max_depth, trace=trace)

    # Organise results by depth and entity type
    by_depth: dict[int, dict[str, list]] = {}
    all_nodes = []

    for node in bfs_result["visited_nodes"]:
        if node.id == start_node_id:
            continue  # skip the start node itself

        depth = bfs_result["depth_map"][node.id]
        by_depth.setdefault(depth, {})
        by_depth[depth].setdefault(node.type, [])
        by_depth[depth][node.type].append(node)
        all_nodes.append(node)

    # ── Pretty print report ───────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"Blast Radius Analysis for: {start_node}  (max depth: {max_depth})")
    print(f"{'='*60}")

    for depth in sorted(by_depth):
        label = "Direct Connections" if depth == 1 else f"Depth {depth} (indirect)"
        print(f"\n  [{label}]")
        type_map = by_depth[depth]
        for etype, nodes in sorted(type_map.items()):
            names = ", ".join(n.name for n in nodes)
            print(f"    {etype.capitalize():12s}: {names}")

    print(f"\n  Total entities discovered: {len(all_nodes)}")
    print(f"{'='*60}")

    return {
        "start_node":  start_node,
        "by_depth":    by_depth,
        "all_nodes":   all_nodes,
        "total_count": len(all_nodes),
        "bfs_result":  bfs_result,
    }

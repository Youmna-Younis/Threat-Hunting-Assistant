"""
attack_chain.py - Attack Chain Reconstruction using DFS.

Reconstructs the full chain of events starting from a suspicious entity.
We follow SPAWNED, WROTE_TO, and CONNECTED_TO relationships by default
(configurable) and produce a chronological timeline using edge timestamps.
"""

from src.graph.graph_store import GraphStore
from src.search.dfs import dfs_find_paths


# Default relationships to follow during chain reconstruction
DEFAULT_CHAIN_ACTIONS = {"SPAWNED", "WROTE_TO", "CONNECTED_TO", "DOWNLOADED"}


def attack_chain_reconstruction(
    graph: GraphStore,
    start_node_id: str,
    max_depth: int = 8,
    action_filter: str = None,
    trace: bool = True,
) -> dict:
    """
    Reconstruct all attack chains from *start_node_id* using DFS.

    Each DFS path is a candidate attack chain.  We post-process the paths
    to attach timestamps from the edges so analysts get a timeline.

    Parameters
    ----------
    graph         : Populated GraphStore.
    start_node_id : Suspicious process / entity to start from.
    max_depth     : Maximum chain depth to follow (default 8).
    action_filter : Restrict edge traversal to this action verb.
                    None = follow all action types.
    trace         : Show DFS trace.

    Returns
    -------
    dict with keys:
      start_node – the Node object for the start
      chains     – list of chain dicts, each with:
                     nodes     : [Node, ...]
                     timeline  : [(timestamp, src_name, action, tgt_name), ...]
      dfs_result – raw DFS output
    """

    start_node = graph.get_node(start_node_id)
    if start_node is None:
        print(f"[AttackChain] ERROR: node '{start_node_id}' not found.")
        return {}

    # Run DFS (no single target – explore everything)
    dfs_result = dfs_find_paths(
        graph,
        start_node_id,
        target_node_id=None,
        max_depth=max_depth,
        action_filter=action_filter,
        trace=trace,
    )

    # ── Build timeline for each path ──────────────────────────────────
    chains = []
    for path_ids in dfs_result["paths"]:
        if len(path_ids) < 2:
            continue   # single-node "path" – not an interesting chain

        nodes    = [graph.get_node(nid) for nid in path_ids if graph.get_node(nid)]
        timeline = []

        # Walk consecutive pairs to find the connecting edge
        for i in range(len(path_ids) - 1):
            src_id = path_ids[i]
            tgt_id = path_ids[i + 1]
            # Find the first edge between src → tgt
            edge = next(
                (e for e in graph.get_outgoing_edges(src_id) if e.target_id == tgt_id),
                None
            )
            if edge:
                src_node = graph.get_node(src_id)
                tgt_node = graph.get_node(tgt_id)
                timeline.append((
                    edge.timestamp or "??:??:??",
                    src_node.name if src_node else src_id,
                    edge.action,
                    tgt_node.name if tgt_node else tgt_id,
                ))

        chains.append({"nodes": nodes, "timeline": timeline})

    # Sort chains by length (longer = more interesting)
    chains.sort(key=lambda c: len(c["nodes"]), reverse=True)

    # ── Pretty print ──────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"Attack Chain Reconstruction from: {start_node}")
    print(f"{'='*60}")

    if not chains:
        print("  No attack chains found (no outgoing paths from start node).")
    else:
        for i, chain in enumerate(chains, 1):
            print(f"\n  Chain {i}  (length {len(chain['nodes'])} nodes):")
            for ts, src, action, tgt in chain["timeline"]:
                print(f"    {ts}  {src}  --[{action}]-->  {tgt}")

    print(f"\n  Total chains reconstructed: {len(chains)}")
    print(f"  DFS expansions performed  : {dfs_result['nodes_visited_count']}")
    print(f"{'='*60}")

    return {
        "start_node": start_node,
        "chains":     chains,
        "dfs_result": dfs_result,
    }

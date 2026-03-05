"""
prioritization.py - Suspicious Activity Prioritization using UCS and A*.

This query finds the cheapest path from a start node to each of a set of
suspicious targets, using both UCS and A* so we can measure how many fewer
nodes A* needs to explore.

A "suspicious target" is any node matching one of the suspicious patterns
defined in identify_suspicious_targets().
"""

from src.graph.graph_store import GraphStore
from src.search.ucs   import ucs_find_cheapest_path, DEFAULT_COST_CONFIG
from src.search.astar import astar_find_path


# Suspicious indicators – these node names / types warrant investigation
SUSPICIOUS_PROCESS_NAMES = {"nc.exe", "ncat.exe", "mimikatz.exe", "ransomware.exe",
                             "malware.exe", "payload.exe", "whoami.exe", "wscript.exe"}

SUSPICIOUS_FILE_EXTENSIONS = {".exe", ".ps1", ".bat", ".vbs", ".hta"}


def identify_suspicious_targets(graph: GraphStore) -> list:
    """
    Scan the graph and return a ranked list of suspicious node IDs.

    Ranking (highest priority first):
      1. Suspicious process names
      2. Executable / script files
      3. External network connections
    """
    targets = []

    for node in graph.get_all_nodes():
        name_lower = node.name.lower()

        if node.type == "process" and name_lower in SUSPICIOUS_PROCESS_NAMES:
            targets.append(("HIGH",   node.id, node))
            continue

        if node.type == "file" and any(name_lower.endswith(ext) for ext in SUSPICIOUS_FILE_EXTENSIONS):
            targets.append(("MEDIUM", node.id, node))
            continue

        if node.type == "network":
            targets.append(("LOW",    node.id, node))

    # Sort: HIGH first, then MEDIUM, then LOW
    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    targets.sort(key=lambda t: priority_order[t[0]])

    return targets


def suspicious_activity_prioritization(
    graph: GraphStore,
    start_node_id: str,
    cost_config: dict = None,
    heuristic: str = "suspiciousness",
    trace: bool = False,         # False by default to keep output clean; UCS/A* traces are verbose
    trace_algorithms: bool = False,
) -> dict:
    """
    Rank suspicious targets by cheapest-path cost from *start_node_id*.

    For each target we run:
      - UCS  to get the guaranteed optimal path
      - A*   to show how many fewer nodes it explores

    Parameters
    ----------
    graph             : Populated GraphStore.
    start_node_id     : Origin node (e.g. a known-compromised host).
    cost_config       : Edge cost table.
    heuristic         : A* heuristic name ("suspiciousness" | "hop_count").
    trace             : Print the overall report (always recommended).
    trace_algorithms  : Also print UCS/A* heap traces (very verbose).

    Returns
    -------
    dict with keys:
      start_node – Node object for the start
      results    – list of result dicts (one per target), sorted by UCS cost
    """

    costs = cost_config if cost_config else DEFAULT_COST_CONFIG

    start_node = graph.get_node(start_node_id)
    if start_node is None:
        print(f"[Prioritization] ERROR: node '{start_node_id}' not found.")
        return {}

    suspicious_targets = identify_suspicious_targets(graph)

    if not suspicious_targets:
        print("[Prioritization] No suspicious targets found in the graph.")
        return {"start_node": start_node, "results": []}

    print(f"\n{'='*60}")
    print(f"Suspicious Activity Prioritization from: {start_node}")
    print(f"{'='*60}")
    print(f"  Identified {len(suspicious_targets)} suspicious targets.\n")

    results = []

    for priority, target_id, target_node in suspicious_targets:
        if target_id == start_node_id:
            continue   # skip start node itself

        # ── UCS ───────────────────────────────────────────────────────
        ucs_result = ucs_find_cheapest_path(
            graph, start_node_id, [target_id],
            cost_config=costs,
            trace=trace_algorithms,
        )

        # ── A* ────────────────────────────────────────────────────────
        astar_result = astar_find_path(
            graph, start_node_id, [target_id],
            cost_config=costs,
            heuristic=heuristic,
            trace=trace_algorithms,
        )

        if not ucs_result["path_found"]:
            continue   # target is unreachable from start

        # Calculate efficiency improvement of A* over UCS
        ucs_explored   = ucs_result["nodes_explored"]
        astar_explored = astar_result["nodes_explored"]
        if ucs_explored > 0:
            savings_pct = round((1 - astar_explored / ucs_explored) * 100)
        else:
            savings_pct = 0

        # Build human-readable path string
        path_names = " → ".join(
            graph.get_node(nid).name for nid in ucs_result["path"] if graph.get_node(nid)
        )

        result = {
            "priority":       priority,
            "target":         target_node,
            "ucs_cost":       ucs_result["total_cost"],
            "ucs_explored":   ucs_explored,
            "astar_explored": astar_explored,
            "savings_pct":    savings_pct,
            "path_ids":       ucs_result["path"],
            "path_names":     path_names,
        }
        results.append(result)

        print(f"  [{priority:6s}] Target: {target_node}")
        print(f"           Path : {path_names}")
        print(f"           Cost : {ucs_result['total_cost']:.1f}  |  "
              f"UCS nodes: {ucs_explored}  |  A* nodes: {astar_explored}  "
              f"({'A* saved ' + str(savings_pct) + '%' if savings_pct > 0 else 'equal'})")
        print()

    # Sort by UCS cost (cheapest = most reachable / immediate threat)
    results.sort(key=lambda r: r["ucs_cost"])

    if results:
        total_ucs   = sum(r["ucs_explored"]   for r in results)
        total_astar = sum(r["astar_explored"]  for r in results)
        overall_savings = round((1 - total_astar / total_ucs) * 100) if total_ucs else 0
        print(f"  Overall: A* explored {overall_savings}% fewer nodes than UCS across all targets.")

    print(f"{'='*60}")

    return {"start_node": start_node, "results": results}

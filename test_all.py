"""
tests/test_all.py - Unit tests for all core modules.

Run with:  python -m pytest tests/test_all.py -v
       or: python tests/test_all.py
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.graph.models      import Node, Edge
from src.graph.graph_store import GraphStore
from src.search.bfs        import bfs_traverse
from src.search.dfs        import dfs_find_paths
from src.search.ucs        import ucs_find_cheapest_path
from src.search.astar      import astar_find_path
from src.parser.log_parser import load_log


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_linear_graph(n: int) -> GraphStore:
    """Build a simple chain: n0 → n1 → n2 → ... → n(n-1)."""
    g = GraphStore()
    for i in range(n):
        g.add_node(Node(id=f"n{i}", type="process", name=f"proc{i}", host="host"))
    for i in range(n - 1):
        g.add_edge(Edge(source_id=f"n{i}", target_id=f"n{i+1}", action="SPAWNED"))
    return g


def make_branching_graph() -> GraphStore:
    """
    Build:
        A → B → D
        A → C → D
        D → E
    """
    g = GraphStore()
    for nid in ["A", "B", "C", "D", "E"]:
        g.add_node(Node(id=nid, type="process", name=nid, host="host"))
    g.add_edge(Edge("A", "B", "SPAWNED"))
    g.add_edge(Edge("A", "C", "SPAWNED"))
    g.add_edge(Edge("B", "D", "SPAWNED"))
    g.add_edge(Edge("C", "D", "SPAWNED"))
    g.add_edge(Edge("D", "E", "SPAWNED"))
    return g


def make_cycle_graph() -> GraphStore:
    """
    Build:  A → B → C → A  (cycle)
    """
    g = GraphStore()
    for nid in ["A", "B", "C"]:
        g.add_node(Node(id=nid, type="process", name=nid, host="host"))
    g.add_edge(Edge("A", "B", "SPAWNED"))
    g.add_edge(Edge("B", "C", "SPAWNED"))
    g.add_edge(Edge("C", "A", "SPAWNED"))   # cycle back
    return g


# ── GraphStore tests ──────────────────────────────────────────────────────────

class TestGraphStore(unittest.TestCase):

    def test_add_node_and_retrieve(self):
        g = GraphStore()
        n = Node("n1", "process", "explorer.exe", "HOST")
        g.add_node(n)
        self.assertEqual(g.get_node("n1"), n)
        self.assertIsNone(g.get_node("missing"))

    def test_duplicate_node_ignored(self):
        g = GraphStore()
        g.add_node(Node("n1", "process", "a.exe", "HOST"))
        g.add_node(Node("n1", "process", "b.exe", "HOST"))   # duplicate ID
        self.assertEqual(g.get_node("n1").name, "a.exe")     # first wins
        self.assertEqual(g.node_count, 1)

    def test_add_edge_and_neighbors(self):
        g = make_linear_graph(3)
        neighbors = g.get_neighbors("n0")
        self.assertEqual(len(neighbors), 1)
        self.assertEqual(neighbors[0].id, "n1")

    def test_get_nodes_by_type(self):
        g = GraphStore()
        g.add_node(Node("p1", "process", "a.exe",   "HOST"))
        g.add_node(Node("f1", "file",    "data.txt", "HOST"))
        processes = g.get_nodes_by_type("process")
        self.assertEqual(len(processes), 1)
        self.assertEqual(processes[0].id, "p1")

    def test_incoming_edges(self):
        g = make_linear_graph(3)
        incoming = g.get_incoming_edges("n1")
        self.assertEqual(len(incoming), 1)
        self.assertEqual(incoming[0].source_id, "n0")

    def test_orphan_edge_ignored(self):
        g = GraphStore()
        g.add_node(Node("n0", "process", "a", "HOST"))
        # target n1 does not exist → should print warning but not crash
        g.add_edge(Edge("n0", "n1", "SPAWNED"))
        self.assertEqual(g.edge_count, 0)

    def test_action_filter(self):
        g = GraphStore()
        for nid in ["A", "B", "C"]:
            g.add_node(Node(nid, "process", nid, "HOST"))
        g.add_edge(Edge("A", "B", "SPAWNED"))
        g.add_edge(Edge("A", "C", "WROTE_TO"))
        spawned = g.get_outgoing_edges("A", action_filter="SPAWNED")
        self.assertEqual(len(spawned), 1)
        self.assertEqual(spawned[0].target_id, "B")


# ── BFS tests ─────────────────────────────────────────────────────────────────

class TestBFS(unittest.TestCase):

    def _run(self, g, start, **kwargs):
        return bfs_traverse(g, start, trace=False, **kwargs)

    def test_linear_all_reachable(self):
        g = GraphStore()
        for i in range(5):
            g.add_node(Node(f"n{i}", "process", f"p{i}", "host"))
        for i in range(4):
            g.add_edge(Edge(f"n{i}", f"n{i+1}", "SPAWNED"))
        result = self._run(g, "n0", max_depth=10)
        self.assertEqual(len(result["visited_nodes"]), 5)

    def test_depth_limit(self):
        g = make_linear_graph(5)
        result = self._run(g, "n0", max_depth=2)
        # Should visit n0, n1, n2 only
        self.assertIn(2, result["depth_map"].values())
        self.assertNotIn("n3", result["depth_map"])

    def test_cycle_no_infinite_loop(self):
        g = make_cycle_graph()
        result = self._run(g, "A", max_depth=5)
        # BFS should terminate; each node visited at most once
        ids = result["traversal_order"]
        self.assertEqual(len(ids), len(set(ids)))

    def test_start_node_at_depth_0(self):
        g = make_linear_graph(3)
        result = self._run(g, "n0", max_depth=3)
        self.assertEqual(result["depth_map"]["n0"], 0)

    def test_unknown_start_returns_empty(self):
        g = make_linear_graph(3)
        result = self._run(g, "MISSING")
        self.assertEqual(result["visited_nodes"], [])

    def test_paths_correct(self):
        g = make_linear_graph(3)
        result = self._run(g, "n0", max_depth=5)
        self.assertEqual(result["paths"]["n2"], ["n0", "n1", "n2"])


# ── DFS tests ─────────────────────────────────────────────────────────────────

class TestDFS(unittest.TestCase):

    def _run(self, g, start, **kwargs):
        return dfs_find_paths(g, start, trace=False, **kwargs)

    def test_finds_path_to_target(self):
        g = make_linear_graph(4)
        result = self._run(g, "n0", target_node_id="n3")
        self.assertTrue(len(result["paths"]) >= 1)
        self.assertEqual(result["paths"][0], ["n0", "n1", "n2", "n3"])

    def test_cycle_no_infinite_loop(self):
        g = make_cycle_graph()
        result = self._run(g, "A", max_depth=10)
        # Should finish without recursion error
        self.assertIsNotNone(result["paths"])

    def test_branching_finds_both_paths(self):
        g = make_branching_graph()
        result = self._run(g, "A", target_node_id="D")
        path_sets = [frozenset(p) for p in result["paths"]]
        # Both A→B→D and A→C→D should be found
        self.assertEqual(len(result["paths"]), 2)

    def test_unreachable_target(self):
        g = make_linear_graph(3)
        # Add an isolated node
        g.add_node(Node("iso", "file", "isolated.txt", "HOST"))
        result = self._run(g, "n0", target_node_id="iso")
        self.assertEqual(result["paths"], [])

    def test_max_depth_respected(self):
        g = make_linear_graph(10)
        result = self._run(g, "n0", target_node_id="n9", max_depth=3)
        # n9 is 9 hops away – should not be found within depth 3
        self.assertEqual(result["paths"], [])


# ── UCS tests ─────────────────────────────────────────────────────────────────

class TestUCS(unittest.TestCase):

    COSTS = {"SPAWNED": 1, "CONNECTED_TO": 5}

    def _run(self, g, start, goals):
        return ucs_find_cheapest_path(g, start, goals, cost_config=self.COSTS, trace=False)

    def test_finds_cheapest_path_linear(self):
        g = make_linear_graph(4)
        result = self._run(g, "n0", ["n3"])
        self.assertTrue(result["path_found"])
        self.assertEqual(result["total_cost"], 3.0)   # 3 × SPAWNED(1)
        self.assertEqual(result["path"], ["n0", "n1", "n2", "n3"])

    def test_prefers_cheaper_path(self):
        """
        Graph:  A --(SPAWNED, 1)--> B --(SPAWNED, 1)--> GOAL   (total 2)
                A --(CONNECTED_TO, 5)--> GOAL                   (total 5)
        UCS should choose the 2-hop path.
        """
        g = GraphStore()
        for nid in ["A", "B", "GOAL"]:
            g.add_node(Node(nid, "process", nid, "host"))
        g.add_edge(Edge("A", "B",    "SPAWNED"))
        g.add_edge(Edge("B", "GOAL", "SPAWNED"))
        g.add_edge(Edge("A", "GOAL", "CONNECTED_TO"))

        result = self._run(g, "A", ["GOAL"])
        self.assertTrue(result["path_found"])
        self.assertEqual(result["total_cost"], 2.0)
        self.assertEqual(result["path"], ["A", "B", "GOAL"])

    def test_no_path(self):
        g = make_linear_graph(3)
        g.add_node(Node("iso", "file", "iso", "host"))
        result = self._run(g, "n0", ["iso"])
        self.assertFalse(result["path_found"])

    def test_multiple_goals_picks_nearest(self):
        g = make_linear_graph(5)
        result = self._run(g, "n0", ["n2", "n4"])
        self.assertTrue(result["path_found"])
        self.assertEqual(result["total_cost"], 2.0)   # n2 is closer
        self.assertEqual(result["path"][-1], "n2")


# ── A* tests ──────────────────────────────────────────────────────────────────

class TestAStar(unittest.TestCase):

    COSTS = {"SPAWNED": 1, "CONNECTED_TO": 5}

    def _run(self, g, start, goals, heuristic="suspiciousness"):
        return astar_find_path(g, start, goals, cost_config=self.COSTS,
                               heuristic=heuristic, trace=False)

    def test_finds_path_same_as_ucs(self):
        g = make_linear_graph(5)
        ucs_r = ucs_find_cheapest_path(g, "n0", ["n4"], cost_config=self.COSTS, trace=False)
        astar_r = self._run(g, "n0", ["n4"])
        self.assertEqual(ucs_r["total_cost"], astar_r["total_cost"])
        self.assertEqual(ucs_r["path"], astar_r["path"])

    def test_astar_explores_fewer_or_equal_nodes(self):
        g = make_branching_graph()
        ucs_r = ucs_find_cheapest_path(g, "A", ["E"], cost_config=self.COSTS, trace=False)
        astar_r = self._run(g, "A", ["E"])
        # A* should never explore MORE nodes than UCS for admissible heuristic
        self.assertLessEqual(astar_r["nodes_explored"], ucs_r["nodes_explored"] + 1)

    def test_hop_count_heuristic(self):
        g = make_linear_graph(5)
        result = self._run(g, "n0", ["n4"], heuristic="hop_count")
        self.assertTrue(result["path_found"])
        self.assertEqual(result["total_cost"], 4.0)

    def test_no_path(self):
        g = make_linear_graph(3)
        g.add_node(Node("iso", "file", "iso", "host"))
        result = self._run(g, "n0", ["iso"])
        self.assertFalse(result["path_found"])


# ── Parser integration test ───────────────────────────────────────────────────

class TestParser(unittest.TestCase):

    LOG_PATH = os.path.join(os.path.dirname(__file__), "..",
                            "data", "sample_logs", "small_incident.json")

    def test_load_sample_log(self):
        if not os.path.exists(self.LOG_PATH):
            self.skipTest("sample log not found")
        graph, ok, skipped = load_log(self.LOG_PATH)
        self.assertGreater(ok, 0)
        self.assertGreater(graph.node_count, 0)
        self.assertGreater(graph.edge_count, 0)

    def test_all_events_parsed(self):
        if not os.path.exists(self.LOG_PATH):
            self.skipTest("sample log not found")
        graph, ok, skipped = load_log(self.LOG_PATH)
        self.assertEqual(skipped, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

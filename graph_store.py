"""
graph_store.py - In-memory directed graph built from parsed security events.

The graph stores nodes in a dict keyed by node ID and maintains two adjacency
lists per node so we can cheaply walk both outgoing and incoming edges.

Lookup indexes:
  - by_type  : node_type  -> list[Node]
  - by_name  : name       -> list[Node]
"""

from collections import defaultdict
from typing import List, Optional
from src.graph.models import Node, Edge


class GraphStore:
    """
    Directed property graph that holds security entities and their relationships.

    Internals
    ---------
    _nodes       : {node_id -> Node}
    _out_edges   : {node_id -> [Edge, ...]}   (edges leaving the node)
    _in_edges    : {node_id -> [Edge, ...]}   (edges arriving at the node)
    _type_index  : {entity_type -> [node_id, ...]}
    _name_index  : {name -> [node_id, ...]}
    """

    def __init__(self):
        self._nodes: dict[str, Node] = {}
        self._out_edges: dict[str, List[Edge]] = defaultdict(list)
        self._in_edges:  dict[str, List[Edge]] = defaultdict(list)
        self._type_index: dict[str, List[str]] = defaultdict(list)
        self._name_index: dict[str, List[str]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Mutators
    # ------------------------------------------------------------------

    def add_node(self, node: Node) -> None:
        """
        Insert a node into the graph.
        If a node with the same ID already exists it is silently skipped –
        the first occurrence wins (deduplication).
        """
        if node.id in self._nodes:
            return  # already present, skip duplicate

        self._nodes[node.id] = node
        self._type_index[node.type].append(node.id)
        self._name_index[node.name.lower()].append(node.id)

    def add_edge(self, edge: Edge) -> None:
        """
        Insert a directed edge.
        Both endpoint nodes must already exist; orphan edges are ignored with
        a warning so that malformed log entries do not crash the build step.
        """
        if edge.source_id not in self._nodes:
            print(f"[WARN] add_edge: unknown source '{edge.source_id}' – edge skipped.")
            return
        if edge.target_id not in self._nodes:
            print(f"[WARN] add_edge: unknown target '{edge.target_id}' – edge skipped.")
            return

        self._out_edges[edge.source_id].append(edge)
        self._in_edges[edge.target_id].append(edge)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_node(self, node_id: str) -> Optional[Node]:
        """Return the Node for *node_id*, or None if not found."""
        return self._nodes.get(node_id)

    def get_all_nodes(self) -> List[Node]:
        """Return every node in the graph."""
        return list(self._nodes.values())

    def get_nodes_by_type(self, entity_type: str) -> List[Node]:
        """Return all nodes whose type matches *entity_type* (case-insensitive)."""
        ids = self._type_index.get(entity_type.lower(), [])
        return [self._nodes[nid] for nid in ids if nid in self._nodes]

    def get_nodes_by_name(self, name: str) -> List[Node]:
        """Return all nodes whose name matches *name* (case-insensitive)."""
        ids = self._name_index.get(name.lower(), [])
        return [self._nodes[nid] for nid in ids if nid in self._nodes]

    def get_outgoing_edges(self, node_id: str, action_filter: Optional[str] = None) -> List[Edge]:
        """
        Return edges leaving *node_id*.

        Parameters
        ----------
        node_id       : Source node ID
        action_filter : If given, only return edges with this action verb
        """
        edges = self._out_edges.get(node_id, [])
        if action_filter:
            edges = [e for e in edges if e.action == action_filter.upper()]
        return edges

    def get_incoming_edges(self, node_id: str, action_filter: Optional[str] = None) -> List[Edge]:
        """Return edges arriving at *node_id*, optionally filtered by action."""
        edges = self._in_edges.get(node_id, [])
        if action_filter:
            edges = [e for e in edges if e.action == action_filter.upper()]
        return edges

    def get_neighbors(self, node_id: str, action_filter: Optional[str] = None) -> List[Node]:
        """
        Return the nodes that *node_id* points to via outgoing edges.
        Optionally restrict to a specific action type.
        """
        edges = self.get_outgoing_edges(node_id, action_filter)
        neighbors = []
        for edge in edges:
            node = self._nodes.get(edge.target_id)
            if node:
                neighbors.append(node)
        return neighbors

    # ------------------------------------------------------------------
    # Stats helpers
    # ------------------------------------------------------------------

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(edges) for edges in self._out_edges.values())

    def summary(self) -> str:
        type_counts = {t: len(ids) for t, ids in self._type_index.items()}
        lines = [
            f"Graph Summary",
            f"  Nodes : {self.node_count}  {type_counts}",
            f"  Edges : {self.edge_count}",
        ]
        return "\n".join(lines)

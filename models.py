"""
models.py - Core data structures for graph nodes and edges.

A Node represents any security entity: process, file, user, host, or network connection.
An Edge represents a directed relationship between two nodes (e.g. SPAWNED, WROTE_TO).
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Node:
    """
    Represents a single entity in the security event graph.

    Attributes:
        id       : Unique identifier (e.g. "proc_002")
        type     : Entity category: process | file | user | host | network
        name     : Human-readable label (e.g. "powershell.exe")
        host     : The machine this entity lives on
        metadata : Any extra key-value pairs from the raw log
    """

    id: str
    type: str
    name: str
    host: str
    metadata: dict = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        return isinstance(other, Node) and self.id == other.id

    def __repr__(self):
        return f"Node({self.type}:{self.name} [{self.id}])"


@dataclass
class Edge:
    """
    Represents a directed relationship between two nodes.

    Attributes:
        source_id  : ID of the originating node
        target_id  : ID of the destination node
        action     : Relationship verb (e.g. "SPAWNED", "CONNECTED_TO")
        timestamp  : When the event occurred (ISO string or None)
        event_id   : Original log event ID for traceability
    """

    source_id: str
    target_id: str
    action: str
    timestamp: Optional[str] = None
    event_id: Optional[str] = None

    def __repr__(self):
        return f"Edge({self.source_id} --[{self.action}]--> {self.target_id})"

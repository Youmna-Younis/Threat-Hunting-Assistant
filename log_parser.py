"""
log_parser.py - Parse JSON/CSV security event logs into a GraphStore.

Each event describes a directed relationship between a source entity and a
target entity.  The parser:
  1. Validates required fields.
  2. Creates/deduplicates Node objects.
  3. Creates Edge objects and adds both to the GraphStore.
"""

import json
import csv
from typing import Tuple
from src.graph.graph_store import GraphStore
from src.graph.models import Node, Edge


# Fields that every event dict must contain at the top level.
REQUIRED_TOP = {"event_id", "timestamp", "source", "target", "action"}
# Fields required inside each source/target block.
REQUIRED_ENTITY = {"type", "id", "name", "host"}


def _validate_event(event: dict) -> Tuple[bool, str]:
    """
    Check that *event* has the minimum required structure.

    Returns (True, "") on success or (False, reason) on failure.
    """
    missing_top = REQUIRED_TOP - event.keys()
    if missing_top:
        return False, f"missing top-level keys: {missing_top}"

    for role in ("source", "target"):
        block = event.get(role, {})
        if not isinstance(block, dict):
            return False, f"'{role}' must be a dict"
        missing_entity = REQUIRED_ENTITY - block.keys()
        if missing_entity:
            return False, f"'{role}' missing keys: {missing_entity}"

    return True, ""


def _entity_to_node(entity: dict) -> Node:
    """Convert a raw source/target dict to a Node object."""
    known_keys = {"type", "id", "name", "host"}
    metadata = {k: v for k, v in entity.items() if k not in known_keys}
    return Node(
        id=entity["id"],
        type=entity["type"].lower(),
        name=entity["name"],
        host=entity["host"],
        metadata=metadata,
    )


def parse_json_log(filepath: str) -> Tuple[GraphStore, int, int]:
    """
    Read a JSON log file and build a GraphStore.

    Expected structure::

        { "events": [ { ...event... }, ... ] }

    Parameters
    ----------
    filepath : Path to the .json log file.

    Returns
    -------
    graph          : Populated GraphStore
    events_ok      : Number of events successfully processed
    events_skipped : Number of events skipped due to validation errors
    """
    graph = GraphStore()
    events_ok = 0
    events_skipped = 0

    with open(filepath, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    events = data.get("events", [])
    if not isinstance(events, list):
        raise ValueError("JSON log must contain a top-level 'events' list.")

    for idx, event in enumerate(events):
        ok, reason = _validate_event(event)
        if not ok:
            print(f"[SKIP] event #{idx}: {reason}")
            events_skipped += 1
            continue

        # --- Build nodes (deduplicated inside GraphStore.add_node) ------
        src_node = _entity_to_node(event["source"])
        tgt_node = _entity_to_node(event["target"])
        graph.add_node(src_node)
        graph.add_node(tgt_node)

        # --- Build edge -------------------------------------------------
        edge = Edge(
            source_id=src_node.id,
            target_id=tgt_node.id,
            action=event["action"].upper(),
            timestamp=event.get("timestamp"),
            event_id=event.get("event_id"),
        )
        graph.add_edge(edge)
        events_ok += 1

    return graph, events_ok, events_skipped


def parse_csv_log(filepath: str) -> Tuple[GraphStore, int, int]:
    """
    Read a flat CSV log file and build a GraphStore.

    Expected columns::

        event_id, timestamp, action,
        src_type, src_id, src_name, src_host,
        tgt_type, tgt_id, tgt_name, tgt_host

    Parameters
    ----------
    filepath : Path to the .csv log file.

    Returns
    -------
    Same as parse_json_log.
    """
    graph = GraphStore()
    events_ok = 0
    events_skipped = 0

    with open(filepath, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for idx, row in enumerate(reader):
            # Reconstruct event dict from flat CSV row
            event = {
                "event_id":   row.get("event_id", ""),
                "timestamp":  row.get("timestamp", ""),
                "action":     row.get("action", ""),
                "source": {
                    "type": row.get("src_type", ""),
                    "id":   row.get("src_id", ""),
                    "name": row.get("src_name", ""),
                    "host": row.get("src_host", ""),
                },
                "target": {
                    "type": row.get("tgt_type", ""),
                    "id":   row.get("tgt_id", ""),
                    "name": row.get("tgt_name", ""),
                    "host": row.get("tgt_host", ""),
                },
            }

            ok, reason = _validate_event(event)
            if not ok:
                print(f"[SKIP] CSV row #{idx}: {reason}")
                events_skipped += 1
                continue

            src_node = _entity_to_node(event["source"])
            tgt_node = _entity_to_node(event["target"])
            graph.add_node(src_node)
            graph.add_node(tgt_node)

            edge = Edge(
                source_id=src_node.id,
                target_id=tgt_node.id,
                action=event["action"].upper(),
                timestamp=event.get("timestamp"),
                event_id=event.get("event_id"),
            )
            graph.add_edge(edge)
            events_ok += 1

    return graph, events_ok, events_skipped


def load_log(filepath: str) -> Tuple[GraphStore, int, int]:
    """
    Auto-detect format (JSON vs CSV) by file extension and delegate.

    Parameters
    ----------
    filepath : Path to log file (.json or .csv).

    Returns
    -------
    Same as parse_json_log.
    """
    lower = filepath.lower()
    if lower.endswith(".json"):
        return parse_json_log(filepath)
    elif lower.endswith(".csv"):
        return parse_csv_log(filepath)
    else:
        raise ValueError(f"Unsupported file extension for: {filepath}")

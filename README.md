# Threat Hunting Assistant

A Python tool that applies **BFS, DFS, UCS, and A\*** search algorithms to security event graphs for threat analysis.

## Project Structure

```
threat_hunting/
├── main.py                          ← CLI entry point
├── data/sample_logs/
│   └── small_incident.json          ← 15-event ransomware scenario
├── config/cost_config.json          ← Edge cost table for UCS/A*
├── src/
│   ├── parser/log_parser.py         ← JSON + CSV log ingestion
│   ├── graph/
│   │   ├── models.py                ← Node / Edge dataclasses
│   │   └── graph_store.py           ← Directed graph with indexes
│   ├── search/
│   │   ├── bfs.py                   ← Breadth-First Search
│   │   ├── dfs.py                   ← Depth-First Search (iterative)
│   │   ├── ucs.py                   ← Uniform Cost Search
│   │   └── astar.py                 ← A* with two heuristics
│   └── queries/
│       ├── blast_radius.py          ← BFS-based blast radius analysis
│       ├── attack_chain.py          ← DFS-based chain reconstruction
│       └── prioritization.py        ← UCS + A* comparison
└── tests/test_all.py                ← 28 unit tests (all passing)
```

## Quick Start

```bash
# List nodes in the graph
python main.py --log data/sample_logs/small_incident.json --list-nodes

# Blast radius: what can explorer.exe reach in 3 hops? (BFS)
python main.py --log data/sample_logs/small_incident.json \
               --blast-radius proc_001 --depth 3

# Attack chain reconstruction from powershell.exe (DFS)
python main.py --log data/sample_logs/small_incident.json \
               --attack-chain proc_002 --no-trace

# Suspicious activity prioritization from explorer.exe (UCS + A*)
python main.py --log data/sample_logs/small_incident.json \
               --prioritize proc_001 --no-trace

# Run all three queries at once
python main.py --log data/sample_logs/small_incident.json \
               --all proc_001 --no-trace
```

## Algorithms

| Algorithm | Use Case | Key Idea |
|-----------|----------|----------|
| **BFS** | Blast radius | Explore level-by-level; finds all nodes within N hops |
| **DFS** | Attack chains | Dive deep; reconstructs full event sequences |
| **UCS** | Priority ranking | Expand cheapest node first; guarantees optimal-cost path |
| **A\*** | Efficient priority | UCS + heuristic; explores fewer nodes while keeping optimality |

### Trace Mode
By default all four algorithms print step-by-step execution traces so you can follow exactly what happens. Suppress with `--no-trace`.

### Edge Costs (UCS / A\*)
Configured in `config/cost_config.json`:

| Action | Cost | Rationale |
|--------|------|-----------|
| SPAWNED | 1 | Normal process creation |
| READ_FILE | 1 | Low-risk |
| LOGGED_INTO | 2 | Credential use |
| WROTE_TO | 3 | Potential data modification |
| MODIFIED_PERMISSIONS | 3 | Privilege escalation indicator |
| DOWNLOADED | 4 | External data ingestion |
| CONNECTED_TO | 5 | Network exfiltration risk |

### A\* Heuristics
- **suspiciousness** (default): assigns h=0 to processes like `powershell`, `cmd`, executables, and network nodes — guides search toward threats eagerly
- **hop_count**: performs a mini-BFS to estimate remaining hops to goal; multiplied by min cost (1) to stay admissible

## Log Format (JSON)

```json
{
  "events": [
    {
      "event_id": "evt_001",
      "timestamp": "2024-01-15 10:30:00",
      "source": {"type": "process", "id": "proc_001", "name": "explorer.exe", "host": "DESKTOP"},
      "target": {"type": "process", "id": "proc_002", "name": "powershell.exe", "host": "DESKTOP"},
      "action": "SPAWNED"
    }
  ]
}
```

CSV format also supported with columns: `event_id, timestamp, action, src_type, src_id, src_name, src_host, tgt_type, tgt_id, tgt_name, tgt_host`

## Running Tests

```bash
python tests/test_all.py
# 28 tests — GraphStore, BFS, DFS, UCS, A*, Parser
```

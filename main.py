"""
main.py - Command-line interface for the Threat Hunting Assistant.

Usage examples
--------------
  # Show all nodes in graph
  python main.py --log data/sample_logs/small_incident.json --graph-summary

  # Blast radius analysis (BFS)
  python main.py --log data/sample_logs/small_incident.json \
                 --blast-radius host_001 --depth 2

  # Attack chain reconstruction (DFS)
  python main.py --log data/sample_logs/small_incident.json \
                 --attack-chain proc_002

  # Suspicious activity prioritization (UCS + A*)
  python main.py --log data/sample_logs/small_incident.json \
                 --prioritize host_001

  # Run all queries at once
  python main.py --log data/sample_logs/small_incident.json --all host_001

  # Disable algorithm traces (just see the report)
  python main.py --log data/sample_logs/small_incident.json \
                 --blast-radius host_001 --no-trace
"""

import argparse
import sys
import os

# Make src importable whether we run from project root or src/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.parser.log_parser           import load_log
from src.queries.blast_radius        import blast_radius_analysis
from src.queries.attack_chain        import attack_chain_reconstruction
from src.queries.prioritization      import suspicious_activity_prioritization


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threat_hunter",
        description="AI-Assisted Threat Hunting Assistant – search algorithm demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Required
    p.add_argument(
        "--log", required=True, metavar="FILE",
        help="Path to JSON or CSV security event log"
    )

    # Query modes
    p.add_argument(
        "--graph-summary", action="store_true",
        help="Print a summary of the loaded graph and exit"
    )
    p.add_argument(
        "--blast-radius", metavar="NODE_ID",
        help="Run BFS blast-radius analysis starting from NODE_ID"
    )
    p.add_argument(
        "--depth", type=int, default=2, metavar="N",
        help="Max hop depth for --blast-radius (default: 2)"
    )
    p.add_argument(
        "--attack-chain", metavar="NODE_ID",
        help="Run DFS attack-chain reconstruction starting from NODE_ID"
    )
    p.add_argument(
        "--chain-depth", type=int, default=8, metavar="N",
        help="Max chain depth for --attack-chain (default: 8)"
    )
    p.add_argument(
        "--prioritize", metavar="NODE_ID",
        help="Run UCS + A* prioritization from NODE_ID"
    )
    p.add_argument(
        "--heuristic", choices=["suspiciousness", "hop_count"], default="suspiciousness",
        help="A* heuristic to use with --prioritize (default: suspiciousness)"
    )
    p.add_argument(
        "--all", metavar="NODE_ID",
        help="Run all three queries from NODE_ID"
    )

    # Misc
    p.add_argument(
        "--no-trace", action="store_true",
        help="Suppress step-by-step algorithm trace output"
    )
    p.add_argument(
        "--list-nodes", action="store_true",
        help="Print all nodes in the graph"
    )

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    # ── Load log ──────────────────────────────────────────────────────
    print(f"\n[*] Loading log: {args.log}")
    try:
        graph, ok, skipped = load_log(args.log)
    except FileNotFoundError:
        print(f"[!] File not found: {args.log}")
        sys.exit(1)
    except Exception as exc:
        print(f"[!] Failed to load log: {exc}")
        sys.exit(1)

    print(f"[*] Events processed: {ok}  |  Skipped: {skipped}")
    print(graph.summary())

    if args.list_nodes:
        print("\n[*] All nodes:")
        for node in graph.get_all_nodes():
            print(f"    {node.id:20s}  {node.type:10s}  {node.name}")

    if args.graph_summary:
        return   # already printed above

    trace = not args.no_trace

    # ── Blast radius ──────────────────────────────────────────────────
    if args.blast_radius or args.all:
        node_id = args.blast_radius or args.all
        blast_radius_analysis(graph, node_id, max_depth=args.depth, trace=trace)

    # ── Attack chain ──────────────────────────────────────────────────
    if args.attack_chain or args.all:
        node_id = args.attack_chain or args.all
        attack_chain_reconstruction(graph, node_id, max_depth=args.chain_depth, trace=trace)

    # ── Prioritization ────────────────────────────────────────────────
    if args.prioritize or args.all:
        node_id = args.prioritize or args.all
        suspicious_activity_prioritization(
            graph, node_id,
            heuristic=args.heuristic,
            trace=trace,
            trace_algorithms=False,   # keep output readable unless debugging
        )


if __name__ == "__main__":
    main()

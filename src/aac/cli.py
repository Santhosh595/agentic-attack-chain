"""Command-line entry point: run correlation rules over a JSONL observation stream.

    python -m aac correlate --rules rules/ --stream stream.jsonl
    python -m aac correlate --rules rules/ --otel spans.jsonl
    python -m aac coverage

Exit codes:
    0  no findings
    1  one or more findings
    2  the input could not be processed
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .correlation import CorrelationEngine
from .observation import ObservationError, load_stream
from .otel import OTelBridge
from .rules import RuleLoadError, load_rules


def _read_jsonl(path: Path) -> list[str]:
    return path.read_text().splitlines()


def _cmd_correlate(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.rules)
    except RuleLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not rules:
        print(f"error: no correlation rules found in {args.rules}", file=sys.stderr)
        return 2

    try:
        if args.otel:
            bridge = OTelBridge()
            spans = [
                json.loads(line)
                for line in _read_jsonl(args.stream)
                if line.strip() and not line.strip().startswith("//")
            ]
            observations = bridge.to_observations(spans)
        else:
            observations = load_stream(_read_jsonl(args.stream))
    except (ObservationError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    engine = CorrelationEngine(rules)
    engine.observe_all(observations)

    findings = engine.findings()
    if args.json:
        print(
            json.dumps(
                {
                    "findings": [f.to_dict() for f in findings],
                    "atomic_event_count": len(engine.atomic_events()),
                    "evictions": engine.evictions,
                },
                indent=2,
            )
        )
    else:
        for finding in findings:
            print(f"[{finding.severity.upper()}] {finding.rule_id}: {finding.title}")
            print(f"  {finding.message}")
            print(f"  actions: {', '.join(finding.actions)}")
            print(f"  evidence: {', '.join(e['observation.id'] for e in finding.evidence)}")
            print()
        print(
            f"{len(findings)} finding(s) from {len(observations)} observation(s); "
            f"{engine.evictions} eviction(s)"
        )
    return 1 if findings else 0


def _cmd_coverage(args: argparse.Namespace) -> int:
    bridge = OTelBridge()
    print(json.dumps(bridge.coverage(), indent=2))
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.rules)
    except RuleLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for rule in rules:
        print(f"{rule.id}  {rule.logic_type:20} {rule.title}")
    print(f"\n{len(rules)} rule(s) valid")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aac", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    correlate = sub.add_parser("correlate", help="run correlation rules over a stream")
    correlate.add_argument("--rules", type=Path, required=True, help="directory of rule YAML files")
    correlate.add_argument("--stream", type=Path, required=True, help="JSONL observation stream")
    correlate.add_argument("--otel", action="store_true", help="treat the stream as OTel spans")
    correlate.add_argument("--json", action="store_true", help="emit JSON")
    correlate.set_defaults(func=_cmd_correlate)

    coverage = sub.add_parser("coverage", help="report the OTel bridge's declared coverage")
    coverage.set_defaults(func=_cmd_coverage)

    validate = sub.add_parser("validate", help="validate correlation rules")
    validate.add_argument("--rules", type=Path, required=True)
    validate.set_defaults(func=_cmd_validate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

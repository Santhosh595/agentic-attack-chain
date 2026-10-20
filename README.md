# agentic-attack-chain

**A correlation engine for AI-agent attack chains.**

ATR (Agent Threat Rules) is becoming the detection standard for AI agents — "Sigma
for AI agents." Its rule corpus is stable and in production: it ships in Microsoft
AGT, Cisco AI Defense, MISP, Gen Digital and FINOS. But its **multi-event
correlation layer does not exist**. The spec is written and unratified, the shipped
engine contains no correlation code, and none of the open upstream issues touch it.

This project implements that missing layer, and bridges OpenTelemetry GenAI
telemetry into it.

```
OTel GenAI spans
  -> ATR observations
  -> session / agent / delegation-aware chain correlation
  -> one high-confidence finding naming every constituent event
```

## Why this is not another scanner

A single agent action rarely constitutes an attack. The attack lives in the chain.
Upstream's own words:

> A single agent action rarely constitutes an attack. **The attack lives in the
> chain** … The defender sees four unrelated alerts and may dismiss each as
> low-severity noise.

ATR's 833 single-event rules fire independently on each step. A defender sees four
low-severity alerts and dismisses them. This engine joins them into one finding
that names every step.

## What it implements

The [ATR Correlation Rule Format v1.0](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/spec/atr-correlation-v1.0.md)
specification, in full:

| Spec feature | Status |
|---|---|
| `temporal_sequence` | implemented |
| `temporal_unordered` | implemented |
| `count_threshold` | implemented |
| `value_overlap` | implemented |
| `chain_propagation` | implemented |
| 6 standard join keys | implemented |
| 4 window types (`wall_time`, `session_chain`, `chain_depth`, `unbounded`) | implemented |
| Bounded state + `correlation_state_evicted` | implemented |
| `severity_uplift` + response actions | implemented |
| Conformance gate (JSONL fixture streams) | implemented — **`tests/correlation-streams/` does not exist upstream** |
| OTel GenAI span → observation bridge | implemented — **issue #70 lists this as "TBD"** |

The upstream JSON Schema is vendored verbatim at
[`spec/schema/correlation.schema.json`](spec/schema/correlation.schema.json)
(5,069 bytes, sha `f8db6ec9dba4`) and is used as the structural contract. Rules are
validated against it, then against semantic checks the schema cannot express.

## Two things the upstream engine does not do

**1. Joins that survive a sub-agent hop.** Grouping by `session.id` alone is
trivially defeated: an actor that spawns a sub-agent gets a fresh session id from
the host, so a two-step chain lands in two buckets and nothing correlates. This
engine joins on `delegation.root` from the
[ATR Observation Format](https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/spec/atr-observation-v1.0.md),
which survives the hop.

**2. Honest coverage.** The observation spec requires a host to declare which
dimensions it can actually observe. An engine that cannot see `file` or `process`
operations says so, rather than reporting "no match" for a question it was never
able to ask:

```console
$ aac coverage
{
  "atr.observation_spec_version": "1.0",
  "covered_dimensions": ["llm_io", "tool_call", ...],
  "uncovered_dimensions": ["file", "process"]
}
```

Reporting "could not look" as "looked and found nothing" is how a coverage number
becomes a lie. That discipline is the point.

## Install

```bash
git clone https://github.com/Santhosh595/agentic-attack-chain
cd agentic-attack-chain
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Use

```bash
# validate the rules
aac validate --rules rules

# correlate an observation stream
aac correlate --rules rules --stream stream.jsonl

# or feed raw OTel spans
aac correlate --rules rules --otel --stream spans.jsonl
```

Exit code `1` means findings were produced, `0` means none, `2` means the input
could not be processed.

## Write a rule

Rules are YAML against the upstream schema. A minimal one:

```yaml
correlation:
  schema_version: "1.0"
  id: "ATR-COR-2026-00003"
  title: "Repeated denied tool calls from one agent"
  description: "An agent probing a permission boundary repeatedly."
  status: "draft"
  severity: "high"
  author: "You"
  date: "2026-10-21"
  license: "MIT"

source_rules:
  - alias: "denied_call"
    rule_id: "ATR-2026-00115"

correlation_logic:
  type: "count_threshold"
  count: { rule_alias: "denied_call", threshold: 5 }
  join_keys: ["agent.id"]
  window: { type: "wall_time", duration: "1h" }

response:
  severity_uplift: "high"
  actions: ["alert", "snapshot"]
```

The spec requires a rule to ship fixture streams, and the engine's conformance
gate enforces it. Put them in `tests/correlation-streams/<rule-id>/`:

- `positive.jsonl` — the engine **MUST** fire
- `negative.jsonl` — the engine **MUST NOT** fire (e.g. same steps, different
  `agent.id` → join-key mismatch)

## Test

```bash
pytest
```

## Status

This is an independent implementation of a **proposed, unratified** upstream
specification. It is not affiliated with or endorsed by the ATR project. The
upstream spec may change; this engine implements the spec as published on
2026-10-21, with the vendored schema pinned by hash.

## License

MIT.

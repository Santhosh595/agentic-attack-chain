# agentic-attack-chain

[![CI](https://github.com/Santhosh595/agentic-attack-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/Santhosh595/agentic-attack-chain/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**A correlation engine for AI-agent attack chains.**

ATR (Agent Threat Rules) is becoming the detection standard for AI agents — "Sigma
for AI agents." Its rule corpus is stable and in production: it ships in Microsoft
AGT, Cisco AI Defense, MISP, Gen Digital and FINOS. But its **multi-event
correlation layer is not implemented**. The spec is written and unratified, the
shipped engines contain no general implementation of it, and none of the open
upstream issues touch it.

What upstream *does* have is an ad-hoc sequence tracker: the TypeScript engine
has a `SessionTracker` that groups events by `sessionId` (`src/session-tracker.ts`,
`src/modules/session.ts`). That covers one narrow case — ordered steps inside
one session — and nothing else. It is not an implementation of the published
correlation specification, which defines five correlation types, six standard
join keys, four window forms, and bounded state with eviction.

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

### What is built, and what is not

**Built and tested (149 tests, run in CI on Python 3.11 and 3.12):**

- the full observation model (ATR Observation Format v1.0)
- the full rule loader — schema validation plus the semantic checks the
  schema cannot express
- all five correlation types, all six join keys, all four window forms
- bounded pending-chain state with `correlation_state_evicted`
- the OpenTelemetry GenAI span → observation bridge
- the CLI: `correlate`, `validate`, `coverage`
- a conformance gate that enforces upstream's fixture-stream convention

**Not built yet — do not read this as a finished product:**

| Missing | Consequence |
|---|---|
| **Only 2 rules ship** (`ATR-COR-2026-00001`, `-00002`) | The engine is exercised by 2 chains, not by a corpus. A rule-shape bug that only appears on a third rule type would not be caught. |
| **No attack corpus** | There is no body of real multi-step attack traces. The fixtures are hand-built to exercise join-key and window behaviour. |
| **No benign corpus** | The hard half of detection work — benign multi-step chains that must *not* fire — is not started. Without it, false-positive rate is unknown, not zero. |
| **No live agent to attack** | Nothing yet produces OTel spans from a running agent, so the bridge is tested against synthetic spans only. |
| **No findings output / OWASP-ATLAS mapping at finding time** | The `severity_uplift` path exists; the per-finding OWASP Agentic ID and MITRE ATLAS ID mapping is not yet emitted. |

The engine is a **working, tested implementation of the correlation
mechanism**, and that mechanism is the thing that was missing upstream. It is
not yet a detection product: a detection product needs the attack corpus and
the benign corpus, and those are the next two pieces of work, not the last
two.

### Deliberate scope boundaries

- **Atomic rules never block on correlation.** A single-event ATR rule still
  fires on its own; correlation adds a higher-confidence finding, it does not
  gate the low-confidence ones.
- **"Not observed" is never reported as "observed absent."** The coverage
  command reports which dimensions the host can actually see.
- **Join keys are ANDed.** A differing `agent.id` or `delegation.root` must
  prevent correlation, even when every other key matches.

## License

MIT.

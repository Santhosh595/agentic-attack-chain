"""Tests for the correlation engine.

This is the layer that does not exist upstream. ATR's correlation spec is
written and unratified; its TypeScript engine has an ad-hoc per-rule
sequence tracker keyed on sessionId only. This engine implements the spec's
five correlation types over the observation contract, with join keys that
survive a sub-agent hop.

The behaviours under test come straight from the spec:
  - "The match fires when the final event in the sequence is observed."
  - "Events between the named ones are allowed (and ignored)."
  - a join-key mismatch must NOT correlate
  - correlation must NOT block atomic-rule emission
  - engines MUST emit a `correlation_state_evicted` event when eviction occurs
"""

from __future__ import annotations

import datetime as dt

import pytest

from aac.correlation import CorrelationEngine, CorrelationFinding
from aac.observation import Observation
from aac.rules import load_rule

RULE = {
    "correlation": {
        "schema_version": "1.0",
        "id": "ATR-COR-2026-00001",
        "title": "Indirect injection then exfiltration",
        "description": "An injected instruction is followed by an outbound transfer.",
        "status": "draft",
        "severity": "critical",
        "author": "Test Author",
        "date": "2026-05-25",
        "license": "MIT",
    },
    "source_rules": [
        {"alias": "injection", "rule_id": "ATR-2026-00002"},
        {"alias": "exfil", "rule_id": "ATR-2026-00020"},
    ],
    "correlation_logic": {
        "type": "temporal_sequence",
        "sequence": [{"alias": "injection"}, {"alias": "exfil"}],
        "join_keys": ["agent.id", "session.id"],
        "window": {"type": "wall_time", "duration": "30m"},
    },
    "response": {
        "severity_uplift": "critical",
        "actions": ["alert", "quarantine"],
        "message_template": "[{correlation.id}] {injection.event_id} -> {exfil.event_id}",
    },
}


def _obs(
    obs_id,
    kind,
    agent="agt-1",
    session="sess-1",
    outcome="ok",
    ts="2026-05-25T10:00:00Z",
    delegation_root=None,
    **fields,
):
    raw = {
        "@timestamp": ts,
        "observation.id": obs_id,
        "observation.kind": kind,
        "agent.id": agent,
        "session.id": session,
        "outcome": outcome,
    }
    if delegation_root:
        raw["delegation.root"] = delegation_root
    raw.update(fields)
    return Observation.from_dict(raw)


def _engine(rule=None, **kwargs):
    return CorrelationEngine([load_rule(rule or RULE)], **kwargs)


# --- temporal_sequence ------------------------------------------------------


def test_a_matching_sequence_produces_one_finding():
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"}))
    engine.observe(_obs("o2", "network", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"}))
    findings = engine.findings()
    assert len(findings) == 1
    assert findings[0].rule_id == "ATR-COR-2026-00001"
    assert findings[0].severity == "critical"


def test_the_finding_names_every_constituent_event():
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"}))
    engine.observe(_obs("o2", "network", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"}))
    finding = engine.findings()[0]
    assert [e["observation.id"] for e in finding.evidence] == ["o1", "o2"]


def test_the_finding_fires_only_when_the_final_event_arrives():
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"}))
    assert engine.findings() == []


def test_events_between_the_named_ones_are_allowed_and_ignored():
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"}))
    engine.observe(_obs("noise", "tool_call", ts="2026-05-25T10:01:00Z"))
    engine.observe(_obs("o2", "network", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"}))
    assert len(engine.findings()) == 1


def test_out_of_order_events_do_not_match_a_sequence():
    engine = _engine()
    engine.observe(_obs("o2", "network", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"}))
    engine.observe(_obs("o1", "llm_io", ts="2026-05-25T10:00:00Z", **{"atr.rule_id": "ATR-2026-00002"}))
    assert engine.findings() == []


# --- join keys --------------------------------------------------------------


def test_a_join_key_mismatch_does_not_correlate():
    """The spec's negative fixture: same steps, different agent.id."""
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", agent="agt-1", **{"atr.rule_id": "ATR-2026-00002"}))
    engine.observe(
        _obs("o2", "network", agent="agt-2", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"})
    )
    assert engine.findings() == []


def test_a_session_mismatch_does_not_correlate():
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", session="sess-1", **{"atr.rule_id": "ATR-2026-00002"}))
    engine.observe(
        _obs("o2", "network", session="sess-2", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"})
    )
    assert engine.findings() == []


def test_joining_on_delegation_root_survives_a_sub_agent_hop():
    """The whole reason delegation.root exists.

    A sub-agent gets a fresh session.id from the host. Joining on
    session.id alone splits the chain into two buckets and nothing
    correlates; joining on delegation.root keeps it together.
    """
    rule = dict(RULE)
    rule["correlation_logic"] = dict(
        RULE["correlation_logic"], join_keys=["agent.id", "delegation.root"]
    )
    engine = _engine(rule)
    engine.observe(
        _obs("o1", "llm_io", session="sess-1", delegation_root="sess-1", **{"atr.rule_id": "ATR-2026-00002"})
    )
    engine.observe(
        _obs(
            "o2",
            "network",
            session="sess-2",
            delegation_root="sess-1",
            ts="2026-05-25T10:05:00Z",
            **{"atr.rule_id": "ATR-2026-00020"},
        )
    )
    assert len(engine.findings()) == 1


# --- windows ----------------------------------------------------------------


def test_events_outside_the_wall_time_window_do_not_correlate():
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"}))
    engine.observe(
        _obs("o2", "network", ts="2026-05-25T11:00:00Z", **{"atr.rule_id": "ATR-2026-00020"})
    )
    assert engine.findings() == []


def test_events_inside_the_wall_time_window_correlate():
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"}))
    engine.observe(
        _obs("o2", "network", ts="2026-05-25T10:29:00Z", **{"atr.rule_id": "ATR-2026-00020"})
    )
    assert len(engine.findings()) == 1


def test_a_session_chain_window_spans_up_to_n_sessions():
    rule = dict(RULE)
    rule["correlation_logic"] = dict(
        RULE["correlation_logic"],
        join_keys=["agent.id", "delegation.root"],
        window={"type": "session_chain", "max_session_count": 3, "max_wall_time": "30d"},
    )
    engine = _engine(rule)
    engine.observe(
        _obs("o1", "llm_io", session="sess-1", delegation_root="sess-1", **{"atr.rule_id": "ATR-2026-00002"})
    )
    engine.observe(
        _obs(
            "o2",
            "network",
            session="sess-9",
            delegation_root="sess-1",
            ts="2026-05-27T14:32:00Z",
            **{"atr.rule_id": "ATR-2026-00020"},
        )
    )
    assert len(engine.findings()) == 1


# --- temporal_unordered -----------------------------------------------------


def test_temporal_unordered_matches_regardless_of_order():
    rule = dict(RULE)
    rule["correlation_logic"] = dict(
        RULE["correlation_logic"], type="temporal_unordered"
    )
    engine = _engine(rule)
    engine.observe(
        _obs("o2", "network", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"})
    )
    engine.observe(_obs("o1", "llm_io", ts="2026-05-25T10:00:00Z", **{"atr.rule_id": "ATR-2026-00002"}))
    assert len(engine.findings()) == 1


# --- count_threshold --------------------------------------------------------


def test_count_threshold_fires_when_the_threshold_is_reached():
    rule = {
        "correlation": dict(RULE["correlation"]),
        "source_rules": [{"alias": "probe", "rule_id": "ATR-2026-00100"}],
        "correlation_logic": {
            "type": "count_threshold",
            "count": {"rule_alias": "probe", "threshold": 3},
            "join_keys": ["agent.id"],
            "window": {"type": "wall_time", "duration": "1h"},
        },
        "response": dict(RULE["response"]),
    }
    engine = _engine(rule)
    for index in range(2):
        engine.observe(
            _obs(f"o{index}", "tool_call", ts=f"2026-05-25T10:0{index}:00Z", **{"atr.rule_id": "ATR-2026-00100"})
        )
    assert engine.findings() == []
    engine.observe(
        _obs("o2", "tool_call", ts="2026-05-25T10:02:00Z", **{"atr.rule_id": "ATR-2026-00100"})
    )
    assert len(engine.findings()) == 1


def test_count_threshold_counts_per_join_group():
    rule = {
        "correlation": dict(RULE["correlation"]),
        "source_rules": [{"alias": "probe", "rule_id": "ATR-2026-00100"}],
        "correlation_logic": {
            "type": "count_threshold",
            "count": {"rule_alias": "probe", "threshold": 2},
            "join_keys": ["agent.id"],
            "window": {"type": "wall_time", "duration": "1h"},
        },
        "response": dict(RULE["response"]),
    }
    engine = _engine(rule)
    engine.observe(_obs("o1", "tool_call", agent="a", **{"atr.rule_id": "ATR-2026-00100"}))
    engine.observe(_obs("o2", "tool_call", agent="b", **{"atr.rule_id": "ATR-2026-00100"}))
    assert engine.findings() == []


# --- value_overlap ----------------------------------------------------------


def test_value_overlap_requires_a_shared_value():
    rule = {
        "correlation": dict(RULE["correlation"]),
        "source_rules": [
            {"alias": "one", "rule_id": "ATR-2026-00100"},
            {"alias": "two", "rule_id": "ATR-2026-00200"},
        ],
        "correlation_logic": {
            "type": "value_overlap",
            "value_overlap_field": "target.host",
            "join_keys": ["agent.id"],
            "window": {"type": "wall_time", "duration": "1h"},
        },
        "response": dict(RULE["response"]),
    }
    engine = _engine(rule)
    engine.observe(
        _obs("o1", "network", **{"atr.rule_id": "ATR-2026-00100", "target.host": "evil.example"})
    )
    engine.observe(
        _obs("o2", "network", ts="2026-05-25T10:01:00Z", **{"atr.rule_id": "ATR-2026-00200", "target.host": "other.example"})
    )
    assert engine.findings() == []
    engine.observe(
        _obs("o3", "network", ts="2026-05-25T10:02:00Z", **{"atr.rule_id": "ATR-2026-00200", "target.host": "evil.example"})
    )
    assert len(engine.findings()) == 1


# --- chain_propagation ------------------------------------------------------


def test_chain_propagation_follows_explicit_upstream_links():
    rule = {
        "correlation": dict(RULE["correlation"]),
        "source_rules": [
            {"alias": "one", "rule_id": "ATR-2026-00100"},
            {"alias": "two", "rule_id": "ATR-2026-00200"},
        ],
        "correlation_logic": {
            "type": "chain_propagation",
            "sequence": [{"alias": "one"}, {"alias": "two"}],
            "join_keys": ["agent.id"],
            "window": {"type": "chain_depth", "max_depth": 3},
        },
        "response": dict(RULE["response"]),
    }
    engine = _engine(rule)
    engine.observe(
        _obs("o1", "multi_agent_comm", **{"atr.rule_id": "ATR-2026-00100", "evidence.upstream_chain": []})
    )
    engine.observe(
        _obs(
            "o2",
            "multi_agent_comm",
            ts="2026-05-25T10:01:00Z",
            **{"atr.rule_id": "ATR-2026-00200", "evidence.upstream_chain": ["o1"]},
        )
    )
    assert len(engine.findings()) == 1


def test_chain_propagation_does_not_fire_without_the_link():
    rule = {
        "correlation": dict(RULE["correlation"]),
        "source_rules": [
            {"alias": "one", "rule_id": "ATR-2026-00100"},
            {"alias": "two", "rule_id": "ATR-2026-00200"},
        ],
        "correlation_logic": {
            "type": "chain_propagation",
            "sequence": [{"alias": "one"}, {"alias": "two"}],
            "join_keys": ["agent.id"],
            "window": {"type": "chain_depth", "max_depth": 3},
        },
        "response": dict(RULE["response"]),
    }
    engine = _engine(rule)
    engine.observe(
        _obs("o1", "multi_agent_comm", **{"atr.rule_id": "ATR-2026-00100", "evidence.upstream_chain": []})
    )
    engine.observe(
        _obs(
            "o2",
            "multi_agent_comm",
            ts="2026-05-25T10:01:00Z",
            **{"atr.rule_id": "ATR-2026-00200", "evidence.upstream_chain": ["some-other-id"]},
        )
    )
    assert engine.findings() == []


# --- source rule matching ---------------------------------------------------


def test_an_observation_matching_no_source_rule_is_ignored():
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-09999"}))
    assert engine.findings() == []


def test_source_rules_may_be_matched_by_category():
    rule = {
        "correlation": dict(RULE["correlation"]),
        "source_rules": [
            {"alias": "injection", "category": "prompt-injection"},
            {"alias": "exfil", "rule_id": "ATR-2026-00020"},
        ],
        "correlation_logic": dict(RULE["correlation_logic"]),
        "response": dict(RULE["response"]),
    }
    engine = _engine(rule)
    engine.observe(
        _obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002", "atr.category": "prompt-injection"})
    )
    engine.observe(
        _obs("o2", "network", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"})
    )
    assert len(engine.findings()) == 1


def test_source_rules_may_be_matched_by_rule_id_pattern():
    rule = {
        "correlation": dict(RULE["correlation"]),
        "source_rules": [
            {"alias": "injection", "rule_id_pattern": "ATR-2026-000*"},
            {"alias": "exfil", "rule_id": "ATR-2026-00020"},
        ],
        "correlation_logic": dict(RULE["correlation_logic"]),
        "response": dict(RULE["response"]),
    }
    engine = _engine(rule)
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"}))
    engine.observe(
        _obs("o2", "network", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"})
    )
    assert len(engine.findings()) == 1


# --- the emitted event ------------------------------------------------------


def test_the_finding_carries_the_rule_response():
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"}))
    engine.observe(_obs("o2", "network", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"}))
    finding = engine.findings()[0]
    assert finding.severity == "critical"
    assert finding.actions == ("alert", "quarantine")
    assert "o1" in finding.message and "o2" in finding.message


def test_the_finding_serialises_with_an_upstream_chain():
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"}))
    engine.observe(_obs("o2", "network", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"}))
    payload = engine.findings()[0].to_dict()
    assert payload["atr.rule_id"] == "ATR-COR-2026-00001"
    assert payload["evidence.upstream_chain"] == ["o1", "o2"]


# --- state bounds and eviction ----------------------------------------------


def test_state_is_bounded_and_eviction_is_reported():
    engine = _engine(max_pending=2)
    for index in range(5):
        engine.observe(
            _obs(f"o{index}", "llm_io", ts=f"2026-05-25T10:0{index}:00Z", **{"atr.rule_id": "ATR-2026-00002"})
        )
    assert engine.evictions > 0


def test_evicted_state_is_reported_as_a_named_event():
    engine = _engine(max_pending=2)
    for index in range(5):
        engine.observe(
            _obs(f"o{index}", "llm_io", ts=f"2026-05-25T10:0{index}:00Z", **{"atr.rule_id": "ATR-2026-00002"})
        )
    kinds = [e.get("event.type") for e in engine.events()]
    assert "correlation_state_evicted" in kinds


def test_a_bounded_engine_still_correlates():
    engine = _engine(max_pending=100)
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"}))
    engine.observe(_obs("o2", "network", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"}))
    assert len(engine.findings()) == 1


# --- atomic emission is not blocked -----------------------------------------


def test_atomic_events_are_emitted_immediately_and_independently():
    """The spec: "Correlation evaluation MUST NOT block atomic-rule emission."""
    engine = _engine()
    engine.observe(_obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"}))
    assert engine.atomic_events() != []


# --- idempotence ------------------------------------------------------------


def test_the_same_observation_twice_does_not_double_count():
    engine = _engine()
    obs = _obs("o1", "llm_io", **{"atr.rule_id": "ATR-2026-00002"})
    engine.observe(obs)
    engine.observe(obs)
    engine.observe(_obs("o2", "network", ts="2026-05-25T10:05:00Z", **{"atr.rule_id": "ATR-2026-00020"}))
    assert len(engine.findings()) == 1

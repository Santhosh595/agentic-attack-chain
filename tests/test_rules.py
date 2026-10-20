"""Tests for correlation-rule loading and validation.

The rule format is defined by ATR Correlation Rule Format v1.0. The JSON
Schema in spec/schema/correlation.schema.json is machine-readable and
normative; the Markdown spec says "This Markdown document is normative;
JSON Schema must match."

Validation here is therefore in two layers:
  1. structural — the rule must satisfy the upstream JSON Schema
  2. semantic  — the rule must be internally coherent (every alias in the
     sequence is a declared source rule, the window type can actually
     express the logic, the join keys are ones this engine knows)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aac.rules import (
    KNOWN_JOIN_KEYS,
    CorrelationRule,
    RuleLoadError,
    load_rule,
    load_rules,
    render_message,
)

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "spec" / "schema" / "correlation.schema.json"

VALID = {
    "correlation": {
        "schema_version": "1.0",
        "id": "ATR-COR-2026-00001",
        "title": "A2A delegated authority abuse chain",
        "description": "Indirect injection then tool call then exfiltration.",
        "status": "draft",
        "severity": "critical",
        "author": "Test Author",
        "date": "2026-05-25",
        "license": "MIT",
        "references": {"owasp_agentic": ["ASI03"], "mitre_atlas": ["AML.T0048"]},
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
        "actions": ["alert", "snapshot", "quarantine"],
        "message_template": "[{correlation.id}] chain: {injection.event_id} -> {exfil.event_id}",
    },
}


def _rule(**overrides):
    """Return a copy of VALID with top-level keys replaced."""
    out = json.loads(json.dumps(VALID))
    out.update(overrides)
    return out


# --- the vendored schema ----------------------------------------------------


def test_schema_file_is_present_and_non_trivial():
    assert SCHEMA_PATH.is_file()
    assert len(SCHEMA_PATH.read_bytes()) > 1000


def test_schema_is_valid_json_and_declares_its_version():
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["properties"]["correlation"]["properties"]["schema_version"]["const"] == "1.0"


# --- loading ----------------------------------------------------------------


def test_a_valid_rule_loads():
    rule = load_rule(VALID)
    assert rule.id == "ATR-COR-2026-00001"
    assert rule.title == "A2A delegated authority abuse chain"
    assert rule.severity == "critical"
    assert rule.logic_type == "temporal_sequence"


def test_rule_id_must_match_the_correlation_id_pattern():
    bad = _rule()
    bad["correlation"]["id"] = "ATR-2026-00001"  # atomic range, not correlation range
    with pytest.raises(RuleLoadError, match="id"):
        load_rule(bad)


def test_schema_version_must_be_one_point_zero():
    bad = _rule()
    bad["correlation"]["schema_version"] = "2.0"
    with pytest.raises(RuleLoadError):
        load_rule(bad)


def test_unknown_top_level_key_is_rejected():
    bad = _rule(nonsense={"a": 1})
    with pytest.raises(RuleLoadError):
        load_rule(bad)


def test_missing_required_block_is_rejected():
    bad = _rule()
    del bad["response"]
    with pytest.raises(RuleLoadError, match="response"):
        load_rule(bad)


def test_empty_source_rules_is_rejected():
    bad = _rule()
    bad["source_rules"] = []
    with pytest.raises(RuleLoadError, match="source_rules"):
        load_rule(bad)


def test_invalid_action_is_rejected():
    bad = _rule()
    bad["response"]["actions"] = ["format_disk"]
    with pytest.raises(RuleLoadError, match="action"):
        load_rule(bad)


def test_source_rule_needs_exactly_one_of_the_three_selectors():
    bad = _rule()
    bad["source_rules"] = [{"alias": "injection"}]
    with pytest.raises(RuleLoadError, match="source_rules"):
        load_rule(bad)


def test_source_rule_may_use_a_rule_id_pattern():
    rule = load_rule(
        _rule(
            source_rules=[
                {"alias": "injection", "rule_id_pattern": "ATR-2026-000*"},
                {"alias": "exfil", "rule_id": "ATR-2026-00020"},
            ]
        )
    )
    assert rule.source_rule("injection").rule_id_pattern == "ATR-2026-000*"


def test_source_rule_may_use_a_category():
    rule = load_rule(
        _rule(
            source_rules=[
                {"alias": "injection", "category": "prompt-injection"},
                {"alias": "exfil", "rule_id": "ATR-2026-00020"},
            ]
        )
    )
    assert rule.source_rule("injection").category == "prompt-injection"


# --- semantic validation ----------------------------------------------------


def test_sequence_alias_must_be_a_declared_source_rule():
    bad = _rule()
    bad["correlation_logic"]["sequence"] = [{"alias": "injection"}, {"alias": "ghost"}]
    with pytest.raises(RuleLoadError, match="ghost"):
        load_rule(bad)


def test_count_threshold_alias_must_be_declared():
    bad = _rule()
    bad["correlation_logic"] = {
        "type": "count_threshold",
        "count": {"rule_alias": "ghost", "threshold": 5},
        "join_keys": ["agent.id"],
        "window": {"type": "wall_time", "duration": "1h"},
    }
    with pytest.raises(RuleLoadError, match="ghost"):
        load_rule(bad)


def test_count_threshold_requires_a_threshold():
    bad = _rule()
    bad["correlation_logic"] = {
        "type": "count_threshold",
        "count": {"rule_alias": "injection"},
        "join_keys": ["agent.id"],
        "window": {"type": "wall_time", "duration": "1h"},
    }
    with pytest.raises(RuleLoadError, match="threshold"):
        load_rule(bad)


def test_value_overlap_requires_a_field():
    bad = _rule()
    bad["correlation_logic"] = {
        "type": "value_overlap",
        "join_keys": ["agent.id"],
        "window": {"type": "wall_time", "duration": "1h"},
    }
    with pytest.raises(RuleLoadError, match="value_overlap_field"):
        load_rule(bad)


def test_temporal_sequence_requires_a_sequence():
    bad = _rule()
    del bad["correlation_logic"]["sequence"]
    with pytest.raises(RuleLoadError, match="sequence"):
        load_rule(bad)


def test_unknown_join_key_is_reported():
    bad = _rule()
    bad["correlation_logic"]["join_keys"] = ["agent.id", "vibes.good"]
    with pytest.raises(RuleLoadError, match="vibes.good"):
        load_rule(bad)


def test_known_join_keys_are_the_six_standard_ones():
    assert set(KNOWN_JOIN_KEYS) == {
        "agent.id",
        "session.id",
        "agent.delegation_chain[*].agent_id",
        "memory.store_id",
        "tool.target_jurisdiction",
        "evidence.upstream_chain[*]",
    }


def test_a_session_chain_window_needs_a_max_session_count():
    bad = _rule()
    bad["correlation_logic"]["window"] = {"type": "session_chain", "max_wall_time": "30d"}
    with pytest.raises(RuleLoadError, match="max_session_count"):
        load_rule(bad)


def test_a_wall_time_window_needs_a_duration():
    bad = _rule()
    bad["correlation_logic"]["window"] = {"type": "wall_time"}
    with pytest.raises(RuleLoadError, match="duration"):
        load_rule(bad)


def test_a_wall_time_duration_must_match_the_pattern():
    bad = _rule()
    bad["correlation_logic"]["window"] = {"type": "wall_time", "duration": "30 minutes"}
    with pytest.raises(RuleLoadError, match="duration"):
        load_rule(bad)


# --- accessors --------------------------------------------------------------


def test_source_rule_lookup_by_alias():
    rule = load_rule(VALID)
    assert rule.source_rule("injection").rule_id == "ATR-2026-00002"
    assert rule.source_rule("exfil").rule_id == "ATR-2026-00020"


def test_sequence_aliases_are_ordered():
    rule = load_rule(VALID)
    assert rule.sequence == ("injection", "exfil")


def test_rule_exposes_its_window_type():
    rule = load_rule(VALID)
    assert rule.window_type == "wall_time"
    assert rule.window_duration == "30m"


# --- message rendering ------------------------------------------------------


def test_render_message_substitutes_alias_event_ids():
    rule = load_rule(VALID)
    text = render_message(
        rule,
        {
            "injection": {"event_id": "e-1"},
            "exfil": {"event_id": "e-9"},
        },
    )
    assert "e-1" in text and "e-9" in text
    assert "{injection.event_id}" not in text


def test_render_message_leaves_unknown_placeholders_alone():
    rule = load_rule(VALID)
    text = render_message(rule, {"injection": {"event_id": "e-1"}})
    assert "{exfil.event_id}" in text


# --- multi-rule loading -----------------------------------------------------


def test_load_rules_reads_a_directory_of_yaml(tmp_path):
    import yaml

    (tmp_path / "a.yaml").write_text(yaml.safe_dump(VALID))
    other = json.loads(json.dumps(VALID))
    other["correlation"]["id"] = "ATR-COR-2026-00002"
    other["correlation"]["title"] = "A second chain for the same class"
    (tmp_path / "b.yaml").write_text(yaml.safe_dump(other))

    rules = load_rules(tmp_path)
    assert len(rules) == 2
    assert {r.id for r in rules} == {"ATR-COR-2026-00001", "ATR-COR-2026-00002"}


def test_load_rules_rejects_duplicate_ids(tmp_path):
    import yaml

    (tmp_path / "a.yaml").write_text(yaml.safe_dump(VALID))
    (tmp_path / "b.yaml").write_text(yaml.safe_dump(VALID))
    with pytest.raises(RuleLoadError, match="duplicate"):
        load_rules(tmp_path)


def test_a_correlation_rule_object_can_be_built_directly():
    rule = CorrelationRule.from_dict(VALID)
    assert rule.id == "ATR-COR-2026-00001"
    assert rule.response_actions == ("alert", "snapshot", "quarantine")
    assert rule.severity_uplift == "critical"

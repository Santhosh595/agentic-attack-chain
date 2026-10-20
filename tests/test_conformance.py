"""Conformance gate for correlation rules.

ATR Correlation Rule Format v1.0 §"Conformance gate" states:

  - Engine MUST be able to load the rule (parse + validate).
  - Engine MUST evaluate the correlation against a fixture event stream
    included in the rule's `test_cases.true_positive_streams`.
  - Engine MUST NOT fire on `test_cases.true_negative_streams`.

This module is that gate, applied to every rule in rules/. It is the
test upstream does not have, and the directory it expects
(`tests/correlation-streams/<rule-id>/`) does not exist upstream.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aac.correlation import CorrelationEngine
from aac.observation import load_stream
from aac.rules import load_rules

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = REPO_ROOT / "rules"
STREAMS_DIR = REPO_ROOT / "tests" / "correlation-streams"


def _all_rules():
    return load_rules(RULES_DIR)


ALL_RULES = _all_rules()


def test_there_is_at_least_one_rule():
    assert ALL_RULES, "no correlation rules found in rules/"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_rule_loads_and_validates(rule):
    assert rule.id.startswith("ATR-COR-")
    assert rule.source_rules
    assert rule.join_keys


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_rule_declares_its_fixture_streams(rule):
    assert rule.true_positive_streams, f"{rule.id} declares no true-positive stream"
    assert rule.true_negative_streams, f"{rule.id} declares no true-negative stream"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_the_declared_streams_exist(rule):
    for relative in rule.true_positive_streams + rule.true_negative_streams:
        path = REPO_ROOT / relative
        assert path.is_file(), f"{rule.id} references a missing stream: {relative}"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_the_stream_directory_follows_the_upstream_convention(rule):
    """The spec's convention is tests/correlation-streams/<rule-id>/."""
    for relative in rule.true_positive_streams + rule.true_negative_streams:
        path = REPO_ROOT / relative
        assert path.parent.name == rule.id
        assert path.parent.parent.name == "correlation-streams"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_true_positive_stream_fires_exactly_once(rule):
    engine = CorrelationEngine([rule])
    for relative in rule.true_positive_streams:
        observations = load_stream((REPO_ROOT / relative).read_text().splitlines())
        engine.observe_all(observations)
    findings = engine.findings()
    assert len(findings) == 1, f"{rule.id} fired {len(findings)} times, expected 1"
    assert findings[0].rule_id == rule.id


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_true_negative_stream_does_not_fire(rule):
    engine = CorrelationEngine([rule])
    for relative in rule.true_negative_streams:
        observations = load_stream((REPO_ROOT / relative).read_text().splitlines())
        engine.observe_all(observations)
    assert engine.findings() == [], f"{rule.id} fired on a negative stream"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_the_finding_names_every_constituent_event(rule):
    """The spec: the output event must reference every constituent event id."""
    engine = CorrelationEngine([rule])
    relative = rule.true_positive_streams[0]
    observations = load_stream((REPO_ROOT / relative).read_text().splitlines())
    engine.observe_all(observations)
    finding = engine.findings()[0]
    assert len(finding.evidence) == len(observations)
    assert [e["observation.id"] for e in finding.evidence] == [
        o.observation_id for o in observations
    ]


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_the_finding_carries_the_rule_response(rule):
    engine = CorrelationEngine([rule])
    observations = load_stream((REPO_ROOT / rule.true_positive_streams[0]).read_text().splitlines())
    engine.observe_all(observations)
    finding = engine.findings()[0]
    assert finding.severity == rule.severity_uplift
    assert finding.actions == rule.response_actions
    assert finding.message


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_atomic_events_are_emitted_for_every_observation(rule):
    """Correlation must not block atomic emission."""
    engine = CorrelationEngine([rule])
    observations = load_stream((REPO_ROOT / rule.true_positive_streams[0]).read_text().splitlines())
    engine.observe_all(observations)
    assert len(engine.atomic_events()) == len(observations)


def test_every_fixture_observation_satisfies_the_observation_contract():
    """The fixture streams are observations, not the upstream's event shape.

    The upstream correlation spec's example fixture uses the older event
    shape (no observation.kind, no outcome). The observation spec
    supersedes it for correlation, so our streams carry the six required
    fields. This test keeps them honest.
    """
    for path in sorted(STREAMS_DIR.rglob("*.jsonl")):
        observations = load_stream(path.read_text().splitlines())
        assert observations, f"{path} is empty"
        for observation in observations:
            assert observation.kind
            assert observation.outcome
            assert observation.agent_id
            assert observation.session_id

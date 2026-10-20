"""Tests for the observation model (ATR Observation Format v1.0)."""

from __future__ import annotations

import datetime as dt

import pytest

from aac.observation import (
    OBSERVATION_KINDS,
    OUTCOMES,
    REQUIRED_FIELDS,
    Observation,
    ObservationError,
    canonical_host,
    canonical_url,
    load_stream,
    parse_timestamp,
)

BASE = {
    "@timestamp": "2026-05-25T10:00:00Z",
    "observation.id": "obs-1",
    "observation.kind": "tool_call",
    "agent.id": "agt-abc",
    "session.id": "sess-1",
    "outcome": "ok",
}


# --- required fields --------------------------------------------------------


@pytest.mark.parametrize("missing", REQUIRED_FIELDS)
def test_missing_required_field_is_rejected(missing):
    raw = {k: v for k, v in BASE.items() if k != missing}
    with pytest.raises(ObservationError, match=missing):
        Observation.from_dict(raw)


def test_empty_required_field_is_rejected():
    raw = dict(BASE, **{"agent.id": ""})
    with pytest.raises(ObservationError, match="agent.id"):
        Observation.from_dict(raw)


def test_observation_id_must_be_a_string():
    raw = dict(BASE, **{"observation.id": 42})
    with pytest.raises(ObservationError, match="observation.id"):
        Observation.from_dict(raw)


# --- enums ------------------------------------------------------------------


def test_outcome_outside_the_enum_is_rejected():
    with pytest.raises(ObservationError, match="outcome"):
        Observation.from_dict(dict(BASE, outcome="is_error"))


def test_all_six_outcomes_are_accepted():
    for outcome in OUTCOMES:
        obs = Observation.from_dict(dict(BASE, outcome=outcome))
        assert obs.outcome == outcome


def test_kind_outside_the_enum_is_rejected():
    with pytest.raises(ObservationError, match="observation.kind"):
        Observation.from_dict(dict(BASE, **{"observation.kind": "telepathy"}))


def test_all_twelve_kinds_are_accepted():
    for kind in OBSERVATION_KINDS:
        obs = Observation.from_dict(dict(BASE, **{"observation.kind": kind}))
        assert obs.kind == kind


# --- timestamps -------------------------------------------------------------


def test_parse_timestamp_accepts_trailing_z():
    parsed = parse_timestamp("2026-05-25T10:00:00Z")
    assert parsed == dt.datetime(2026, 5, 25, 10, 0, tzinfo=dt.timezone.utc)


def test_parse_timestamp_accepts_fractional_seconds():
    parsed = parse_timestamp("2026-07-29T09:14:02.113Z")
    assert parsed.microsecond == 113000


def test_parse_timestamp_rejects_naive_datetime():
    with pytest.raises(ValueError, match="timezone"):
        parse_timestamp("2026-05-25T10:00:00")


def test_parse_timestamp_preserves_offset():
    parsed = parse_timestamp("2026-05-25T10:00:00+05:30")
    assert parsed.utcoffset() == dt.timedelta(hours=5, minutes=30)


# --- delegation.root --------------------------------------------------------


def test_delegation_root_defaults_to_session_id():
    obs = Observation.from_dict(BASE)
    assert obs.delegation_root == "sess-1"


def test_delegation_root_is_kept_when_supplied():
    obs = Observation.from_dict(dict(BASE, **{"delegation.root": "sess-root"}))
    assert obs.delegation_root == "sess-root"


def test_delegation_root_survives_a_session_change():
    """The whole point of the field: a sub-agent gets a fresh session id.

    Grouping by session.id alone would split this into two buckets and
    nothing would correlate. Grouping by delegation.root keeps it together.
    """
    first = Observation.from_dict(dict(BASE, **{"session.id": "sess-4419"}))
    second = Observation.from_dict(
        dict(
            BASE,
            **{
                "session.id": "sess-4420",
                "delegation.root": "sess-4419",
                "observation.id": "obs-2",
            },
        )
    )
    assert first.session_id != second.session_id
    assert first.delegation_root == second.delegation_root


# --- dimension-specific fields ---------------------------------------------


def test_kind_specific_fields_are_preserved():
    obs = Observation.from_dict(
        dict(BASE, **{"tool.name": "shell.exec", "file.path": "/etc/passwd"})
    )
    assert obs.fields["tool.name"] == "shell.exec"
    assert obs.fields["file.path"] == "/etc/passwd"


def test_get_resolves_standard_keys():
    obs = Observation.from_dict(dict(BASE, **{"tool.name": "shell.exec"}))
    assert obs.get("agent.id") == "agt-abc"
    assert obs.get("session.id") == "sess-1"
    assert obs.get("outcome") == "ok"
    assert obs.get("tool.name") == "shell.exec"


def test_get_returns_none_for_an_absent_key():
    obs = Observation.from_dict(BASE)
    assert obs.get("memory.store_id") is None


def test_get_all_wraps_a_scalar_and_passes_a_list_through():
    obs = Observation.from_dict(
        dict(BASE, **{"evidence.upstream_chain": ["a", "b"], "memory.store_id": "m1"})
    )
    assert obs.get_all("evidence.upstream_chain") == ["a", "b"]
    assert obs.get_all("memory.store_id") == ["m1"]
    assert obs.get_all("nothing.here") == []


# --- round trip -------------------------------------------------------------


def test_to_dict_round_trips_through_from_dict():
    original = Observation.from_dict(
        dict(BASE, **{"tool.name": "shell.exec", "delegation.root": "sess-root"})
    )
    again = Observation.from_dict(original.to_dict())
    assert again.to_dict() == original.to_dict()


def test_to_dict_emits_utc_z_suffix():
    obs = Observation.from_dict(BASE)
    assert obs.to_dict()["@timestamp"] == "2026-05-25T10:00:00Z"


# --- canonicalisation -------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("example.com:8443", "example.com"),
        ("EXAMPLE.com:443", "example.com"),
        ("  example.com  ", "example.com"),
        (None, None),
    ],
)
def test_canonical_host(raw, expected):
    assert canonical_host(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://collect.example.net/path?q=1", "https://collect.example.net"),
        ("HTTPS://Collect.Example.NET:443/x", "https://collect.example.net"),
        ("http://example.net", "http://example.net"),
        (None, None),
    ],
)
def test_canonical_url(raw, expected):
    assert canonical_url(raw) == expected


# --- outcome semantics ------------------------------------------------------


def test_denied_refused_error_timeout_are_not_collapsed():
    """The spec forbids collapsing these into one boolean.

    A dense run of denials is boundary-probing; a run of errors is a broken
    agent. Flattening them to is_error makes the first invisible.
    """
    outcomes = ["denied", "refused", "error", "timeout"]
    flags = {
        o: Observation.from_dict(dict(BASE, outcome=o)).is_terminal_failure
        for o in outcomes
    }
    assert all(flags.values())


def test_ok_and_rate_limited_are_not_terminal_failures():
    assert not Observation.from_dict(dict(BASE, outcome="ok")).is_terminal_failure
    assert not Observation.from_dict(
        dict(BASE, outcome="rate_limited")
    ).is_terminal_failure


# --- stream loading ---------------------------------------------------------


def test_load_stream_reads_jsonl_in_order():
    lines = [
        '{"@timestamp":"2026-05-25T10:00:00Z","observation.id":"a","observation.kind":"tool_call","agent.id":"x","session.id":"s","outcome":"ok"}',
        "",
        "// a comment line",
        '{"@timestamp":"2026-05-25T10:00:01Z","observation.id":"b","observation.kind":"network","agent.id":"x","session.id":"s","outcome":"denied"}',
    ]
    observations = load_stream(lines)
    assert [o.observation_id for o in observations] == ["a", "b"]


def test_load_stream_reports_the_offending_line_number():
    lines = [
        '{"@timestamp":"2026-05-25T10:00:00Z","observation.id":"a","observation.kind":"tool_call","agent.id":"x","session.id":"s","outcome":"ok"}',
        "{not json}",
    ]
    with pytest.raises(ObservationError, match="line 2"):
        load_stream(lines)

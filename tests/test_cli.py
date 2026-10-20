"""Tests for the command-line interface."""

from __future__ import annotations

import json

from aac.cli import main

STREAM = """{"@timestamp":"2026-05-25T10:00:00Z","observation.id":"o1","observation.kind":"llm_io","agent.id":"agt-1","session.id":"sess-1","outcome":"ok","atr.rule_id":"ATR-2026-00002"}
{"@timestamp":"2026-05-25T10:00:30Z","observation.id":"o2","observation.kind":"tool_call","agent.id":"agt-1","session.id":"sess-1","outcome":"ok","atr.rule_id":"ATR-2026-00115"}
{"@timestamp":"2026-05-25T10:01:00Z","observation.id":"o3","observation.kind":"network","agent.id":"agt-1","session.id":"sess-1","outcome":"ok","atr.rule_id":"ATR-2026-00610"}
"""


def _write(tmp_path, text, name="stream.jsonl"):
    path = tmp_path / name
    path.write_text(text)
    return path


def test_correlate_reports_a_finding_and_exits_one(tmp_path, capsys):
    stream = _write(tmp_path, STREAM)
    code = main(["correlate", "--rules", str(tmp_path.parent / "x") if False else "rules",
                 "--stream", str(stream)])
    assert code == 1
    out = capsys.readouterr().out
    assert "ATR-COR-2026-00001" in out


def test_correlate_exits_zero_when_nothing_matches(tmp_path, capsys):
    benign = STREAM.replace("ATR-2026-00002", "ATR-2026-09999")
    stream = _write(tmp_path, benign)
    code = main(["correlate", "--rules", "rules", "--stream", str(stream)])
    assert code == 0
    assert "0 finding(s)" in capsys.readouterr().out


def test_correlate_can_emit_json(tmp_path, capsys):
    stream = _write(tmp_path, STREAM)
    main(["correlate", "--rules", "rules", "--stream", str(stream), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["atr.rule_id"] == "ATR-COR-2026-00001"
    assert payload["atomic_event_count"] == 3


def test_correlate_reports_a_missing_rule_directory(tmp_path, capsys):
    stream = _write(tmp_path, STREAM)
    code = main(["correlate", "--rules", str(tmp_path / "nope"), "--stream", str(stream)])
    assert code == 2
    assert "error" in capsys.readouterr().err


def test_correlate_reports_a_malformed_stream(tmp_path, capsys):
    stream = _write(tmp_path, "{not json}\n")
    code = main(["correlate", "--rules", "rules", "--stream", str(stream)])
    assert code == 2
    assert "error" in capsys.readouterr().err


def test_validate_lists_the_rules(capsys):
    code = main(["validate", "--rules", "rules"])
    assert code == 0
    out = capsys.readouterr().out
    assert "ATR-COR-2026-00001" in out
    assert "rule(s) valid" in out


def test_coverage_reports_the_declared_dimensions(capsys):
    code = main(["coverage"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["atr.observation_spec_version"] == "1.0"
    assert "file" in payload["uncovered_dimensions"]


def test_otel_mode_converts_spans(tmp_path, capsys):
    spans = json.dumps(
        {
            "name": "gen_ai.chat",
            "context": {"trace_id": "t1", "span_id": "s1"},
            "attributes": {
                "gen_ai.agent.id": "agt-1",
                "gen_ai.conversation.id": "sess-1",
                "atr.rule_id": "ATR-2026-00002",
            },
            "start_time": 1779000000_000_000_000,
        }
    )
    stream = _write(tmp_path, spans + "\n")
    code = main(["correlate", "--rules", "rules", "--stream", str(stream), "--otel", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["atomic_event_count"] == 1
    assert code == 0

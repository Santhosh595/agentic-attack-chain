"""Tests for the OpenTelemetry GenAI -> Observation bridge.

The OTel bridge is the named, requested gap upstream: ATR issue #70 lists
an "OpenTelemetry span exporter (TBD)" as a wanted reference
implementation, and no surveyed project bridges OTel GenAI telemetry to
agent attack-chain detection.

The bridge maps OTel GenAI semantic-convention span attributes onto the
ATR observation contract. The mapping is lossy in specific, declared ways
— that is the point of the observation spec's "declared coverage" section.
"""

from __future__ import annotations

import pytest

from aac.observation import Observation
from aac.otel import OTelBridge, BridgeError


def _span(
    name="gen_ai.chat.completion",
    attributes=None,
    trace_id="0af7651916cd43dd8448eb211c80319c",
    span_id="b7ad6b7169203331",
    start_time=None,
    status=None,
):
    """Build a minimal OTel span-shaped object."""
    attrs = {
        "gen_ai.system": "openai",
        "gen_ai.agent.id": "agt-abc",
        "gen_ai.conversation.id": "sess-1",
    }
    if attributes:
        attrs.update(attributes)
    span = {
        "name": name,
        "context": {"trace_id": trace_id, "span_id": span_id},
        "attributes": attrs,
        "start_time": start_time or 1779000000_000_000_000,
    }
    if status is not None:
        span["status"] = status
    return span


# --- mapping ----------------------------------------------------------------


def test_a_span_becomes_an_observation():
    bridge = OTelBridge()
    obs = bridge.to_observation(_span(), observation_id="obs-1")
    assert isinstance(obs, Observation)
    assert obs.agent_id == "agt-abc"
    assert obs.session_id == "sess-1"


def test_the_span_name_maps_to_an_observation_kind():
    bridge = OTelBridge()
    obs = bridge.to_observation(_span(name="gen_ai.execute_tool"), observation_id="obs-1")
    assert obs.kind == "tool_call"


def test_a_chat_span_maps_to_llm_io():
    bridge = OTelBridge()
    obs = bridge.to_observation(_span(name="gen_ai.chat.completion"), observation_id="obs-1")
    assert obs.kind == "llm_io"


def test_an_mcp_span_maps_to_mcp_exchange():
    bridge = OTelBridge()
    obs = bridge.to_observation(_span(name="mcp.client.call_tool"), observation_id="obs-1")
    assert obs.kind == "mcp_exchange"


def test_a_memory_span_maps_to_memory_access():
    bridge = OTelBridge()
    obs = bridge.to_observation(_span(name="gen_ai.memory.write"), observation_id="obs-1")
    assert obs.kind == "memory_access"


def test_an_agent_span_maps_to_multi_agent_comm():
    bridge = OTelBridge()
    obs = bridge.to_observation(_span(name="gen_ai.agent.delegate"), observation_id="obs-1")
    assert obs.kind == "multi_agent_comm"


def test_an_unknown_span_name_maps_to_agent_behavior():
    bridge = OTelBridge()
    obs = bridge.to_observation(_span(name="com.example.custom"), observation_id="obs-1")
    assert obs.kind == "agent_behavior"


def test_a_genai_tool_name_maps_to_a_tool_call():
    bridge = OTelBridge()
    obs = bridge.to_observation(
        _span(name="execute_tool", attributes={"gen_ai.tool.name": "shell.exec"}),
        observation_id="obs-1",
    )
    assert obs.kind == "tool_call"
    assert obs.get("tool.name") == "shell.exec"


# --- required attributes ----------------------------------------------------


def test_a_span_without_an_agent_id_is_rejected():
    bridge = OTelBridge()
    with pytest.raises(BridgeError, match="gen_ai.agent.id"):
        bridge.to_observation(_span(attributes={"gen_ai.agent.id": None}), observation_id="obs-1")


def test_a_span_without_a_conversation_id_is_rejected():
    bridge = OTelBridge()
    with pytest.raises(BridgeError, match="gen_ai.conversation.id"):
        bridge.to_observation(
            _span(attributes={"gen_ai.conversation.id": None}), observation_id="obs-1"
        )


def test_an_explicitly_empty_observation_id_is_rejected():
    """An empty id is not a usable identity.

    The id is normally derivable from the span, so the bridge falls back
    to derivation — but an explicitly empty string is a caller error, not
    a request to auto-number.
    """
    bridge = OTelBridge()
    with pytest.raises(BridgeError, match="observation.id"):
        bridge.to_observation(_span(span_id="", trace_id=""), observation_id="")


# --- outcome ----------------------------------------------------------------


def test_a_successful_span_maps_to_ok():
    bridge = OTelBridge()
    obs = bridge.to_observation(_span(), observation_id="obs-1")
    assert obs.outcome == "ok"


def test_an_error_status_maps_to_error():
    bridge = OTelBridge()
    obs = bridge.to_observation(
        _span(status={"code": "STATUS_CODE_ERROR", "message": "boom"}),
        observation_id="obs-1",
    )
    assert obs.outcome == "error"


def test_a_denied_status_maps_to_denied_not_error():
    """The observation spec forbids collapsing denials into a generic error.

    A denied call and a broken call look identical once flattened to
    is_error, and boundary-probing is invisible in the flattened form.
    """
    bridge = OTelBridge()
    obs = bridge.to_observation(
        _span(status={"code": "STATUS_CODE_ERROR", "message": "permission denied"}),
        observation_id="obs-1",
    )
    assert obs.outcome == "denied"


def test_a_refused_status_maps_to_refused():
    bridge = OTelBridge()
    obs = bridge.to_observation(
        _span(status={"code": "STATUS_CODE_UNSET", "message": "refused by guardrail"}),
        observation_id="obs-1",
    )
    assert obs.outcome == "refused"


def test_an_explicit_outcome_attribute_wins():
    bridge = OTelBridge()
    obs = bridge.to_observation(
        _span(attributes={"gen_ai.outcome": "rate_limited"}), observation_id="obs-1"
    )
    assert obs.outcome == "rate_limited"


# --- delegation -------------------------------------------------------------


def test_delegation_root_defaults_to_the_conversation_id():
    bridge = OTelBridge()
    obs = bridge.to_observation(_span(), observation_id="obs-1")
    assert obs.delegation_root == "sess-1"


def test_a_delegation_root_attribute_is_honoured():
    bridge = OTelBridge()
    obs = bridge.to_observation(
        _span(attributes={"gen_ai.agent.delegation_root": "sess-root"}), observation_id="obs-1"
    )
    assert obs.delegation_root == "sess-root"


# --- timestamps -------------------------------------------------------------


def test_the_span_start_time_becomes_the_observation_timestamp():
    bridge = OTelBridge()
    obs = bridge.to_observation(
        _span(start_time=1779000000_000_000_000), observation_id="obs-1"
    )
    assert obs.timestamp.isoformat().startswith("2026-")


# --- passthrough fields -----------------------------------------------------


def test_target_host_is_canonicalised():
    bridge = OTelBridge()
    obs = bridge.to_observation(
        _span(name="gen_ai.network.request", attributes={"server.address": "Evil.Example.NET:443"}),
        observation_id="obs-1",
    )
    assert obs.get("target.host") == "evil.example.net"


def test_a_rule_id_attribute_is_carried_through():
    """The bridge must not drop atr.rule_id — that is how a span becomes
    a constituent event of a correlation chain."""
    bridge = OTelBridge()
    obs = bridge.to_observation(
        _span(attributes={"atr.rule_id": "ATR-2026-00002"}), observation_id="obs-1"
    )
    assert obs.get("atr.rule_id") == "ATR-2026-00002"


def test_arbitrary_attributes_are_preserved_under_their_own_names():
    bridge = OTelBridge()
    obs = bridge.to_observation(
        _span(attributes={"memory.store_id": "mem-xyz"}), observation_id="obs-1"
    )
    assert obs.get("memory.store_id") == "mem-xyz"


# --- declared coverage ------------------------------------------------------


def test_the_bridge_declares_the_dimensions_it_covers():
    bridge = OTelBridge()
    coverage = bridge.coverage()
    assert coverage["atr.observation_spec_version"] == "1.0"
    assert "llm_io" in coverage["covered_dimensions"]
    assert "tool_call" in coverage["covered_dimensions"]


def test_the_bridge_declares_dimensions_it_cannot_observe():
    """Spans carry no file or process detail, so the bridge must say so.

    The observation spec is explicit that reporting "could not look" as
    "looked and found nothing" is how a coverage number becomes a lie.
    """
    bridge = OTelBridge()
    coverage = bridge.coverage()
    assert "file" in coverage["uncovered_dimensions"]
    assert "process" in coverage["uncovered_dimensions"]


# --- batch conversion -------------------------------------------------------


def test_a_batch_of_spans_converts_in_order():
    bridge = OTelBridge()
    spans = [_span(), _span(span_id="b7ad6b7169203332")]
    observations = bridge.to_observations(spans)
    assert len(observations) == 2
    assert observations[0].observation_id != observations[1].observation_id


def test_observation_ids_are_derived_from_the_span_when_not_supplied():
    bridge = OTelBridge()
    obs = bridge.to_observation(_span())
    assert obs.observation_id

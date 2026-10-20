"""OpenTelemetry GenAI span -> ATR Observation bridge.

Upstream ATR issue #70 names an "OpenTelemetry span exporter (TBD)" as a
wanted reference implementation. This module is that bridge: it converts
OTel GenAI spans into the observation contract that correlation needs.

Two things this module is careful about:

1. It does not invent coverage. A span carries no file-operation detail
   and no process detail, so the bridge declares those dimensions
   uncovered. The observation spec is explicit that reporting "could not
   look" as "looked and found nothing" is how a coverage number becomes
   a lie.

2. It does not collapse outcomes. A denied call, a refused call and a
   broken call are three different things, and the difference is what
   makes boundary-probing visible.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Iterable, Mapping

from .observation import Observation, canonical_host, canonical_url

# Span-name -> observation.kind.
#
# The OTel GenAI conventions name spans by operation. The observation
# spec's `observation.kind` is the dimension the observation belongs to.
# Matching is longest-prefix so "gen_ai.chat.completion" and
# "gen_ai.execute_tool" both land correctly.
_SPAN_KIND_PREFIXES: tuple[tuple[str, str], ...] = (
    ("gen_ai.execute_tool", "tool_call"),
    ("gen_ai.tool", "tool_call"),
    ("execute_tool", "tool_call"),
    ("mcp.client", "mcp_exchange"),
    ("mcp.server", "mcp_exchange"),
    ("mcp.", "mcp_exchange"),
    ("gen_ai.memory", "memory_access"),
    ("memory.", "memory_access"),
    ("gen_ai.agent.delegate", "multi_agent_comm"),
    ("gen_ai.agent", "multi_agent_comm"),
    ("gen_ai.chat", "llm_io"),
    ("gen_ai.generate_content", "llm_io"),
    ("gen_ai.embeddings", "llm_io"),
    ("gen_ai.inference", "llm_io"),
    ("gen_ai.skill", "skill_lifecycle"),
    ("gen_ai.context", "context_window"),
    ("gen_ai.network", "network"),
    ("http.", "network"),
)

# Dimensions a GenAI span can actually carry. Everything else in the
# observation spec's kind list is not observable from a span, and the
# bridge says so rather than pretending.
COVERED_DIMENSIONS = (
    "llm_io",
    "tool_call",
    "tool_response",
    "mcp_exchange",
    "multi_agent_comm",
    "memory_access",
    "skill_lifecycle",
    "context_window",
    "agent_behavior",
    "network",
)

UNCOVERED_DIMENSIONS = ("file", "process")

# Attribute -> observation field, for the fields the conventions name.
_ATTR_TO_FIELD = {
    "gen_ai.tool.name": "tool.name",
    "gen_ai.tool.call.id": "tool.call_id",
    "server.address": "target.host",
    "server.port": "target.port",
    "url.full": "target.url",
    "gen_ai.memory.store_id": "memory.store_id",
    "gen_ai.agent.delegation_root": "delegation.root",
    "gen_ai.agent.delegation_chain": "agent.delegation_chain",
    "gen_ai.file.path": "file.path",
    "gen_ai.file.operation": "file.operation",
    "gen_ai.process.executable": "process.executable",
    "gen_ai.process.argv": "process.argv",
    "gen_ai.prompt": "content",
    "gen_ai.completion": "content",
}

# Attributes the bridge consumes itself rather than copying through.
_CONSUMED_ATTRS = frozenset(
    {
        "gen_ai.system",
        "gen_ai.agent.id",
        "gen_ai.conversation.id",
        "gen_ai.outcome",
    }
)


class BridgeError(ValueError):
    """Raised when a span cannot be converted into a valid observation."""


def _span_kind(name: str) -> str:
    lowered = name.lower()
    for prefix, kind in _SPAN_KIND_PREFIXES:
        if lowered.startswith(prefix):
            return kind
    return "agent_behavior"


def _outcome(span: Mapping[str, Any], attributes: Mapping[str, Any]) -> str:
    """Map a span's status onto the observation outcome enum.

    The observation spec forbids collapsing denied / refused / error /
    timeout into one boolean, so the message text is inspected before
    falling back to a generic error.
    """
    explicit = attributes.get("gen_ai.outcome")
    if isinstance(explicit, str) and explicit:
        return explicit

    status = span.get("status") or {}
    code = str(status.get("code", "") or "")
    message = str(status.get("message", "") or "").lower()

    if code.upper().endswith("ERROR") or message:
        if "denied" in message or "permission" in message or "forbidden" in message:
            return "denied"
        if "refused" in message or "guardrail" in message or "blocked by" in message:
            return "refused"
        if "timeout" in message or "timed out" in message:
            return "timeout"
        if "rate" in message and "limit" in message:
            return "rate_limited"
        return "error"
    return "ok"


def _timestamp(span: Mapping[str, Any]) -> dt.datetime:
    """Convert a span's start time into an aware datetime."""
    raw = span.get("start_time")
    if raw is None:
        return dt.datetime.now(dt.timezone.utc)
    if isinstance(raw, dt.datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=dt.timezone.utc)
    # OpenTelemetry uses nanoseconds since the epoch.
    seconds = int(raw) / 1_000_000_000
    return dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc)


class OTelBridge:
    """Converts OTel GenAI spans into ATR observations."""

    def __init__(self) -> None:
        self._counter = 0

    # -- conversion ---------------------------------------------------------

    def to_observation(
        self, span: Mapping[str, Any], observation_id: str | None = None
    ) -> Observation:
        """Convert one span into an observation."""
        attributes = span.get("attributes") or {}

        agent_id = attributes.get("gen_ai.agent.id")
        if not agent_id:
            raise BridgeError(
                "span is missing gen_ai.agent.id; a correlation rule grouped by "
                "an absent field is a coin flip, not a detection"
            )
        session_id = attributes.get("gen_ai.conversation.id")
        if not session_id:
            raise BridgeError(
                "span is missing gen_ai.conversation.id; correlation requires it"
            )

        obs_id = self._resolve_id(span, observation_id)
        if not obs_id:
            raise BridgeError("observation.id must be supplied or derivable from the span")

        kind = _span_kind(str(span.get("name", "")))
        outcome = _outcome(span, attributes)

        fields: dict[str, Any] = {}
        for attribute, field_name in _ATTR_TO_FIELD.items():
            if attribute in attributes and attributes[attribute] is not None:
                fields[field_name] = attributes[attribute]

        # Canonicalise the target fields so two observations that name the
        # same target produce the same join value.
        if "target.host" in fields:
            fields["target.host"] = canonical_host(fields["target.host"])
        if "target.url" in fields:
            fields["target.url"] = canonical_url(fields["target.url"])

        # Carry through any attribute the host already tagged with an ATR
        # rule id or category — that is how a span becomes a constituent
        # event of a correlation chain.
        for passthrough in ("atr.rule_id", "atr.category", "evidence.upstream_chain"):
            if passthrough in attributes:
                fields[passthrough] = attributes[passthrough]

        # Carry through any remaining attribute under its own name.
        #
        # A span may carry fields this bridge has never heard of —
        # memory.store_id, tool.target_jurisdiction, an evidence chain
        # from the host's own instrumentation. Those are exactly the
        # fields correlation rules join on, so dropping them would
        # silently break rules whose join key the bridge does not
        # remap. The only attributes consumed are the ones above.
        for attribute, value in attributes.items():
            if attribute in _ATTR_TO_FIELD or attribute in _CONSUMED_ATTRS:
                continue
            if value is None:
                continue
            fields[attribute] = value

        delegation_root = fields.pop("delegation.root", None) or session_id

        raw = {
            "@timestamp": _timestamp(span).isoformat().replace("+00:00", "Z"),
            "observation.id": obs_id,
            "observation.kind": kind,
            "agent.id": agent_id,
            "session.id": session_id,
            "delegation.root": delegation_root,
            "outcome": outcome,
        }
        raw.update(fields)
        return Observation.from_dict(raw)

    def to_observations(
        self, spans: Iterable[Mapping[str, Any]]
    ) -> list[Observation]:
        """Convert a batch of spans, skipping the ones that cannot convert."""
        observations: list[Observation] = []
        for span in spans:
            try:
                observations.append(self.to_observation(span))
            except BridgeError:
                continue
        return observations

    # -- identity -----------------------------------------------------------

    def _derive_id(self, span: Mapping[str, Any]) -> str:
        """Derive a stable observation id from the span's identity."""
        context = span.get("context") or {}
        trace_id = context.get("trace_id")
        span_id = context.get("span_id")
        if trace_id and span_id:
            return f"obs-{trace_id}-{span_id}"
        self._counter += 1
        return f"obs-auto-{self._counter:08d}"

    def _resolve_id(self, span: Mapping[str, Any], observation_id: str | None) -> str:
        """Resolve the observation id, distinguishing absent from empty.

        None means "derive one for me". An explicit empty string is a
        caller error: silently auto-numbering it would give the caller an
        id they did not ask for, and the resulting evidence chain would
        cite a name that appears nowhere in the source telemetry.
        """
        if observation_id is None:
            return self._derive_id(span)
        if not observation_id.strip():
            raise BridgeError(
                "observation.id was supplied as an empty string; pass None to "
                "derive an id from the span"
            )
        return observation_id

    # -- coverage -----------------------------------------------------------

    def coverage(self) -> dict[str, Any]:
        """Report which observation dimensions this bridge can observe."""
        return {
            "atr.observation_spec_version": "1.0",
            "covered_dimensions": list(COVERED_DIMENSIONS),
            "uncovered_dimensions": list(UNCOVERED_DIMENSIONS),
        }

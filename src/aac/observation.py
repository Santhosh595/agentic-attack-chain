"""Observation model — the input side of correlation.

Implements the required-field contract from ATR Observation Format v1.0
(spec/atr-observation-v1.0.md). The spec makes six fields required and
keeps `delegation.root` recommended-but-always-populated, because grouping
by `session.id` alone is trivially defeated by sub-agent spawning.

Every field name below is the literal dotted name the spec uses on the wire
("agent.id", "session.id", "observation.kind", ...). We keep them as literal
keys rather than nesting, because the correlation spec's join keys are
XPath-like strings into "the event JSON" and the fixture streams in the
upstream spec use the flat form. Flat keys keep one canonical spelling
between the observation, the rule and the fixture.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# --- Enums, verbatim from spec §3 and §4 -----------------------------------

OUTCOMES = ("ok", "error", "denied", "refused", "timeout", "rate_limited")

OBSERVATION_KINDS = (
    # The first nine map onto agent_source.type in the rule schema.
    "llm_io",
    "tool_call",
    "tool_response",
    "mcp_exchange",
    "multi_agent_comm",
    "memory_access",
    "skill_lifecycle",
    "context_window",
    "agent_behavior",
    # These three are defined by the observation spec and have no
    # corresponding rules in the canonical corpus yet.
    "network",
    "file",
    "process",
)

# The nine kinds the canonical corpus can already express.
CORPUS_COVERABLE_KINDS = OBSERVATION_KINDS[:9]

REQUIRED_FIELDS = (
    "@timestamp",
    "observation.id",
    "observation.kind",
    "agent.id",
    "session.id",
    "outcome",
)

# --- Canonicalisation helpers (spec §4.1) ----------------------------------

_HOST_PORT_RE = re.compile(r"^(?P<host>\[[0-9a-f:]+\]|[^:]+):(?P<port>\d+)$", re.I)


def canonical_host(host: str | None) -> str | None:
    """Lowercase a hostname and strip the port.

    The observation spec requires canonicalisation before any join: two
    observations that refer to the same target but produce different join
    values will silently never correlate, and the rule author will conclude
    the engine is broken.
    """
    if host is None:
        return None
    value = host.strip().lower()
    match = _HOST_PORT_RE.match(value)
    if match:
        return match.group("host")
    return value


def canonical_url(url: str | None) -> str | None:
    """Reduce a URL to scheme and host, dropping path, query and fragment.

    The port goes too: the spec strips it from bare hostnames, and keeping
    it here would make the same target produce two different join values
    depending on which field the rule joined on.
    """
    if url is None:
        return None
    value = url.strip().lower()
    if "//" not in value:
        return value
    scheme, _, rest = value.partition("//")
    if not rest:
        return value
    host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = canonical_host(host) or host
    return f"{scheme}//{host}" if scheme else host


def parse_timestamp(value: str) -> _dt.datetime:
    """Parse an RFC 3339 timestamp into an aware datetime.

    Accepts a trailing "Z", which datetime.fromisoformat rejects on
    Python < 3.11. Fractional seconds are optional.
    """
    if not isinstance(value, str):
        raise TypeError(f"@timestamp must be a string, got {type(value).__name__}")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = _dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError(f"@timestamp must carry a timezone offset: {value!r}")
    return parsed


class ObservationError(ValueError):
    """Raised when an observation does not satisfy the required-field contract."""


@dataclass(slots=True)
class Observation:
    """One atomic observation, in the flat dotted-key form the specs use."""

    timestamp: _dt.datetime
    observation_id: str
    kind: str
    agent_id: str
    session_id: str
    outcome: str
    delegation_root: str
    fields: dict[str, Any] = field(default_factory=dict)

    # -- construction -------------------------------------------------------

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Observation":
        """Build an observation from a flat dotted-key mapping.

        Raises ObservationError when a required field is missing, has the
        wrong type, or holds a value outside its enum. We validate eagerly:
        the spec's whole argument is that a correlation rule grouped by a
        field that may be absent "is not a detection, it is a coin flip".
        """
        missing = [name for name in REQUIRED_FIELDS if raw.get(name) in (None, "")]
        if missing:
            raise ObservationError(f"missing required field(s): {', '.join(missing)}")

        kind = raw["observation.kind"]
        if kind not in OBSERVATION_KINDS:
            raise ObservationError(
                f"observation.kind {kind!r} is not one of {OBSERVATION_KINDS}"
            )

        outcome = raw["outcome"]
        if outcome not in OUTCOMES:
            raise ObservationError(f"outcome {outcome!r} is not one of {OUTCOMES}")

        for name in ("observation.id", "agent.id", "session.id"):
            if not isinstance(raw[name], str):
                raise ObservationError(f"{name} must be a string")

        session_id = raw["session.id"]
        # The spec says delegation.root MUST equal session.id when the agent
        # is not a delegate, and is always populated.
        delegation_root = raw.get("delegation.root") or session_id

        fields = {
            key: value
            for key, value in raw.items()
            if key not in REQUIRED_FIELDS and key != "delegation.root"
        }

        return cls(
            timestamp=parse_timestamp(raw["@timestamp"]),
            observation_id=raw["observation.id"],
            kind=kind,
            agent_id=raw["agent.id"],
            session_id=session_id,
            outcome=outcome,
            delegation_root=delegation_root,
            fields=fields,
        )

    # -- serialisation ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return the flat dotted-key wire form."""
        out: dict[str, Any] = {
            "@timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "observation.id": self.observation_id,
            "observation.kind": self.kind,
            "agent.id": self.agent_id,
            "session.id": self.session_id,
            "delegation.root": self.delegation_root,
            "outcome": self.outcome,
        }
        out.update(self.fields)
        return out

    # -- join-key access ----------------------------------------------------

    def get(self, key: str) -> Any:
        """Look up a value by its wire name, including the standard fields.

        Correlation join keys are written as "agent.id", "session.id" and
        "evidence.upstream_chain[*]" — strings into the event JSON. This
        resolves the six standard keys to their typed attributes and falls
        through to the dimension-specific fields.
        """
        standard = {
            "@timestamp": self.timestamp,
            "observation.id": self.observation_id,
            "observation.kind": self.kind,
            "agent.id": self.agent_id,
            "session.id": self.session_id,
            "delegation.root": self.delegation_root,
            "outcome": self.outcome,
        }
        if key in standard:
            return standard[key]
        return self.fields.get(key)

    def get_all(self, key: str) -> list[Any]:
        """Resolve a key that may hold a list (the "[*]" form)."""
        value = self.get(key)
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return list(value)
        return [value]

    @property
    def is_terminal_failure(self) -> bool:
        """True when the action failed in a way that is not a policy refusal.

        The observation spec is explicit that denied / refused / error /
        timeout MUST NOT be collapsed into one boolean, because the signal
        for boundary-probing is a dense run of denials, which looks
        identical to breakage if you flatten it.
        """
        return self.outcome in ("denied", "refused", "error", "timeout")


def load_stream(lines: Iterable[str]) -> list[Observation]:
    """Load a JSONL fixture stream into observations, in file order."""
    import json

    observations: list[Observation] = []
    for number, line in enumerate(lines, start=1):
        text = line.strip()
        if not text or text.startswith("//"):
            continue
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ObservationError(f"line {number} is not valid JSON: {exc}") from exc
        observations.append(Observation.from_dict(raw))
    return observations

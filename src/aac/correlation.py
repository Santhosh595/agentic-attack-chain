"""Correlation engine — the layer that does not exist upstream.

ATR's correlation spec (spec/atr-correlation-v1.0.md) is written, detailed
and unratified, and no engine implements it. The TypeScript production
engine has an ad-hoc per-rule sequence tracker keyed on sessionId alone.

This module implements the spec's five correlation types over the
observation contract, with two properties the upstream tracker lacks:

  - join keys that survive a sub-agent hop (delegation.root)
  - bounded state with an explicit eviction signal, as the spec requires

Design notes that matter for correctness:

  * Atomic emission never blocks on correlation. An observation is always
    recorded as an atomic event immediately; correlation findings are
    produced separately when a chain completes. The spec is explicit that
    "correlation evaluation MUST NOT block atomic-rule emission".

  * Join keys are ANDed. The spec's negative fixture is "same steps,
    different agent.id -> MUST NOT correlate", so a rule listing two join
    keys requires both to match.

  * A chain is identified by its join-key values. Two events with the same
    join values belong to the same chain; different values are different
    chains. This is what makes the join-key mismatch work.

  * The sequence matcher is a small explicit state machine rather than a
    regex, because the spec forbids catastrophic backtracking and requires
    O(1) state update per event.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .observation import Observation
from .rules import CorrelationRule, render_message

# Maximum pending chains kept per rule before the oldest is evicted.
DEFAULT_MAX_PENDING = 1000

# How long a completed chain stays retrievable, in findings().
_FINDING_RETENTION = 256


def _parse_duration(text: str) -> dt.timedelta:
    """Turn "30m" / "24h" / "7d" / "45s" into a timedelta."""
    unit = text[-1]
    value = int(text[:-1])
    if unit == "s":
        return dt.timedelta(seconds=value)
    if unit == "m":
        return dt.timedelta(minutes=value)
    if unit == "h":
        return dt.timedelta(hours=value)
    if unit == "d":
        return dt.timedelta(days=value)
    raise ValueError(f"unsupported duration {text!r}")


@dataclass(slots=True)
class _Pending:
    """A partially matched chain, waiting for its next step."""

    rule_id: str
    join_values: tuple[Any, ...]
    progress: int
    events: list[Observation]
    aliases: list[str]
    first_seen: dt.datetime
    last_seen: dt.datetime
    sessions: set[str]


@dataclass(slots=True)
class CorrelationFinding:
    """One completed attack chain."""

    rule_id: str
    title: str
    severity: str
    actions: tuple[str, ...]
    message: str
    evidence: list[dict[str, Any]]
    aliases: list[str]
    detected_at: dt.datetime
    bindings: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise as an ATR-shaped correlation event.

        The spec says the engine "MUST emit one correlation event after
        consuming" the chain, "referencing all four event IDs in
        evidence.upstream_chain of the output event".
        """
        return {
            "event.type": "correlation",
            "atr.rule_id": self.rule_id,
            "atr.category": "attack-chain",
            "atr.title": self.title,
            "atr.severity": self.severity,
            "atr.actions": list(self.actions),
            "atr.message": self.message,
            "@timestamp": self.detected_at.isoformat().replace("+00:00", "Z"),
            "evidence.upstream_chain": [e.get("observation.id") for e in self.evidence],
            "evidence.events": self.evidence,
        }


class CorrelationEngine:
    """Evaluates observations against a set of correlation rules."""

    def __init__(
        self,
        rules: Sequence[CorrelationRule],
        max_pending: int = DEFAULT_MAX_PENDING,
    ) -> None:
        self.rules = list(rules)
        self.max_pending = max_pending
        self._pending: dict[str, list[_Pending]] = {rule.id: [] for rule in self.rules}
        self._findings: list[CorrelationFinding] = []
        self._atomic: list[dict[str, Any]] = []
        self._events: list[dict[str, Any]] = []
        self._seen_observation_ids: set[str] = set()
        self.evictions = 0

    # -- ingestion ----------------------------------------------------------

    def observe(self, observation: Observation) -> None:
        """Record one observation.

        The observation is deduplicated on observation.id, recorded as an
        atomic event immediately, and then offered to every rule.
        """
        if observation.observation_id in self._seen_observation_ids:
            return
        self._seen_observation_ids.add(observation.observation_id)

        atomic = observation.to_dict()
        atomic["event.type"] = "atomic"
        self._atomic.append(atomic)

        for rule in self.rules:
            self._apply(rule, observation)

    def observe_all(self, observations: Iterable[Observation]) -> None:
        for observation in observations:
            self.observe(observation)

    # -- rule dispatch ------------------------------------------------------

    def _apply(self, rule: CorrelationRule, observation: Observation) -> None:
        alias = self._match_alias(rule, observation)
        if alias is None:
            return

        logic = rule.logic_type
        if logic == "count_threshold":
            self._apply_count_threshold(rule, observation, alias)
        elif logic == "value_overlap":
            self._apply_value_overlap(rule, observation, alias)
        elif logic == "chain_propagation":
            self._apply_chain_propagation(rule, observation, alias)
        else:
            self._apply_sequence(rule, observation, alias)

    def _match_alias(self, rule: CorrelationRule, observation: Observation) -> str | None:
        """Return the source-rule alias this observation satisfies, if any.

        Matching runs in specificity order: an exact rule_id beats a
        category, which beats a rule_id_pattern. Order matters because a
        pattern is a prefix glob — "ATR-2026-000*" also matches
        "ATR-2026-00020", so a naive first-match-wins scan would let an
        earlier pattern alias swallow a later exact id. The upstream spec
        says to prefer explicit rule_id values over patterns for exactly
        this reason.
        """
        rule_id = observation.get("atr.rule_id")
        category = observation.get("atr.category")

        for source in rule.source_rules:
            if source.rule_id is not None and rule_id == source.rule_id:
                return source.alias

        for source in rule.source_rules:
            if source.category is not None and category == source.category:
                return source.alias

        for source in rule.source_rules:
            if source.rule_id_pattern is not None and isinstance(rule_id, str):
                if fnmatch.fnmatchcase(rule_id, source.rule_id_pattern):
                    return source.alias

        return None

    # -- join keys ----------------------------------------------------------

    def _join_values(self, rule: CorrelationRule, observation: Observation) -> tuple[Any, ...]:
        values = []
        for key in rule.join_keys:
            values.append(tuple(sorted(map(str, observation.get_all(key)))) if key.endswith("[*]") else observation.get(key))
        return tuple(values)

    def _same_join(self, rule: CorrelationRule, observation: Observation, pending: _Pending) -> bool:
        return self._join_values(rule, observation) == pending.join_values

    # -- sequence correlation (temporal_sequence / temporal_unordered) -------

    def _apply_sequence(
        self, rule: CorrelationRule, observation: Observation, alias: str
    ) -> None:
        pending_list = self._pending[rule.id]
        ordered = rule.logic_type == "temporal_sequence"

        for pending in pending_list:
            if not self._same_join(rule, observation, pending):
                continue
            if not self._within_window(rule, pending, observation):
                continue
            if not self._advances(rule, pending, observation, alias, ordered):
                continue

            pending.events.append(observation)
            pending.aliases.append(alias)
            pending.last_seen = observation.timestamp
            pending.sessions.add(observation.session_id)
            pending.progress += 1
            if pending.progress >= len(rule.sequence):
                self._emit(rule, pending)
            return

        # No pending chain matched: start a new one.
        #
        # For an ordered sequence only the FIRST alias can open a chain.
        # For an unordered sequence any alias in the sequence can open one,
        # because the spec does not constrain the order — a chain that
        # begins with the exfiltration is still the same chain.
        if rule.sequence and (rule.sequence[0] == alias or not ordered):
            pending = _Pending(
                rule_id=rule.id,
                join_values=self._join_values(rule, observation),
                progress=1,
                events=[observation],
                aliases=[alias],
                first_seen=observation.timestamp,
                last_seen=observation.timestamp,
                sessions={observation.session_id},
            )
            pending_list.append(pending)
            self._evict_if_needed(rule)

    def _advances(
        self,
        rule: CorrelationRule,
        pending: _Pending,
        observation: Observation,
        alias: str,
        ordered: bool,
    ) -> bool:
        """Would this observation advance the pending chain?

        Ordered: the alias must be the next one in the declared sequence,
        and the observation must not precede the previous step.
        Unordered: the alias must be in the sequence and not already used
        by this chain.
        """
        if ordered:
            if pending.progress >= len(rule.sequence):
                return False
            if rule.sequence[pending.progress] != alias:
                return False
            return observation.timestamp >= pending.last_seen

        if alias not in rule.sequence:
            return False
        if alias in pending.aliases:
            return False
        return True

    def _within_window(
        self, rule: CorrelationRule, pending: _Pending, observation: Observation
    ) -> bool:
        window = rule.window_type
        if window == "wall_time":
            delta = observation.timestamp - pending.first_seen
            return delta <= _parse_duration(rule.window_duration or "0s")
        if window == "session_chain":
            max_sessions = rule.window_max_session_count or 1
            sessions = pending.sessions | {observation.session_id}
            if len(sessions) > max_sessions:
                return False
            if rule.window_duration:
                delta = observation.timestamp - pending.first_seen
                if delta > _parse_duration(rule.window_duration):
                    return False
            return True
        if window == "chain_depth":
            return len(pending.events) < (rule.window_max_depth or 2)
        return True  # unbounded

    # -- count_threshold ----------------------------------------------------

    def _apply_count_threshold(
        self, rule: CorrelationRule, observation: Observation, alias: str
    ) -> None:
        threshold = rule.count_threshold or 1
        target_alias = rule.count_alias
        if target_alias is not None and alias != target_alias:
            return

        pending_list = self._pending[rule.id]
        join_values = self._join_values(rule, observation)
        for pending in pending_list:
            if pending.join_values != join_values:
                continue
            if not self._within_window(rule, pending, observation):
                continue
            pending.events.append(observation)
            pending.aliases.append(alias)
            pending.last_seen = observation.timestamp
            pending.sessions.add(observation.session_id)
            if len(pending.events) >= threshold:
                self._emit(rule, pending)
            return

        pending_list.append(
            _Pending(
                rule_id=rule.id,
                join_values=join_values,
                progress=1,
                events=[observation],
                aliases=[alias],
                first_seen=observation.timestamp,
                last_seen=observation.timestamp,
                sessions={observation.session_id},
            )
        )
        self._evict_if_needed(rule)

    # -- value_overlap -------------------------------------------------------

    def _apply_value_overlap(
        self, rule: CorrelationRule, observation: Observation, alias: str
    ) -> None:
        field_name = rule.value_overlap_field
        if not field_name:
            return
        value = observation.get(field_name)
        if value is None:
            return

        pending_list = self._pending[rule.id]
        for pending in pending_list:
            if not self._same_join(rule, observation, pending):
                continue
            if not self._within_window(rule, pending, observation):
                continue
            pending.events.append(observation)
            pending.aliases.append(alias)
            pending.last_seen = observation.timestamp
            pending.sessions.add(observation.session_id)
            if len(pending.events) >= 2:
                # "Two or more source rules fire AND share a common value in
                # a named field" — the value must be shared between the
                # events, not equal across all of them. Two different
                # events pointing at the same target is the overlap.
                values = [e.get(field_name) for e in pending.events]
                if len(set(values)) < len(values):
                    self._emit(rule, pending)
            return

        pending_list.append(
            _Pending(
                rule_id=rule.id,
                join_values=self._join_values(rule, observation),
                progress=1,
                events=[observation],
                aliases=[alias],
                first_seen=observation.timestamp,
                last_seen=observation.timestamp,
                sessions={observation.session_id},
            )
        )
        self._evict_if_needed(rule)

    # -- chain_propagation --------------------------------------------------

    def _apply_chain_propagation(
        self, rule: CorrelationRule, observation: Observation, alias: str
    ) -> None:
        upstream = [str(u) for u in observation.get_all("evidence.upstream_chain")]
        pending_list = self._pending[rule.id]

        for pending in pending_list:
            if not self._same_join(rule, observation, pending):
                continue
            if not self._within_window(rule, pending, observation):
                continue
            if not upstream:
                continue
            known = {e.observation_id for e in pending.events}
            if not any(link in known for link in upstream):
                continue
            pending.events.append(observation)
            pending.aliases.append(alias)
            pending.last_seen = observation.timestamp
            pending.sessions.add(observation.session_id)
            pending.progress += 1
            if pending.progress >= len(rule.sequence):
                self._emit(rule, pending)
            return

        if rule.sequence and rule.sequence[0] == alias:
            pending_list.append(
                _Pending(
                    rule_id=rule.id,
                    join_values=self._join_values(rule, observation),
                    progress=1,
                    events=[observation],
                    aliases=[alias],
                    first_seen=observation.timestamp,
                    last_seen=observation.timestamp,
                    sessions={observation.session_id},
                )
            )
            self._evict_if_needed(rule)

    # -- emission -----------------------------------------------------------

    def _emit(self, rule: CorrelationRule, pending: _Pending) -> None:
        bindings: dict[str, dict[str, Any]] = {}
        for alias, observation in zip(pending.aliases, pending.events):
            bindings[alias] = {
                "event_id": observation.observation_id,
                "observation_id": observation.observation_id,
                "rule_id": observation.get("atr.rule_id"),
                "timestamp": observation.timestamp.isoformat().replace("+00:00", "Z"),
                "agent_id": observation.agent_id,
                "session_id": observation.session_id,
            }

        finding = CorrelationFinding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity_uplift,
            actions=rule.response_actions,
            message=render_message(rule, bindings),
            evidence=[e.to_dict() for e in pending.events],
            aliases=list(pending.aliases),
            detected_at=pending.events[-1].timestamp,
            bindings=bindings,
        )
        self._findings.append(finding)
        self._findings = self._findings[-_FINDING_RETENTION:]

        # Remove the completed chain so it cannot fire again.
        pending_list = self._pending[rule.id]
        if pending in pending_list:
            pending_list.remove(pending)

    def _evict_if_needed(self, rule: CorrelationRule) -> None:
        pending_list = self._pending[rule.id]
        while len(pending_list) > self.max_pending:
            evicted = pending_list.pop(0)
            self.evictions += 1
            self._events.append(
                {
                    "event.type": "correlation_state_evicted",
                    "atr.rule_id": rule.id,
                    "@timestamp": evicted.last_seen.isoformat().replace("+00:00", "Z"),
                    "evicted.observation_count": len(evicted.events),
                    "evicted.join_values": [str(v) for v in evicted.join_values],
                }
            )

    # -- results ------------------------------------------------------------

    def findings(self) -> list[CorrelationFinding]:
        """Completed correlation findings, oldest first."""
        return list(self._findings)

    def atomic_events(self) -> list[dict[str, Any]]:
        """Atomic events, emitted immediately and independently of correlation."""
        return list(self._atomic)

    def events(self) -> list[dict[str, Any]]:
        """Every event the engine emitted, atomic and correlation alike."""
        out = list(self._atomic)
        out.extend(finding.to_dict() for finding in self._findings)
        out.extend(self._events)
        return out

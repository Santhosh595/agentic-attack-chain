"""Correlation-rule loading and validation.

Implements ATR Correlation Rule Format v1.0. The upstream JSON Schema
(spec/schema/correlation.schema.json) is the structural contract; this
module adds the semantic checks the schema cannot express — that a
sequence names only declared source rules, that a window type can carry
the logic it is attached to, and that join keys are ones this engine
actually knows how to resolve.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

# The six standard join keys from the correlation spec §"Join keys".
# Custom keys are allowed by the spec ("best-effort"), but this engine
# refuses them rather than silently correlating on a field it never read.
KNOWN_JOIN_KEYS = (
    "agent.id",
    "session.id",
    "agent.delegation_chain[*].agent_id",
    "memory.store_id",
    "tool.target_jurisdiction",
    "evidence.upstream_chain[*]",
)

# The extra keys this engine can resolve, beyond the six the spec names.
# delegation.root comes from the observation spec and is the join key that
# survives a sub-agent hop; the others are dimension fields the
# observation spec §4.1 defines.
RESOLVABLE_JOIN_KEYS = KNOWN_JOIN_KEYS + (
    "delegation.root",
    "observation.kind",
    "outcome",
    "tool.name",
    "target.host",
    "file.path",
    "process.executable",
)

CORRELATION_TYPES = (
    "temporal_sequence",
    "temporal_unordered",
    "count_threshold",
    "value_overlap",
    "chain_propagation",
)

WINDOW_TYPES = ("wall_time", "session_chain", "chain_depth", "unbounded")

_ALLOWED_ACTIONS = (
    "block_input",
    "block_output",
    "redact",
    "alert",
    "snapshot",
    "quarantine",
    "terminate_session",
)

_DURATION_RE = re.compile(r"^[0-9]+[smhd]$")
_CORR_ID_RE = re.compile(r"^ATR-COR-(?:[A-Z]{2}-)?[0-9]{4}-[0-9]{5}$")
_RULE_ID_RE = re.compile(r"^ATR-(?:[A-Z]{2}-)?[0-9]{4}-[0-9]{5}$")
_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_.]*)\}")


class RuleLoadError(ValueError):
    """Raised when a correlation rule is not loadable."""


def _schema() -> dict[str, Any]:
    """Load the vendored upstream JSON Schema."""
    path = Path(__file__).resolve().parents[2] / "spec" / "schema" / "correlation.schema.json"
    if not path.is_file():
        raise RuleLoadError(f"upstream correlation schema is missing at {path}")
    return json.loads(path.read_text())


_SCHEMA_VALIDATOR = None


def _window_hint(window: Any) -> str | None:
    """Explain exactly what a window object is missing, for a better error.

    The upstream schema rejects a malformed window with a generic "not valid
    under any of the given schemas", because it is expressed as a oneOf over
    four shapes. That is correct but useless to a rule author. This turns the
    same rejection into a specific, actionable message.
    """
    if not isinstance(window, Mapping):
        return "window must be a mapping"
    window_type = window.get("type")
    if window_type == "wall_time":
        if "duration" not in window:
            return "wall_time window needs a duration matching ^[0-9]+[smhd]$"
        if not _DURATION_RE.match(str(window.get("duration"))):
            return f"wall_time duration {window.get('duration')!r} must match ^[0-9]+[smhd]$"
    if window_type == "session_chain":
        if "max_session_count" not in window:
            return "session_chain window needs max_session_count"
    if window_type == "chain_depth":
        if "max_depth" not in window:
            return "chain_depth window needs max_depth"
    return None


def _validate_structure(raw: Mapping[str, Any]) -> None:
    """Validate against the upstream JSON Schema."""
    global _SCHEMA_VALIDATOR
    if _SCHEMA_VALIDATOR is None:
        import jsonschema

        _SCHEMA_VALIDATOR = jsonschema.Draft202012Validator(_schema())
    errors = sorted(_SCHEMA_VALIDATOR.iter_errors(raw), key=lambda e: list(e.path))
    if not errors:
        return
    first = errors[0]
    location = "/".join(str(p) for p in first.path) or "<root>"
    if location == "correlation_logic/window":
        hint = _window_hint((raw.get("correlation_logic") or {}).get("window"))
        if hint:
            raise RuleLoadError(hint)
    raise RuleLoadError(f"schema violation at {location}: {first.message}")


@dataclass(frozen=True, slots=True)
class SourceRule:
    """One constituent atomic rule referenced by a correlation rule."""

    alias: str
    rule_id: str | None = None
    rule_id_pattern: str | None = None
    category: str | None = None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SourceRule":
        return cls(
            alias=raw["alias"],
            rule_id=raw.get("rule_id"),
            rule_id_pattern=raw.get("rule_id_pattern"),
            category=raw.get("category"),
        )


@dataclass(frozen=True, slots=True)
class CorrelationRule:
    """A loaded, validated correlation rule."""

    id: str
    title: str
    description: str
    status: str
    severity: str
    author: str
    date: str
    license: str
    references: dict[str, Any]
    source_rules: tuple[SourceRule, ...]
    logic_type: str
    sequence: tuple[str, ...]
    join_keys: tuple[str, ...]
    window_type: str
    window_duration: str | None
    window_max_session_count: int | None
    window_max_depth: int | None
    count_alias: str | None
    count_threshold: int | None
    value_overlap_field: str | None
    severity_uplift: str
    response_actions: tuple[str, ...]
    message_template: str | None
    true_positive_streams: tuple[str, ...]
    true_negative_streams: tuple[str, ...]

    # -- construction -------------------------------------------------------

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CorrelationRule":
        _validate_structure(raw)

        correlation = raw["correlation"]
        logic = raw["correlation_logic"]
        response = raw["response"]
        window = logic.get("window") or {}
        count = logic.get("count") or {}
        test_cases = raw.get("test_cases") or {}

        source_rules = tuple(SourceRule.from_dict(item) for item in raw["source_rules"])
        aliases = {sr.alias for sr in source_rules}

        sequence = tuple(item["alias"] for item in logic.get("sequence", []) or [])

        # Semantic checks the JSON Schema cannot express.
        if logic["type"] in ("temporal_sequence", "temporal_unordered"):
            if not sequence:
                raise RuleLoadError(
                    f"{correlation['id']}: correlation_logic.type is {logic['type']} "
                    "but no sequence is declared"
                )
            for alias in sequence:
                if alias not in aliases:
                    raise RuleLoadError(
                        f"{correlation['id']}: sequence references alias {alias!r} "
                        "which is not a declared source rule"
                    )

        if logic["type"] == "count_threshold":
            threshold = count.get("threshold")
            if threshold is None:
                raise RuleLoadError(
                    f"{correlation['id']}: count_threshold requires count.threshold"
                )
            alias = count.get("rule_alias")
            if alias is not None and alias not in aliases:
                raise RuleLoadError(
                    f"{correlation['id']}: count.rule_alias {alias!r} is not a "
                    "declared source rule"
                )

        if logic["type"] == "value_overlap" and not logic.get("value_overlap_field"):
            raise RuleLoadError(
                f"{correlation['id']}: value_overlap requires value_overlap_field"
            )

        join_keys = tuple(logic.get("join_keys") or ())
        for key in join_keys:
            if key not in RESOLVABLE_JOIN_KEYS:
                raise RuleLoadError(
                    f"{correlation['id']}: join key {key!r} is not a key this engine "
                    f"can resolve; known keys are {', '.join(RESOLVABLE_JOIN_KEYS)}"
                )

        window_type = window.get("type")
        if window_type not in WINDOW_TYPES:
            raise RuleLoadError(
                f"{correlation['id']}: unknown window type {window_type!r}"
            )
        if window_type == "wall_time":
            duration = window.get("duration")
            if not duration or not _DURATION_RE.match(duration):
                raise RuleLoadError(
                    f"{correlation['id']}: wall_time window needs a duration matching "
                    "^[0-9]+[smhd]$"
                )
        if window_type == "session_chain":
            count_sessions = window.get("max_session_count")
            if count_sessions is None:
                raise RuleLoadError(
                    f"{correlation['id']}: session_chain window needs max_session_count"
                )
        if window_type == "chain_depth":
            if window.get("max_depth") is None:
                raise RuleLoadError(
                    f"{correlation['id']}: chain_depth window needs max_depth"
                )

        for action in response["actions"]:
            if action not in _ALLOWED_ACTIONS:
                raise RuleLoadError(
                    f"{correlation['id']}: unknown response action {action!r}"
                )

        return cls(
            id=correlation["id"],
            title=correlation["title"],
            description=correlation["description"],
            status=correlation["status"],
            severity=correlation["severity"],
            author=correlation["author"],
            date=correlation["date"],
            license=correlation["license"],
            references=dict(correlation.get("references") or {}),
            source_rules=source_rules,
            logic_type=logic["type"],
            sequence=sequence,
            join_keys=join_keys,
            window_type=window_type,
            window_duration=window.get("duration"),
            window_max_session_count=window.get("max_session_count"),
            window_max_depth=window.get("max_depth"),
            count_alias=count.get("rule_alias"),
            count_threshold=count.get("threshold"),
            value_overlap_field=logic.get("value_overlap_field"),
            severity_uplift=response["severity_uplift"],
            response_actions=tuple(response["actions"]),
            message_template=response.get("message_template"),
            true_positive_streams=tuple(test_cases.get("true_positive_streams") or ()),
            true_negative_streams=tuple(test_cases.get("true_negative_streams") or ()),
        )

    # -- accessors ----------------------------------------------------------

    def source_rule(self, alias: str) -> SourceRule:
        for sr in self.source_rules:
            if sr.alias == alias:
                return sr
        raise KeyError(alias)

    @property
    def requires_dimensions(self) -> tuple[str, ...]:
        """Observation kinds this rule needs, when the rule declares them."""
        return tuple(self.references.get("requires_dimensions", ()) or ())


def load_rule(raw: Mapping[str, Any]) -> CorrelationRule:
    """Load and validate a single correlation rule from a mapping."""
    if not isinstance(raw, Mapping):
        raise RuleLoadError("a correlation rule must be a mapping")
    correlation = raw.get("correlation")
    if not isinstance(correlation, Mapping):
        raise RuleLoadError("a correlation rule must have a 'correlation' block")
    rule_id = correlation.get("id")
    if isinstance(rule_id, str) and not _CORR_ID_RE.match(rule_id):
        raise RuleLoadError(
            f"correlation id {rule_id!r} does not match the correlation id pattern "
            "^ATR-COR-(?:[A-Z]{2}-)?[0-9]{4}-[0-9]{5}$"
        )
    return CorrelationRule.from_dict(raw)


def load_rule_file(path: str | Path) -> CorrelationRule:
    """Load a correlation rule from a YAML or JSON file."""
    import yaml

    path = Path(path)
    text = path.read_text()
    if path.suffix.lower() == ".json":
        raw = json.loads(text)
    else:
        raw = yaml.safe_load(text)
    try:
        return load_rule(raw)
    except RuleLoadError as exc:
        raise RuleLoadError(f"{path}: {exc}") from exc


def load_rules(directory: str | Path) -> list[CorrelationRule]:
    """Load every correlation rule in a directory, rejecting duplicate ids."""
    directory = Path(directory)
    rules: list[CorrelationRule] = []
    seen: dict[str, str] = {}
    for path in sorted(directory.glob("*.y*ml")):
        rule = load_rule_file(path)
        if rule.id in seen:
            raise RuleLoadError(
                f"duplicate correlation id {rule.id} in {path.name} and {seen[rule.id]}"
            )
        seen[rule.id] = path.name
        rules.append(rule)
    return rules


def render_message(rule: CorrelationRule, bindings: Mapping[str, Mapping[str, Any]]) -> str:
    """Render a rule's message template against the matched event bindings.

    Placeholders are "{alias.field}" — for example "{injection.event_id}". A
    placeholder with no binding is left intact rather than blanked, so a
    partially-matched chain still shows what is missing.
    """
    template = rule.message_template
    if not template:
        return rule.title

    def replace(match: re.Match[str]) -> str:
        alias, field = match.group(1), match.group(2)
        binding = bindings.get(alias)
        if binding is None or field not in binding:
            return match.group(0)
        return str(binding[field])

    return _PLACEHOLDER_RE.sub(replace, template)

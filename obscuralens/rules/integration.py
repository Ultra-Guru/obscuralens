"""
Integration helpers that wire the YAML rule engine into the product (v6.3).

:mod:`obscuralens.rules.engine` has shipped as a stable library API since
v5.1: 224 curated rules across 21 packs, every one carrying an id, a
title, an honest description of *why* the signal matters, a severity and
a weight.  Until this module landed, nothing in the product consumed it --
no CLI command, no REST endpoint, no report section -- so the packs were
data that only external callers could reach.

This module is the missing adapter layer.  It does three small things and
nothing else:

1. :func:`fields_for` -- normalise a tracker payload into the flat field
   dict the rule conditions expect.  Most kinds keep their facts under
   ``payload['info']``; the username sweep returns a flat mapping instead.
   The engine's own ``resolve_field`` already falls back to ``info.``
   prefixes, so this is a thin, defensive helper rather than a rewrite.
2. :func:`rule_sections` -- turn a :class:`~obscuralens.rules.engine.RuleEvaluation`
   into the ``{'title', 'type', ...}`` section dicts that
   :func:`obscuralens.correlation.risk.risk_sections` and
   ``investigate.investigate_sections`` already produce, so rule findings
   render through the existing text, HTML and Markdown report paths with
   no template changes.
3. :func:`evaluate_payload` -- the one-call convenience used by the CLI,
   the REST API, the MCP server and the SDK so every surface returns an
   identical ``to_dict()`` mapping.

Framing the packs keep and this module repeats: these rules describe
**technical indicators, never people**.  A hit is a triage aid for an
analyst -- it is not evidence and not a verdict.  Every function here is
defensive: junk input yields a well-formed empty result instead of an
exception, because a rule layer must never be the reason a lookup fails.
"""

from typing import Any, Dict, List, Optional

from .engine import RuleEvaluation, evaluate_rules, load_all_packs

__all__ = [
    'SEVERITY_ORDER',
    'evaluate_payload',
    'fields_for',
    'packs_catalog',
    'rule_sections',
    'severity_counts',
]

#: Severity ordering used for grouping and sorting hits in reports.
#: Highest first -- an analyst reads the critical rows before the notes.
SEVERITY_ORDER = ('critical', 'high', 'medium', 'low', 'info')


def fields_for(payload: Any) -> Dict[str, Any]:
    """
    Flatten a tracker payload into the field dict rule conditions read.

    Trackers return ``{'info': {...}, 'sources': [...], ...}`` for most
    kinds, while the username sweep returns its findings at the top
    level.  Rule conditions address fields by their bare name
    (``is_tor``, ``registration.age_days``), so the ``info`` mapping is
    merged over the envelope: envelope keys stay reachable (``sources``,
    ``error``) and ``info`` wins on collision because that is where the
    authoritative facts live.

    Args:
        payload: A tracker result, or anything else.

    Returns:
        A flat ``dict`` -- empty if ``payload`` is not a mapping.
    """
    if not isinstance(payload, dict):
        return {}
    fields: Dict[str, Any] = {
        key: value for key, value in payload.items() if key != 'info'
    }
    info = payload.get('info')
    if isinstance(info, dict):
        fields.update(info)
    # Keep the nested form reachable too, so packs may address either
    # `age_days` or `info.age_days` without caring about the envelope.
    if isinstance(info, dict):
        fields['info'] = info
    return fields


def evaluate_payload(kind: str, payload: Any) -> RuleEvaluation:
    """
    Evaluate the rule packs for ``kind`` against a raw tracker payload.

    Equivalent to ``evaluate_rules(kind, fields_for(payload))`` and the
    single entry point every product surface should call, so the CLI, the
    REST API, the MCP server and the SDK cannot drift apart.

    A payload that is not a mapping means *no data was collected*, and no
    data must never be scored: that case returns a well-formed empty
    evaluation, exactly as :func:`~obscuralens.rules.engine.evaluate_rules`
    does, instead of letting the data-quality rules fire against an empty
    field dict and inventing a ``watch`` band out of nothing.

    Args:
        kind: Target kind (``ip``, ``domain``, ``username``, ...).
        payload: Tracker result for that target.

    Returns:
        A :class:`RuleEvaluation` -- well-formed and empty for unknown
        kinds or non-mapping payloads.  Never raises.
    """
    if not isinstance(payload, dict):
        return evaluate_rules(kind, payload)  # engine returns an empty result
    return evaluate_rules(kind, fields_for(payload))


def severity_counts(evaluation: Optional[RuleEvaluation]) -> Dict[str, int]:
    """
    Count matched rules per severity, highest severity first.

    Only severities that actually fired appear in the mapping, so an
    evaluation with no hits yields ``{}`` and callers can treat the empty
    mapping as "nothing to show".
    """
    counts: Dict[str, int] = {}
    hits = getattr(evaluation, 'hits', None) or []
    for hit in hits:
        severity = str(getattr(hit.rule, 'severity', '') or 'info').lower()
        counts[severity] = counts.get(severity, 0) + 1
    return {
        severity: counts[severity]
        for severity in SEVERITY_ORDER
        if severity in counts
    }


def _summary_line(evaluation: RuleEvaluation) -> str:
    """Human summary for the grid: severity mix, or an explicit all-clear."""
    counts = severity_counts(evaluation)
    if not counts:
        return 'No rule matched this target.'
    return ', '.join(
        f'{count} {severity}' for severity, count in counts.items()
    )


def rule_sections(evaluation: Optional[RuleEvaluation]) -> List[Dict[str, Any]]:
    """
    Report sections for a :class:`RuleEvaluation`.

    Produces the same section shapes as
    :func:`obscuralens.correlation.risk.risk_sections` so rule findings
    flow through every existing renderer (text tables, Markdown, HTML,
    the web UI) without a single template change:

    * a ``grid`` headline -- score, band, pack, severity mix;
    * a ``table`` of the rules that fired -- id, title, severity, weight;
    * a ``table`` of per-condition explanations against the real field
      values, because the engine's contract is that *a hit tells you why*.

    An evaluation with no hits still returns the grid (an explicit
    all-clear is a result an analyst needs to see), and ``None`` yields an
    empty list.
    """
    if evaluation is None:
        return []
    hits = list(getattr(evaluation, 'hits', None) or [])
    kind = str(getattr(evaluation, 'kind', '') or 'target')
    sections: List[Dict[str, Any]] = [{
        'title': 'Rule Pack Findings',
        'type': 'grid',
        'data': {
            'Score': f"{getattr(evaluation, 'score', 0)}/100",
            'Band': getattr(evaluation, 'band', 'clean'),
            'Pack': kind,
            'Rules matched': str(len(hits)),
            'Severity mix': _summary_line(evaluation),
        },
    }]
    if not hits:
        return sections

    order = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    ordered = sorted(
        hits,
        key=lambda hit: (
            order.get(
                str(getattr(hit.rule, 'severity', '') or 'info').lower(),
                len(SEVERITY_ORDER),
            ),
            -int(getattr(hit, 'score', 0) or 0),
            str(getattr(hit.rule, 'id', '')),
        ),
    )
    sections.append({
        'title': 'Matched Rules',
        'type': 'table',
        'columns': ['Rule', 'Title', 'Severity', 'Weight'],
        'rows': [[
            getattr(hit.rule, 'id', ''),
            getattr(hit.rule, 'title', ''),
            getattr(hit.rule, 'severity', ''),
            getattr(hit, 'score', 0),
        ] for hit in ordered],
    })
    explanations: List[List[Any]] = []
    for hit in ordered:
        for line in (getattr(hit, 'explanations', None) or []):
            explanations.append([getattr(hit.rule, 'id', ''), line])
    if explanations:
        sections.append({
            'title': 'Why These Rules Fired',
            'type': 'table',
            'columns': ['Rule', 'Condition'],
            'rows': explanations,
        })
    return sections


def packs_catalog() -> Dict[str, Any]:
    """
    Machine-readable inventory of every loaded rule pack.

    Backs ``obscuralens rules --list``, ``GET /api/rules/packs`` and the
    ``rules_packs`` MCP tool, so the shipped rule inventory is
    introspectable without reading the YAML off disk.

    Returns:
        ``{'packs': [{'kind', 'name', 'description', 'version',
        'rules', 'severities'}, ...], 'total_packs', 'total_rules'}``
        sorted by kind.
    """
    packs = load_all_packs() or {}
    entries: List[Dict[str, Any]] = []
    total_rules = 0
    for kind in sorted(packs):
        pack = packs[kind]
        rules = list(getattr(pack, 'rules', None) or [])
        total_rules += len(rules)
        severities: Dict[str, int] = {}
        for rule in rules:
            severity = str(getattr(rule, 'severity', '') or 'info').lower()
            severities[severity] = severities.get(severity, 0) + 1
        entries.append({
            'kind': kind,
            'name': getattr(pack, 'name', '') or f'{kind}-rules',
            'description': getattr(pack, 'description', '') or '',
            'version': getattr(pack, 'version', 1),
            'rules': len(rules),
            'severities': {
                severity: severities[severity]
                for severity in SEVERITY_ORDER
                if severity in severities
            },
        })
    return {
        'packs': entries,
        'total_packs': len(entries),
        'total_rules': total_rules,
    }

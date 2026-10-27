"""
Offline tests for the rule-engine product integration (v6.3).

The YAML rule engine shipped in v5.1 as a library-only API: 224 rules
across 21 packs that nothing in the product consumed.  These tests cover
the adapter layer that wires it into the CLI, the REST API, the MCP
server and the SDK:

* :mod:`obscuralens.rules.integration` -- payload flattening
  (``fields_for``), the one-call ``evaluate_payload``, report-section
  shaping (``rule_sections``), severity grouping and the pack catalog;
* the ``obscuralens rules`` command and the ``--rules`` lookup flag,
  including the serialised-block renderer used for table output;
* ``GET /api/rules/packs`` and ``GET /api/rules/{kind}/{target}``;
* the ``rules_packs`` / ``rules_evaluate`` MCP tools;
* the ``RuleReport`` / ``RuleHitModel`` SDK models and the client
  methods, sync and async.

Everything here is offline: trackers are monkeypatched, no test touches
the network, and the defensive contract (junk input yields well-formed
empty results rather than exceptions) is asserted explicitly.
"""

import argparse
import asyncio
import json

import pytest

from obscuralens import commands, mcp_server
from obscuralens.rules import (
    SEVERITY_ORDER,
    evaluate_payload,
    fields_for,
    packs_catalog,
    rule_sections,
    severity_counts,
)
from obscuralens.sdk.models import RuleHitModel, RuleReport

# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #

#: A tracker-shaped payload that trips several real ip-pack rules.
DIRTY_IP = {
    'ip': '203.0.113.10',
    'success': True,
    'info': {
        'is_tor': True,
        'is_proxy': True,
        'abuse_confidence': 97,
        'ports': [22, 23, 445],
        'country_code': 'RU',
    },
    'sources': ['ipwho.is'],
    'sources_ok': ['ipwho.is'],
}

#: A payload that trips nothing in the ip pack.
CLEAN_IP = {
    'ip': '1.1.1.1',
    'success': True,
    'info': {'country_code': 'AU', 'reverse_dns': 'one.one.one.one'},
    'field_sources': {'country_code': ['ipwho.is', 'ip-api.com']},
}


class _StubTracker:
    """Minimal tracker stand-in: returns a canned payload, never networks."""

    def __init__(self, payload):
        self._payload = payload

    def track(self, target, **kwargs):
        result = dict(self._payload)
        result.setdefault('ip', target)
        return result


def _args(**kwargs):
    """Namespace with the flags ``add_common`` would have supplied."""
    base = {
        'format': None, 'output': None, 'timeout': None, 'no_cache': False,
        'no_color': True, 'risk': False, 'rules': False, 'template': None,
        'kind': None, 'target': None, 'list_packs': False,
    }
    base.update(kwargs)
    return argparse.Namespace(**base)


# --------------------------------------------------------------------------- #
# fields_for
# --------------------------------------------------------------------------- #

class TestFieldsFor:
    """Payload envelopes must flatten to the field dict rules read."""

    def test_merges_info_over_envelope(self):
        fields = fields_for({'info': {'a': 1}, 'sources': ['x']})
        assert fields['a'] == 1
        assert fields['sources'] == ['x']

    def test_info_wins_on_collision(self):
        # `info` holds the authoritative facts, so it must win.
        fields = fields_for({'country': 'XX', 'info': {'country': 'AU'}})
        assert fields['country'] == 'AU'

    def test_nested_info_stays_reachable(self):
        fields = fields_for({'info': {'a': 1}})
        assert fields['info'] == {'a': 1}

    def test_flat_payload_passes_through(self):
        # The username sweep returns findings at the top level.
        fields = fields_for({'confirmed': ['github'], 'ruled_out': []})
        assert fields['confirmed'] == ['github']

    @pytest.mark.parametrize('junk', [None, 'string', 42, [], ('a',), object()])
    def test_non_mapping_yields_empty_dict(self, junk):
        assert fields_for(junk) == {}

    def test_non_dict_info_is_ignored(self):
        assert fields_for({'info': 'nope', 'x': 1}) == {'x': 1}

    def test_does_not_mutate_input(self):
        payload = {'info': {'a': 1}, 'b': 2}
        fields_for(payload)
        assert payload == {'info': {'a': 1}, 'b': 2}


# --------------------------------------------------------------------------- #
# evaluate_payload
# --------------------------------------------------------------------------- #

class TestEvaluatePayload:
    """One call from a raw tracker payload to a scored evaluation."""

    def test_scores_a_dirty_payload(self):
        evaluation = evaluate_payload('ip', DIRTY_IP)
        assert evaluation.kind == 'ip'
        assert evaluation.score > 0
        assert evaluation.band in ('elevated', 'high', 'critical')
        assert 'IP-001' in evaluation.matched_ids   # Tor exit node

    def test_hits_explain_themselves(self):
        evaluation = evaluate_payload('ip', DIRTY_IP)
        hit = next(h for h in evaluation.hits if h.rule.id == 'IP-001')
        assert hit.explanations
        assert 'is_tor' in ' '.join(hit.explanations)

    def test_clean_payload_scores_low(self):
        evaluation = evaluate_payload('ip', CLEAN_IP)
        assert evaluation.score < 30
        assert 'IP-001' not in evaluation.matched_ids

    def test_shared_pack_runs_alongside_kind_pack(self):
        # SHARED-* rules apply to every kind.
        evaluation = evaluate_payload('ip', DIRTY_IP)
        assert any(i.startswith('SHARED-') for i in evaluation.matched_ids)

    def test_score_is_capped_at_100(self):
        evaluation = evaluate_payload('ip', DIRTY_IP)
        assert 0 <= evaluation.score <= 100

    @pytest.mark.parametrize('kind', ['ip', 'domain', 'email', 'username',
                                      'cve', 'crypto', 'url', 'hash'])
    def test_every_wired_kind_evaluates(self, kind):
        evaluation = evaluate_payload(kind, {'info': {}})
        assert evaluation.kind == kind
        assert isinstance(evaluation.score, int)

    def test_unknown_kind_runs_only_the_shared_pack(self):
        # No kind pack exists, but the always-on shared pack still applies,
        # so the result is well-formed and carries no kind-specific rules.
        evaluation = evaluate_payload('not-a-kind', {'info': {'a': 1}})
        assert all(i.startswith('SHARED-') for i in evaluation.matched_ids)
        assert 0 <= evaluation.score <= 100

    @pytest.mark.parametrize('junk', [None, 'x', 7, []])
    def test_non_mapping_payload_is_never_scored(self, junk):
        # "No data collected" must not be turned into a risk band by the
        # data-quality rules firing against an empty field dict.
        evaluation = evaluate_payload('ip', junk)
        assert evaluation.score == 0
        assert evaluation.hits == []
        assert evaluation.band == 'clean'

    def test_empty_info_still_flags_data_quality(self):
        # An empty result is a real finding: no provenance, no hostnames.
        evaluation = evaluate_payload('ip', {'info': {}})
        assert 'SHARED-006' in evaluation.matched_ids

    def test_to_dict_is_json_serialisable(self):
        payload = evaluate_payload('ip', DIRTY_IP).to_dict()
        assert json.loads(json.dumps(payload))['kind'] == 'ip'
        assert {'kind', 'score', 'band', 'hits'} <= set(payload)


# --------------------------------------------------------------------------- #
# severity_counts / rule_sections
# --------------------------------------------------------------------------- #

class TestSeverityCounts:
    def test_counts_are_ordered_high_to_low(self):
        counts = severity_counts(evaluate_payload('ip', DIRTY_IP))
        order = [s for s in SEVERITY_ORDER if s in counts]
        assert list(counts) == order

    def test_empty_evaluation_yields_empty_mapping(self):
        assert severity_counts(evaluate_payload('ip', None)) == {}

    def test_none_is_tolerated(self):
        assert severity_counts(None) == {}

    def test_total_matches_hit_count(self):
        evaluation = evaluate_payload('ip', DIRTY_IP)
        assert sum(severity_counts(evaluation).values()) == len(evaluation.hits)


class TestRuleSections:
    """Sections must match the shapes existing renderers already consume."""

    def test_none_yields_no_sections(self):
        assert rule_sections(None) == []

    def test_grid_is_always_present(self):
        sections = rule_sections(evaluate_payload('ip', DIRTY_IP))
        assert sections[0]['type'] == 'grid'
        assert sections[0]['title'] == 'Rule Pack Findings'
        assert sections[0]['data']['Band'] in (
            'clean', 'watch', 'elevated', 'high', 'critical')

    def test_all_clear_still_reports_the_grid(self):
        # An explicit all-clear is a result the analyst needs to see.
        sections = rule_sections(evaluate_payload('ip', None))
        assert len(sections) == 1
        assert sections[0]['data']['Rules matched'] == '0'
        assert 'No rule matched' in sections[0]['data']['Severity mix']

    def test_matched_rules_table_shape(self):
        sections = rule_sections(evaluate_payload('ip', DIRTY_IP))
        table = next(s for s in sections if s['title'] == 'Matched Rules')
        assert table['columns'] == ['Rule', 'Title', 'Severity', 'Weight']
        assert all(len(row) == 4 for row in table['rows'])

    def test_rows_sorted_by_severity_then_weight(self):
        sections = rule_sections(evaluate_payload('ip', DIRTY_IP))
        table = next(s for s in sections if s['title'] == 'Matched Rules')
        ranks = [SEVERITY_ORDER.index(row[2]) for row in table['rows']]
        assert ranks == sorted(ranks)

    def test_explanations_table_present_and_paired(self):
        sections = rule_sections(evaluate_payload('ip', DIRTY_IP))
        table = next(s for s in sections
                     if s['title'] == 'Why These Rules Fired')
        assert table['columns'] == ['Rule', 'Condition']
        assert all(len(row) == 2 and row[1] for row in table['rows'])

    def test_sections_render_through_the_existing_formatter(self):
        # The payoff of matching risk_sections shapes: no new templates.
        text = commands._render_sections_text(
            rule_sections(evaluate_payload('ip', DIRTY_IP)))
        assert 'RULE PACK FINDINGS' in text.upper()
        assert 'IP-001' in text


# --------------------------------------------------------------------------- #
# packs_catalog
# --------------------------------------------------------------------------- #

class TestPacksCatalog:
    def test_reports_every_shipped_pack(self):
        catalog = packs_catalog()
        assert catalog['total_packs'] == len(catalog['packs'])
        assert catalog['total_packs'] >= 21
        assert catalog['total_rules'] >= 224

    def test_entries_are_sorted_by_kind(self):
        kinds = [entry['kind'] for entry in packs_catalog()['packs']]
        assert kinds == sorted(kinds)

    def test_entry_shape_and_totals_agree(self):
        catalog = packs_catalog()
        assert sum(e['rules'] for e in catalog['packs']) == \
            catalog['total_rules']
        for entry in catalog['packs']:
            assert {'kind', 'name', 'description', 'version', 'rules',
                    'severities'} == set(entry)
            assert entry['rules'] == sum(entry['severities'].values())
            assert set(entry['severities']) <= set(SEVERITY_ORDER)

    def test_shared_pack_is_catalogued(self):
        kinds = {entry['kind'] for entry in packs_catalog()['packs']}
        assert 'shared' in kinds

    def test_is_json_serialisable(self):
        assert json.loads(json.dumps(packs_catalog()))['total_packs'] >= 21


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

class TestRulesCommand:
    def test_parser_accepts_the_rules_command(self):
        parsed = commands.build_parser().parse_args(['rules', 'ip', '1.1.1.1'])
        assert parsed.command == 'rules'
        assert parsed.kind == 'ip' and parsed.target == '1.1.1.1'

    def test_parser_accepts_bare_list(self):
        parsed = commands.build_parser().parse_args(['rules', '--list'])
        assert parsed.list_packs is True

    def test_rules_is_dispatched(self):
        assert commands._HANDLERS['rules'] is commands._cmd_rules

    def test_every_lookup_takes_the_rules_flag(self):
        parsed = commands.build_parser().parse_args(['ip', '1.1.1.1', '--rules'])
        assert parsed.rules is True

    def test_list_table_output(self, capsys):
        assert commands._cmd_rules(_args(list_packs=True)) == 0
        out = capsys.readouterr().out
        assert 'RULE PACKS' in out.upper()
        assert 'ip-rules' in out

    def test_list_json_output(self, capsys):
        assert commands._cmd_rules(_args(list_packs=True, format='json')) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['total_packs'] >= 21

    def test_evaluate_table_output(self, capsys, monkeypatch):
        monkeypatch.setattr(commands, '_tracker',
                            lambda kind: _StubTracker(DIRTY_IP))
        rc = commands._cmd_rules(_args(kind='ip', target='203.0.113.10'))
        assert rc == 0
        out = capsys.readouterr().out
        assert 'IP-001' in out

    def test_evaluate_json_attaches_rules_block(self, capsys, monkeypatch):
        monkeypatch.setattr(commands, '_tracker',
                            lambda kind: _StubTracker(DIRTY_IP))
        rc = commands._cmd_rules(
            _args(kind='ip', target='203.0.113.10', format='json'))
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['rules']['kind'] == 'ip'
        assert payload['rules']['hits']

    def test_missing_target_is_a_usage_error(self):
        assert commands._cmd_rules(_args(kind='ip')) == 2

    def test_invalid_target_is_rejected_before_lookup(self, monkeypatch):
        def _boom(kind):
            raise AssertionError('tracker must not run on invalid input')
        monkeypatch.setattr(commands, '_tracker', _boom)
        assert commands._cmd_rules(_args(kind='ip', target='not-an-ip')) == 2

    def test_empty_lookup_reports_failure(self, monkeypatch):
        monkeypatch.setattr(commands, '_tracker',
                            lambda kind: _StubTracker({'info': {}}))
        assert commands._cmd_rules(_args(kind='ip', target='1.1.1.1')) == 1

    def test_rules_flag_attaches_block_to_a_lookup(self, monkeypatch, capsys):
        monkeypatch.setattr(commands, '_tracker',
                            lambda kind: _StubTracker(DIRTY_IP))
        rc = commands._run_lookup(
            _args(kind='ip', rules=True, format='json'),
            'ip', '203.0.113.10', 'IP')
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['rules']['score'] > 0

    def test_lookup_without_the_flag_has_no_rules_block(self, monkeypatch,
                                                        capsys):
        monkeypatch.setattr(commands, '_tracker',
                            lambda kind: _StubTracker(DIRTY_IP))
        commands._run_lookup(_args(kind='ip', format='json'),
                             'ip', '203.0.113.10', 'IP')
        assert 'rules' not in json.loads(capsys.readouterr().out)


class TestRulesSectionsFromDict:
    """The serialised-block renderer used for attached --rules output."""

    def test_renders_grid_and_table(self):
        block = evaluate_payload('ip', DIRTY_IP).to_dict()
        sections = commands._rules_sections_from_dict(block)
        assert sections[0]['title'] == 'RULE PACK FINDINGS'
        assert any(s['title'] == 'MATCHED RULES' for s in sections)

    def test_no_hits_yields_only_the_summary(self):
        sections = commands._rules_sections_from_dict(
            {'kind': 'ip', 'score': 0, 'band': 'clean', 'hits': []})
        assert len(sections) == 1

    def test_extra_sections_picks_up_the_block(self):
        result = dict(DIRTY_IP)
        result['rules'] = evaluate_payload('ip', DIRTY_IP).to_dict()
        titles = [s['title'] for s in commands._extra_sections(result)]
        assert 'RULE PACK FINDINGS' in titles

    def test_extra_sections_ignores_a_missing_block(self):
        titles = [s['title'] for s in commands._extra_sections(dict(DIRTY_IP))]
        assert 'RULE PACK FINDINGS' not in titles


# --------------------------------------------------------------------------- #
# REST API
# --------------------------------------------------------------------------- #

@pytest.fixture()
def api_client():
    fastapi_testclient = pytest.importorskip('fastapi.testclient')
    from obscuralens.web.app import create_app
    return fastapi_testclient.TestClient(create_app())


class TestRulesApi:
    def test_packs_endpoint(self, api_client):
        response = api_client.get('/api/rules/packs')
        assert response.status_code == 200
        payload = response.json()
        assert payload['total_packs'] >= 21
        assert payload['total_rules'] >= 224

    def test_packs_entry_shape(self, api_client):
        entry = api_client.get('/api/rules/packs').json()['packs'][0]
        assert {'kind', 'name', 'description', 'version', 'rules',
                'severities'} == set(entry)

    def test_unknown_kind_is_rejected(self, api_client):
        assert api_client.get('/api/rules/nope/x').status_code == 400

    def test_invalid_target_is_rejected(self, api_client):
        response = api_client.get('/api/rules/ip/not-an-ip')
        assert response.status_code == 400

    def test_lookup_attaches_a_rules_block(self, api_client, monkeypatch):
        from obscuralens.web import app as web_app
        monkeypatch.setitem(web_app._TRACKERS, 'ip',
                            lambda: _StubTracker(DIRTY_IP))
        payload = api_client.get('/api/rules/ip/203.0.113.10').json()
        assert payload['rules']['kind'] == 'ip'
        assert payload['rules']['hits']

    def test_tracker_failure_returns_a_failure_payload(self, api_client,
                                                       monkeypatch):
        class _Boom:
            def track(self, target, **kwargs):
                raise RuntimeError('source down')
        from obscuralens.web import app as web_app
        monkeypatch.setitem(web_app._TRACKERS, 'ip', _Boom)
        response = api_client.get('/api/rules/ip/1.1.1.1')
        assert response.status_code == 200
        assert response.json()['success'] is False


# --------------------------------------------------------------------------- #
# MCP tools
# --------------------------------------------------------------------------- #

class TestRulesMcpTools:
    def test_both_tools_are_advertised(self):
        names = {tool['name'] for tool in mcp_server.TOOLS}
        assert {'rules_packs', 'rules_evaluate'} <= names

    def test_both_tools_dispatch(self):
        assert {'rules_packs', 'rules_evaluate'} <= set(mcp_server._HANDLERS)

    def test_schemas_are_well_formed(self):
        for tool in mcp_server.TOOLS:
            if not tool['name'].startswith('rules_'):
                continue
            schema = tool['inputSchema']
            assert schema['type'] == 'object'
            assert schema['additionalProperties'] is False
            assert tool['description']

    def test_packs_tool_returns_the_catalog(self):
        payload = mcp_server._HANDLERS['rules_packs']({})
        assert payload['total_rules'] >= 224

    def test_evaluate_tool_scores_supplied_data(self):
        payload = mcp_server._HANDLERS['rules_evaluate'](
            {'kind': 'ip', 'data': DIRTY_IP})
        assert payload['kind'] == 'ip'
        assert payload['score'] > 0
        assert any(hit['id'] == 'IP-001' for hit in payload['hits'])

    def test_evaluate_accepts_a_flat_field_dict(self):
        payload = mcp_server._HANDLERS['rules_evaluate'](
            {'kind': 'ip', 'data': {'is_tor': True}})
        assert 'IP-001' in [hit['id'] for hit in payload['hits']]

    @pytest.mark.parametrize('data', [None, 'x', 7, []])
    def test_evaluate_rejects_non_object_data(self, data):
        with pytest.raises(ValueError):
            mcp_server._HANDLERS['rules_evaluate']({'kind': 'ip',
                                                    'data': data})

    def test_evaluate_requires_a_kind(self):
        with pytest.raises(ValueError):
            mcp_server._HANDLERS['rules_evaluate']({'data': {}})

    def test_evaluate_is_offline(self, monkeypatch):
        # The tool must score supplied data, never run a lookup.
        import obscuralens.trackers as trackers

        def _boom(*args, **kwargs):
            raise AssertionError('rules_evaluate must not network')
        for name in dir(trackers):
            attr = getattr(trackers, name)
            if isinstance(attr, type) and hasattr(attr, 'track'):
                monkeypatch.setattr(attr, 'track', _boom, raising=False)
        payload = mcp_server._HANDLERS['rules_evaluate'](
            {'kind': 'ip', 'data': DIRTY_IP})
        assert payload['score'] > 0


# --------------------------------------------------------------------------- #
# SDK models + client methods
# --------------------------------------------------------------------------- #

class TestRuleReportModel:
    def test_parses_a_full_envelope(self):
        envelope = dict(DIRTY_IP)
        envelope['rules'] = evaluate_payload('ip', DIRTY_IP).to_dict()
        report = RuleReport.from_dict(envelope, kind='ip',
                                      target='203.0.113.10')
        assert report.kind == 'ip'
        assert report.target == '203.0.113.10'
        assert report.lookup is not None
        assert 'IP-001' in report.matched_ids()

    def test_parses_a_bare_block(self):
        block = evaluate_payload('ip', DIRTY_IP).to_dict()
        report = RuleReport.from_dict(block)
        assert report.kind == 'ip'
        assert report.lookup is None
        assert report.hits

    def test_defaults_are_safe(self):
        report = RuleReport.from_dict({})
        assert report.score == 0
        assert report.band == 'clean'
        assert report.is_clean()

    def test_by_severity_is_case_insensitive(self):
        report = RuleReport.from_dict(
            evaluate_payload('ip', DIRTY_IP).to_dict())
        assert report.by_severity('HIGH') == report.by_severity('high')

    def test_explain_is_sorted_heaviest_first(self):
        report = RuleReport.from_dict(
            evaluate_payload('ip', DIRTY_IP).to_dict())
        weights = [hit.weight for hit in
                   sorted(report.hits, key=lambda h: -h.weight)]
        assert weights == sorted(weights, reverse=True)
        assert len(report.explain()) == len(report.hits)

    @pytest.mark.parametrize('band,expected', [
        ('clean', False), ('watch', False), ('elevated', False),
        ('high', True), ('critical', True),
    ])
    def test_is_high_or_worse(self, band, expected):
        report = RuleReport.from_dict({'band': band, 'hits': []})
        assert report.is_high_or_worse() is expected

    def test_hit_model_shape_and_str(self):
        hit = RuleHitModel.from_dict({
            'id': 'IP-001', 'title': 'Tor exit node', 'severity': 'high',
            'weight': 20, 'tags': ['tor'], 'references': ['T1090.003'],
            'explanations': ['is_tor is true'],
        })
        assert str(hit) == 'IP-001 [high] Tor exit node'
        assert hit.tags == ['tor'] and hit.references == ['T1090.003']

    def test_hit_model_falls_back_to_score_for_weight(self):
        assert RuleHitModel.from_dict({'score': 15}).weight == 15

    def test_hit_model_tolerates_junk(self):
        hit = RuleHitModel.from_dict(None)
        assert hit.id == '' and hit.severity == 'info'


class TestSdkClientMethods:
    def test_sync_client_exposes_both_methods(self):
        from obscuralens.sdk import ObscuraLensClient
        assert callable(ObscuraLensClient.rules)
        assert callable(ObscuraLensClient.rule_packs)

    def test_async_client_exposes_both_methods(self):
        from obscuralens.sdk.async_client import AsyncObscuraLensClient
        assert asyncio.iscoroutinefunction(AsyncObscuraLensClient.rules)
        assert asyncio.iscoroutinefunction(AsyncObscuraLensClient.rule_packs)

    def test_rules_rejects_an_unknown_kind_before_any_request(self):
        from obscuralens.sdk import ObscuraLensClient
        client = ObscuraLensClient(base_url='http://127.0.0.1:1')
        with pytest.raises(ValueError):
            client.rules('not-a-kind', 'x')

    def test_rules_calls_the_expected_path(self, monkeypatch):
        from obscuralens.sdk import ObscuraLensClient
        client = ObscuraLensClient(base_url='http://127.0.0.1:1')
        seen = {}

        def _fake(method, path, **kwargs):
            seen['method'], seen['path'] = method, path
            return {'rules': {'kind': 'ip', 'score': 20, 'band': 'watch',
                              'hits': []}}
        monkeypatch.setattr(client, '_request', _fake)
        report = client.rules('ip', '1.1.1.1')
        assert seen == {'method': 'GET', 'path': '/api/rules/ip/1.1.1.1'}
        assert report.band == 'watch'

    def test_rule_packs_calls_the_expected_path(self, monkeypatch):
        from obscuralens.sdk import ObscuraLensClient
        client = ObscuraLensClient(base_url='http://127.0.0.1:1')
        seen = {}

        def _fake(method, path, **kwargs):
            seen['path'] = path
            return {'packs': [], 'total_packs': 0, 'total_rules': 0}
        monkeypatch.setattr(client, '_request', _fake)
        assert client.rule_packs()['total_packs'] == 0
        assert seen['path'] == '/api/rules/packs'

    def test_sdk_package_exports_the_models(self):
        import obscuralens.sdk as sdk
        assert 'RuleReport' in sdk.__all__
        assert 'RuleHitModel' in sdk.__all__


# --------------------------------------------------------------------------- #
# Cross-surface consistency
# --------------------------------------------------------------------------- #

class TestSurfaceConsistency:
    """Every surface must report the same numbers for the same input."""

    def test_cli_api_and_mcp_agree(self, api_client, monkeypatch):
        from obscuralens.web import app as web_app
        monkeypatch.setitem(web_app._TRACKERS, 'ip',
                            lambda: _StubTracker(DIRTY_IP))
        library = evaluate_payload('ip', DIRTY_IP).to_dict()
        api = api_client.get('/api/rules/ip/203.0.113.10').json()['rules']
        mcp = mcp_server._HANDLERS['rules_evaluate'](
            {'kind': 'ip', 'data': DIRTY_IP})
        assert library['score'] == api['score'] == mcp['score']
        assert library['band'] == api['band'] == mcp['band']

    def test_sdk_model_round_trips_the_api_payload(self, api_client,
                                                   monkeypatch):
        from obscuralens.web import app as web_app
        monkeypatch.setitem(web_app._TRACKERS, 'ip',
                            lambda: _StubTracker(DIRTY_IP))
        payload = api_client.get('/api/rules/ip/203.0.113.10').json()
        report = RuleReport.from_dict(payload, kind='ip')
        assert report.score == payload['rules']['score']
        assert report.matched_ids() == [h['id']
                                        for h in payload['rules']['hits']]

    def test_pack_totals_agree_across_surfaces(self, api_client):
        library = packs_catalog()
        api = api_client.get('/api/rules/packs').json()
        mcp = mcp_server._HANDLERS['rules_packs']({})
        assert library['total_rules'] == api['total_rules'] == \
            mcp['total_rules']

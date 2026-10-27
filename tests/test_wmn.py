"""
WhatsMyName (WMN) dataset interop tests.

Everything runs offline: dataset payloads are synthetic, HTTP responses come
from the shared fakes, and the dataset cache is pointed at a per-test
temporary directory.
"""

import json

import pytest

from obscuralens.config import config
from obscuralens.trackers import wmn as wmn_mod
from obscuralens.trackers.wmn import (
    WmnDatasetError,
    WmnTracker,
    dataset_path,
    load_cached_dataset,
    load_local_dataset,
    meta_path,
    parse_dataset,
    update_dataset,
    validate_site,
)
from obscuralens.utils.http_client import HttpClient


def _official_payload() -> dict:
    """A miniature stand-in for the official wmn-data.json."""
    return {
        'license': 'MIT',
        'authors': ['WebBreacher', 'community'],
        'sites': [
            {
                'name': 'Example',
                'uri_check': 'https://example.com/@{account}',
                'e_code': 200, 'e_string': 'profile-header',
                'm_code': 404, 'm_string': 'not found here',
                'known': ['alice'], 'cat': 'social',
            },
            {
                # Status-split-only site (no evidence strings).
                'name': 'CodeTest',
                'uri_check': 'https://code.test/u/{account}',
                'e_code': 200, 'e_string': '',
                'm_code': 404, 'm_string': '',
                'cat': 'coding',
            },
            {
                # POST body site with a pretty profile URL.
                'name': 'PostSite',
                'uri_check': 'https://api.post.test/graphql',
                'uri_pretty': 'https://post.test/u/{account}',
                'post_body': '{"query":"user(\\"{account}\\")"}',
                'headers': {'Content-Type': 'application/json'},
                'e_code': 200, 'e_string': '"name"',
                'm_code': 200, 'm_string': '"errors"',
                'cat': 'tech',
            },
            {
                # Bot-walled site - skipped unless include_protected.
                'name': 'WalledSite',
                'uri_check': 'https://walled.test/{account}',
                'e_code': 200, 'e_string': 'wall-bypass',
                'm_code': 404, 'm_string': '',
                'protection': ['cloudflare'], 'cat': 'social',
            },
            # Skipped entries:
            {'name': 'NoPlaceholder', 'uri_check': 'https://x.test/user',
             'e_code': 200, 'cat': 'misc'},
            {'name': 'MarkedInvalid', 'uri_check': 'https://x.test/{account}',
             'e_code': 200, 'cat': 'misc', 'valid': False},
            {'name': 'NoCat', 'uri_check': 'https://x.test/{account}',
             'e_code': 200},
            {'name': 'BadCode', 'uri_check': 'https://x.test/{account}',
             'e_code': 9999, 'cat': 'misc'},
            {'name': 'BadPost', 'uri_check': 'https://x.test/api',
             'post_body': '{"q":"fixed"}', 'e_code': 200, 'cat': 'misc'},
        ],
    }


@pytest.fixture()
def dataset():
    return parse_dataset(
        json.dumps(_official_payload()).encode('utf-8'), source='test')


@pytest.fixture()
def wmn_cache(tmp_path, monkeypatch):
    """Point the WMN cache at a per-test directory."""
    monkeypatch.setattr(config, 'config_dir', tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# Site validation
# ---------------------------------------------------------------------------

def test_validate_site_normalises_fields():
    site, reason = validate_site({
        'name': 'Example', 'uri_check': 'https://e.test/@{account}',
        'e_code': 200, 'e_string': 'found-marker', 'm_code': 404,
        'm_string': 'missing-marker', 'known': ['alice', 5],
        'cat': 'social', 'headers': {'A': 1},
    })
    assert reason == ''
    assert site['e_code'] == 200 and site['m_code'] == 404
    assert site['known'] == ['alice']
    assert site['headers'] == {'A': '1'}
    assert site['protection'] == []


@pytest.mark.parametrize('entry,reason_part', [
    ({'uri_check': 'https://x.test/{account}', 'e_code': 200,
      'cat': 'misc'}, 'missing name'),
    ({'name': 'A', 'uri_check': 'https://x.test/user', 'e_code': 200,
      'cat': 'misc'}, 'placeholder'),
    ({'name': 'A', 'uri_check': 'https://x.test/{account}', 'e_code': 200,
      'cat': 'misc', 'valid': False}, 'invalid upstream'),
    ({'name': 'A', 'uri_check': 'https://x.test/{account}', 'e_code': 200},
     'missing category'),
    ({'name': 'A', 'uri_check': 'https://x.test/{account}', 'e_code': 'abc',
      'cat': 'misc'}, 'e_code'),
    ({'name': 'A', 'uri_check': 'https://x.test/{account}', 'e_code': 700,
      'cat': 'misc'}, 'e_code'),
    ({'name': 'A', 'uri_check': 'https://x.test/api',
      'post_body': '{"q":"fixed"}', 'e_code': 200, 'cat': 'misc'},
     'post_body'),
])
def test_validate_site_skip_reasons(entry, reason_part):
    site, reason = validate_site(entry)
    assert site is None
    assert reason_part in reason


def test_validate_site_non_object():
    assert validate_site('nope')[0] is None


# ---------------------------------------------------------------------------
# Dataset parsing
# ---------------------------------------------------------------------------

def test_parse_dataset_counts_categories_and_provenance(dataset):
    assert dataset.declared == 9
    assert len(dataset.sites) == 4
    assert len(dataset.skipped) == 5
    assert dataset.categories == {'coding': 1, 'social': 2, 'tech': 1}
    assert dataset.license == 'MIT'
    assert dataset.authors == ['WebBreacher', 'community']
    assert len(dataset.sha256) == 64
    assert {name for name, _ in dataset.skipped} == {
        'NoPlaceholder', 'MarkedInvalid', 'NoCat', 'BadCode', 'BadPost'}


def test_parse_dataset_accepts_bare_list():
    payload = [{'name': 'Solo', 'uri_check': 'https://s.test/{account}',
                'e_code': 200, 'cat': 'misc'}]
    dataset = parse_dataset(json.dumps(payload).encode('utf-8'), source='t')
    assert [s['name'] for s in dataset.sites] == ['Solo']
    assert dataset.license == ''


def test_parse_dataset_dedupes_by_name():
    payload = [
        {'name': 'Dup', 'uri_check': 'https://a.test/{account}',
         'e_code': 200, 'cat': 'misc'},
        {'name': 'dup', 'uri_check': 'https://b.test/{account}',
         'e_code': 200, 'cat': 'misc'},
    ]
    dataset = parse_dataset(json.dumps(payload).encode('utf-8'), source='t')
    assert len(dataset.sites) == 1
    assert dataset.skipped == [('dup', 'duplicate name')]


def test_parse_dataset_rejects_bad_json():
    with pytest.raises(WmnDatasetError, match='not valid JSON'):
        parse_dataset(b'{not json', source='t')


def test_parse_dataset_rejects_no_valid_sites():
    payload = {'license': 'x', 'authors': [], 'sites': [
        {'name': 'Broken', 'uri_check': 'nope', 'e_code': 200, 'cat': 'm'}]}
    with pytest.raises(WmnDatasetError, match='no valid sites'):
        parse_dataset(json.dumps(payload).encode('utf-8'), source='t')


def test_parse_dataset_rejects_non_list_sites():
    with pytest.raises(WmnDatasetError, match='not a list'):
        parse_dataset(json.dumps({'sites': 5}).encode('utf-8'), source='t')


def test_load_local_dataset_reports_source(tmp_path):
    path = tmp_path / 'wmn.json'
    path.write_text(json.dumps(_official_payload()), encoding='utf-8')
    dataset = load_local_dataset(path, source='my-import')
    assert dataset.source == 'my-import'
    assert len(dataset.sites) == 4


def test_load_local_dataset_missing_file(tmp_path):
    with pytest.raises(WmnDatasetError, match='cannot read'):
        load_local_dataset(tmp_path / 'nope.json')


# ---------------------------------------------------------------------------
# Cache + update
# ---------------------------------------------------------------------------

def test_update_from_local_source_writes_cache(wmn_cache):
    source = wmn_cache / 'import.json'
    source.write_text(json.dumps(_official_payload()), encoding='utf-8')
    dataset = update_dataset(str(source))
    assert dataset_path().exists() and meta_path().exists()
    assert dataset.source == str(source)

    cached = load_cached_dataset()
    assert cached is not None
    assert cached.sha256 == dataset.sha256
    assert len(cached.sites) == 4


def test_update_from_url_uses_fetch(wmn_cache, monkeypatch):
    body = json.dumps(_official_payload())

    def fake_fetch(url, use_cache=True, **kwargs):
        assert 'WebBreacher/WhatsMyName' in url
        assert use_cache is False  # dataset updates must bypass the cache
        return 200, body, ''

    monkeypatch.setattr(wmn_mod.http, 'fetch', fake_fetch)
    dataset = update_dataset()
    assert dataset.source == wmn_mod.WMN_DATA_URL
    assert dataset.fetched_at  # timestamped
    cached = load_cached_dataset()
    assert len(cached.sites) == 4
    assert cached.sha256 == dataset.sha256


def test_update_url_failure_raises(wmn_cache, monkeypatch):
    monkeypatch.setattr(wmn_mod.http, 'fetch',
                        lambda url, **kw: (500, '', 'http 500'))
    with pytest.raises(WmnDatasetError, match='http 500'):
        update_dataset()


def test_update_network_exception_raises(wmn_cache, monkeypatch):
    def boom(url, **kwargs):
        raise ConnectionError('no route')

    monkeypatch.setattr(wmn_mod.http, 'fetch', boom)
    with pytest.raises(WmnDatasetError, match='download failed'):
        update_dataset()


def test_update_missing_local_source_raises(wmn_cache):
    with pytest.raises(WmnDatasetError, match='not found'):
        update_dataset(str(wmn_cache / 'nope.json'))


def test_update_bad_payload_raises_and_leaves_no_cache(wmn_cache,
                                                       monkeypatch):
    monkeypatch.setattr(wmn_mod.http, 'fetch',
                        lambda url, **kw: (200, '<html>404</html>', ''))
    with pytest.raises(WmnDatasetError):
        update_dataset()
    assert not dataset_path().exists()


def test_load_cached_dataset_digest_mismatch_raises(wmn_cache):
    update_dataset_source = wmn_cache / 'ds.json'
    update_dataset_source.write_text(json.dumps(_official_payload()),
                                     encoding='utf-8')
    update_dataset(str(update_dataset_source))
    meta = json.loads(meta_path().read_text(encoding='utf-8'))
    meta['sha256'] = '0' * 64
    meta_path().write_text(json.dumps(meta), encoding='utf-8')
    with pytest.raises(WmnDatasetError, match='digest mismatch'):
        load_cached_dataset()


def test_load_cached_dataset_absent_returns_none(wmn_cache):
    assert load_cached_dataset() is None


def test_load_cached_dataset_without_meta_still_works(wmn_cache):
    # A cache file without its sidecar (older layout) is still usable.
    payload = json.dumps({'license': 'MIT', 'authors': [], 'sites': [
        {'name': 'Solo', 'uri_check': 'https://s.test/{account}',
         'e_code': 200, 'cat': 'misc'}]})
    dataset_path().write_text(payload, encoding='utf-8')
    cached = load_cached_dataset()
    assert cached is not None and len(cached.sites) == 1
    assert cached.fetched_at == ''


# ---------------------------------------------------------------------------
# Verdict mapping
# ---------------------------------------------------------------------------

def _tracker(dataset, **kwargs):
    return WmnTracker(dataset, **kwargs)


def test_verdict_found_high_on_evidence_string(dataset, fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(
        status_code=200, text='<html>profile-header ...</html>')
    result = _tracker(dataset, sites=['Example']).check('alice')
    row = result['results'][0]
    assert row['status'] == 'found' and row['exists'] is True
    assert row['confidence'] == 'high'
    assert 'evidence string' in row['reason']


def test_verdict_found_medium_on_status_split_only(dataset, fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(status_code=200, text='x')
    result = _tracker(dataset, sites=['CodeTest']).check('bob')
    row = result['results'][0]
    assert row['status'] == 'found'
    assert row['confidence'] == 'medium'
    assert 'community-verified status split' in row['reason']


def test_verdict_not_found_high_on_missing_marker(dataset, fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(
        status_code=200, text='oops - not found here, go home')
    result = _tracker(dataset, sites=['Example']).check('bob')
    row = result['results'][0]
    assert row['status'] == 'not_found'
    assert row['confidence'] == 'high'
    assert row['exists'] is False


def test_verdict_not_found_medium_on_missing_split(dataset, fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(status_code=404, text='')
    result = _tracker(dataset, sites=['CodeTest']).check('bob')
    row = result['results'][0]
    assert row['status'] == 'not_found'
    assert row['confidence'] == 'medium'


def test_verdict_unknown_on_bot_wall(dataset, fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(status_code=403, text='')
    result = _tracker(dataset, sites=['Example']).check('bob')
    row = result['results'][0]
    assert row['status'] == 'unknown'
    assert 'bot wall' in row['reason']


def test_verdict_unknown_on_mismatch(dataset, fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(
        status_code=500, text='server oops')
    result = _tracker(dataset, sites=['Example']).check('bob')
    row = result['results'][0]
    assert row['status'] == 'unknown'
    assert 'no decisive signal' in row['reason']


def test_verdict_unknown_on_network_error(dataset, fake_http, fake_response):
    def broken(url, **kwargs):
        raise ConnectionError('reset')

    fake_http.get = broken
    result = _tracker(dataset, sites=['Example']).check('bob')
    row = result['results'][0]
    assert row['status'] == 'unknown'
    assert row['error'] == 'ConnectionError'
    assert row['reason'] == 'network error'


def test_evidence_match_is_case_insensitive(dataset, fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(
        status_code=200, text='<HTML>PROFILE-HEADER</HTML>')
    result = _tracker(dataset, sites=['Example']).check('alice')
    assert result['results'][0]['status'] == 'found'


# ---------------------------------------------------------------------------
# Sweep mechanics
# ---------------------------------------------------------------------------

def test_check_result_shape_and_counts(dataset, fake_http, fake_response):
    def dispatch(url, **kwargs):
        if 'example.com' in url:
            return fake_response(status_code=200,
                                 text='profile-header present')
        if 'code.test' in url:
            return fake_response(status_code=404, text='')
        return fake_response(status_code=403, text='')

    fake_http.get = dispatch
    result = _tracker(dataset, sites=['Example', 'CodeTest',
                                      'WalledSite'],
                      include_protected=True).check('alice')
    assert result['engine'] == 'whatsmyname'
    assert result['total_checked'] == 3
    assert result['found_count'] == 1
    assert result['not_found_count'] == 1
    assert result['unknown_count'] == 1
    assert result['success'] is True
    assert {r['platform'] for r in result['results']} == {
        'Example', 'CodeTest', 'WalledSite'}


def test_check_records_dataset_provenance(dataset, fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(status_code=404, text='')
    result = _tracker(dataset).check('alice')
    assert result['dataset']['sites_available'] == 4
    assert result['dataset']['sites_selected'] == 3  # WalledSite excluded
    assert result['dataset']['license'] == 'MIT'
    assert result['filters']['include_protected'] is False
    assert result['filters']['dropped_by_filter']['protected'] == 1


def test_category_filter(dataset, fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(status_code=404, text='')
    tracker = _tracker(dataset, categories=['coding'])
    assert [s['name'] for s in tracker.sites] == ['CodeTest']
    assert tracker.dropped_filters['category'] == 3
    result = tracker.check('alice')
    assert result['filters']['categories'] == ['coding']


def test_sites_filter_unknown_names_select_nothing(dataset):
    tracker = _tracker(dataset, sites=['NoSuchSite'])
    assert tracker.sites == []


def test_protected_sites_excluded_by_default(dataset):
    tracker = _tracker(dataset)
    assert 'WalledSite' not in {s['name'] for s in tracker.sites}
    tracker_open = _tracker(dataset, include_protected=True)
    assert 'WalledSite' in {s['name'] for s in tracker_open.sites}


def test_limit_caps_checked_sites(dataset, fake_http, fake_response):
    fake_http.get = lambda url, **kw: fake_response(status_code=404, text='')
    result = _tracker(dataset, include_protected=True).check('alice', limit=2)
    assert result['total_checked'] == 2
    assert result['dataset']['sites_checked_cap'] == 2


def test_display_url_prefers_uri_pretty(dataset, fake_http, fake_response):
    fake_http.post_raw = lambda url, **kw: fake_response(
        status_code=200, text='{"data":{"name":"alice"}}')
    result = _tracker(dataset, sites=['PostSite']).check('alice')
    row = result['results'][0]
    assert row['url'] == 'https://post.test/u/alice'
    assert row['status'] == 'found'


def test_post_body_entries_use_post_with_headers(dataset, fake_http, fake_response):
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return fake_response(status_code=200, text='{"data":{"name":"x"}}')

    fake_http.post_raw = fake_post
    _tracker(dataset, sites=['PostSite']).check('alice')
    assert len(calls) == 1
    url, kwargs = calls[0]
    assert url == 'https://api.post.test/graphql'
    assert b'alice' in kwargs['data']
    assert kwargs['headers']['Content-Type'] == 'application/json'


def test_empty_sweep_is_successful_noop(dataset):
    result = _tracker(dataset, sites=['NoSuchSite']).check('alice')
    assert result['total_checked'] == 0
    assert result['success'] is True


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------

def test_parser_accepts_wmn_check_flags():
    from obscuralens.commands import build_parser
    args = build_parser().parse_args([
        'wmn', 'check', 'john_doe', '--category', 'social,coding',
        '--limit', '5', '--format', 'json', '--include-protected'])
    assert args.command == 'wmn' and args.action == 'check'
    assert args.target == 'john_doe'
    assert args.category == 'social,coding'
    assert args.limit == 5
    assert args.include_protected is True


def test_parser_accepts_wmn_update_source():
    from obscuralens.commands import build_parser
    args = build_parser().parse_args(
        ['wmn', 'update', '--source', '/tmp/wmn.json'])
    assert args.action == 'update'
    assert args.source == '/tmp/wmn.json'


def test_wmn_without_action_prints_usage(capsys):
    from obscuralens.commands import run
    assert run(['wmn']) == 2
    assert 'usage' in capsys.readouterr().err


def test_wmn_check_without_dataset_hints_update(wmn_cache, capsys):
    from obscuralens.commands import run
    assert run(['wmn', 'check', 'alice']) == 1
    assert 'wmn update' in capsys.readouterr().err


def test_wmn_check_end_to_end_json(wmn_cache, fake_http, capsys, fake_response):
    source = wmn_cache / 'ds.json'
    source.write_text(json.dumps(_official_payload()), encoding='utf-8')
    assert wmn_mod.load_local_dataset(source)  # sanity: fixture parses

    from obscuralens.commands import run
    assert run(['wmn', 'update', '--source', str(source)]) == 0
    capsys.readouterr()  # flush the update summary from stdout

    fake_http.get = lambda url, **kw: fake_response(
        status_code=200, text='profile-header present')
    assert run(['wmn', 'check', 'alice', '--format', 'json']) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['engine'] == 'whatsmyname'
    # Example (evidence string) and CodeTest (status split) both count as
    # found; PostSite's default raw-POST stub answers 599 -> unknown.
    assert payload['found_count'] == 2
    assert payload['dataset']['sites_selected'] == 3


def test_wmn_check_text_report(wmn_cache, fake_http, capsys, fake_response):
    source = wmn_cache / 'ds.json'
    source.write_text(json.dumps(_official_payload()), encoding='utf-8')
    from obscuralens.commands import run
    run(['wmn', 'update', '--source', str(source)])
    capsys.readouterr()  # flush the update summary from stdout

    fake_http.get = lambda url, **kw: fake_response(status_code=404, text='')
    assert run(['wmn', 'check', 'bob', '--category', 'coding']) == 0
    out = capsys.readouterr().out
    assert 'WHATSMYNAME SWEEP' in out.upper()
    assert 'CodeTest' in out


def test_wmn_info_and_categories(wmn_cache, capsys):
    source = wmn_cache / 'ds.json'
    source.write_text(json.dumps(_official_payload()), encoding='utf-8')
    from obscuralens.commands import run
    assert run(['wmn', 'update', '--source', str(source)]) == 0
    capsys.readouterr()  # flush the update summary from stdout
    assert run(['wmn', 'info']) == 0
    out = capsys.readouterr().out
    assert 'Sites valid' in out
    assert run(['wmn', 'categories', '--format', 'json']) == 0
    cats = json.loads(capsys.readouterr().out)
    assert cats == {'coding': 1, 'social': 2, 'tech': 1}


# ---------------------------------------------------------------------------
# HttpClient.post (raw response POST used by WMN POST entries)
# ---------------------------------------------------------------------------

def test_http_client_post_returns_raw_response(tmp_env, monkeypatch, fake_response):
    monkeypatch.setattr(config.app_config, 'requests_per_second', 0.0)
    client = HttpClient(timeout=5)
    calls = []

    def fake_session_post(url, **kwargs):
        calls.append((url, kwargs))
        return fake_response(status_code=201, text='created')

    monkeypatch.setattr(client.session, 'post', fake_session_post)
    response = client.post('https://api.test/graphql', data=b'{"q":1}',
                           headers={'Content-Type': 'application/json'})
    assert response.status_code == 201
    assert response.text == 'created'
    url, kwargs = calls[0]
    assert url == 'https://api.test/graphql'
    assert kwargs['data'] == b'{"q":1}'
    assert kwargs['headers']['Content-Type'] == 'application/json'
    assert kwargs['timeout'] == 5  # default timeout applied

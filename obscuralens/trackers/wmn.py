"""
WhatsMyName (WMN) dataset interop for the username sweep.

`WhatsMyName <https://github.com/WebBreacher/WhatsMyName>`_ (by Micah
Hoffman / WebBreacher and the OSINT community) maintains a curated JSON
dataset of ~700 profile-URL checks that projects such as Sherlock and
Maigret consume as an additional site list. This module imports that
dataset as an additional username sweep and maps its per-site rules onto
the same honest three-state verdicts the built-in sweep uses:

* ``found``      status == e_code AND the evidence string is present in the
                 body (high confidence), or no evidence string is declared
                 and the community-verified status split matched (medium).
* ``not_found``  the missing-marker string is present in the body (high), or
                 the community-verified missing split matched with no marker
                 string declared (medium).
* ``unknown``    bot walls (403/429/...), network errors, and code/evidence
                 mismatches - never guessed.

The dataset file is cached under the config directory together with a
metadata sidecar (source, fetch time, SHA-256). ``obscuralens wmn update``
refreshes it; every other command runs from the cache, so sweeps are
offline-safe once the dataset has been downloaded.
"""

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import config
from ..database import db
from ..utils.http_client import http
from .username_tracker import BLOCKED_STATUSES, UsernameResult

WMN_DATA_URL = ('https://raw.githubusercontent.com/WebBreacher/WhatsMyName/'
                'main/wmn-data.json')
WMN_REPO_URL = 'https://github.com/WebBreacher/WhatsMyName'
DATASET_FILE = 'wmn-data.json'
META_FILE = 'wmn-data.meta.json'

VALID_STATUS_CODES = range(100, 600)


class WmnDatasetError(Exception):
    """Raised when a WMN dataset cannot be downloaded, read or parsed."""


# ---------------------------------------------------------------------------
# Dataset model + validation
# ---------------------------------------------------------------------------

@dataclass
class WmnDataset:
    """A validated WhatsMyName dataset plus its provenance metadata."""
    sites: List[Dict[str, Any]] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)
    categories: Dict[str, int] = field(default_factory=dict)
    source: str = ''
    sha256: str = ''
    fetched_at: str = ''
    license: str = ''
    authors: List[str] = field(default_factory=list)
    declared: int = 0

    def summary(self) -> Dict[str, Any]:
        """JSON-safe overview used by ``wmn info`` / ``wmn update``."""
        return {
            'source': self.source,
            'sha256': self.sha256,
            'fetched_at': self.fetched_at,
            'license': self.license,
            'authors': self.authors,
            'sites_declared': self.declared,
            'sites_valid': len(self.sites),
            'sites_skipped': len(self.skipped),
            'skipped': [{'name': name, 'reason': reason}
                        for name, reason in self.skipped],
            'categories': dict(sorted(self.categories.items())),
        }


def _as_int(value: Any) -> Optional[int]:
    """Coerce a status-code field to a sane int, else None."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        code = int(value)
    except (TypeError, ValueError):
        return None
    return code if code in VALID_STATUS_CODES else None


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ''


def validate_site(raw: Any) -> Tuple[Optional[Dict[str, Any]], str]:
    """
    Normalise one raw WMN entry.

    Returns ``(site, '')`` when the entry is usable, ``(None, reason)``
    when it must be skipped. A site is usable when it has a name, a
    ``uri_check`` URL containing the ``{account}`` placeholder, a category
    and a sane ``e_code``; ``valid: false`` entries (marked bad upstream)
    are always skipped.
    """
    if not isinstance(raw, dict):
        return None, 'not an object'

    name = _as_str(raw.get('name')).strip()
    uri_check = _as_str(raw.get('uri_check')).strip()
    cat = _as_str(raw.get('cat')).strip()

    if not name:
        return None, 'missing name'
    if raw.get('valid') is False:
        return None, 'marked invalid upstream'
    e_code = _as_int(raw.get('e_code'))
    if e_code is None:
        return None, 'invalid e_code'
    m_code = _as_int(raw.get('m_code'))
    post_body = _as_str(raw.get('post_body')) or None
    if post_body:
        # POST entries carry the account in the request body; the URL is
        # often a static API endpoint (e.g. a GraphQL host).
        if '{account}' not in post_body:
            return None, 'post_body has no {account} placeholder'
    elif '{account}' not in uri_check:
        return None, 'uri_check has no {account} placeholder'
    if not cat:
        return None, 'missing category'
    headers = raw.get('headers') if isinstance(raw.get('headers'), dict) else {}
    headers = {str(k): str(v) for k, v in headers.items()}

    site = {
        'name': name,
        'cat': cat,
        'uri_check': uri_check,
        'uri_pretty': _as_str(raw.get('uri_pretty')).strip(),
        'e_code': e_code,
        'e_string': _as_str(raw.get('e_string')),
        'm_code': m_code,
        'm_string': _as_str(raw.get('m_string')),
        'post_body': post_body,
        'headers': headers,
        'known': [k for k in raw.get('known', []) if isinstance(k, str)],
        'protection': [p for p in raw.get('protection', [])
                       if isinstance(p, str)],
    }
    return site, ''


def parse_dataset(raw_bytes: bytes, source: str,
                  fetched_at: str = '') -> WmnDataset:
    """
    Parse and validate a WMN dataset payload.

    Accepts the official top-level object (license/authors/sites) or a bare
    list of sites. Raises :class:`WmnDatasetError` on unparsable JSON or a
    payload with no valid entries (a truncated or renamed upstream file
    must never silently produce an empty sweep).
    """
    try:
        raw = json.loads(raw_bytes.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as e:
        raise WmnDatasetError(f'not valid JSON: {e}') from e

    sites_raw: List[Any] = []
    license_name = ''
    authors: List[str] = []
    if isinstance(raw, dict):
        sites_raw = raw.get('sites') or []
        license_name = _as_str(raw.get('license'))
        authors = [a for a in raw.get('authors', []) if isinstance(a, str)]
    elif isinstance(raw, list):
        sites_raw = raw
    if not isinstance(sites_raw, list):
        raise WmnDatasetError('"sites" is not a list')

    sites: List[Dict[str, Any]] = []
    skipped: List[Tuple[str, str]] = []
    seen: set = set()
    for entry in sites_raw:
        site, reason = validate_site(entry)
        if site is None:
            label = entry.get('name', '?') if isinstance(entry, dict) else '?'
            skipped.append((str(label), reason))
            continue
        if site['name'].lower() in seen:
            skipped.append((site['name'], 'duplicate name'))
            continue
        seen.add(site['name'].lower())
        sites.append(site)

    if not sites:
        raise WmnDatasetError('no valid sites in dataset')

    categories: Dict[str, int] = {}
    for site in sites:
        categories[site['cat']] = categories.get(site['cat'], 0) + 1

    return WmnDataset(
        sites=sites,
        skipped=skipped,
        categories=categories,
        source=source,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        fetched_at=fetched_at,
        license=license_name,
        authors=authors,
        declared=len(sites_raw),
    )


# ---------------------------------------------------------------------------
# Cache + download
# ---------------------------------------------------------------------------

def dataset_path() -> Path:
    """Path of the cached dataset file."""
    return Path(config.config_dir) / DATASET_FILE


def meta_path() -> Path:
    """Path of the cached dataset metadata sidecar."""
    return Path(config.config_dir) / META_FILE


def load_local_dataset(path: Path, source: str = '') -> WmnDataset:
    """Parse a dataset from a local file (import path / cache)."""
    try:
        raw_bytes = Path(path).read_bytes()
    except OSError as e:
        raise WmnDatasetError(f'cannot read {path}: {e}') from e
    return parse_dataset(raw_bytes, source or str(path))


def load_cached_dataset() -> Optional[WmnDataset]:
    """Load the cached dataset, or None when it was never downloaded."""
    path = dataset_path()
    if not path.exists():
        return None
    dataset = load_local_dataset(path, source='cache')
    meta_file = meta_path()
    if not meta_file.exists():
        return dataset
    try:
        meta = json.loads(meta_file.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return dataset
    dataset.source = _as_str(meta.get('source')) or dataset.source
    dataset.fetched_at = _as_str(meta.get('fetched_at'))
    # The cache must match its recorded digest - a truncated write (full
    # disk, killed process) degrades to "no dataset" instead of a sweep
    # against half the sites.
    if dataset.sha256 != _as_str(meta.get('sha256')):
        raise WmnDatasetError('cached dataset digest mismatch')
    return dataset


def update_dataset(source: Optional[str] = None) -> WmnDataset:
    """
    Download (or import) the WMN dataset and write the cache.

    ``source`` may be a local file path or an http(s) URL; the default is
    the official dataset JSON. The cache write is atomic (tmp + replace) so
    a killed process cannot leave a truncated dataset behind.
    """
    fetched_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    if source:
        candidate = Path(source)
        if '://' not in source:
            if not candidate.is_file():
                raise WmnDatasetError(f'source file not found: {source}')
            dataset = load_local_dataset(candidate, source=source)
        else:
            dataset = _fetch_dataset(source, fetched_at)
    else:
        dataset = _fetch_dataset(WMN_DATA_URL, fetched_at)

    # Serialise once, digest exactly what will be stored, then write both
    # files atomically (tmp + replace) so a killed process cannot leave a
    # truncated dataset behind.
    payload = json.dumps(
        {'license': dataset.license, 'authors': dataset.authors,
         'sites': dataset.sites},
        ensure_ascii=False).encode('utf-8')
    dataset.sha256 = hashlib.sha256(payload).hexdigest()

    cache_dir = Path(config.config_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    tmp_file = cache_dir / (DATASET_FILE + '.tmp')
    tmp_file.write_bytes(payload)
    tmp_file.replace(cache_dir / DATASET_FILE)
    meta = {
        'source': dataset.source,
        'fetched_at': dataset.fetched_at,
        'sha256': dataset.sha256,
        'sites_declared': dataset.declared,
        'sites_valid': len(dataset.sites),
        'license': dataset.license,
    }
    tmp_meta = cache_dir / (META_FILE + '.tmp')
    tmp_meta.write_text(json.dumps(meta, indent=2) + '\n', encoding='utf-8')
    tmp_meta.replace(cache_dir / META_FILE)
    return dataset


def _fetch_dataset(url: str, fetched_at: str) -> WmnDataset:
    """Download a dataset over HTTP and parse it."""
    try:
        code, text, error = http.fetch(url, use_cache=False)
    except Exception as e:
        raise WmnDatasetError(f'download failed: {type(e).__name__}: {e}') from e
    if error:
        raise WmnDatasetError(f'download failed: {error}')
    if code != 200:
        raise WmnDatasetError(f'download failed: HTTP {code}')
    return parse_dataset(text.encode('utf-8'), source=url,
                         fetched_at=fetched_at)


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------

class WmnTracker:
    """
    Sweep a username across the WhatsMyName dataset.

    Reuses :class:`UsernameResult` so WMN rows flow through the same
    formatting, CSV and JSON paths as built-in username results.
    """

    def __init__(self, dataset: WmnDataset, categories: Optional[List[str]] = None,
                 sites: Optional[List[str]] = None,
                 include_protected: bool = False):
        selected = dataset.sites
        self.include_protected = bool(include_protected)
        self.requested_categories = sorted(
            {c.strip() for c in (categories or []) if c.strip()})
        self.dropped_filters: Dict[str, int] = {}
        if categories:
            wanted = {c.strip().lower() for c in categories if c.strip()}
            filtered = [s for s in selected if s['cat'].lower() in wanted]
            self.dropped_filters['category'] = len(selected) - len(filtered)
            selected = filtered
        if sites:
            wanted = {s.strip().lower() for s in sites if s.strip()}
            filtered = [s for s in selected if s['name'].lower() in wanted]
            self.dropped_filters['name'] = len(selected) - len(filtered)
            selected = filtered
        if not include_protected:
            protected = [s for s in selected if s['protection']]
            self.dropped_filters['protected'] = len(protected)
            selected = [s for s in selected if not s['protection']]
        self.dataset = dataset
        self.sites = selected

    def check(self, username: str, limit: Optional[int] = None,
              max_workers: Optional[int] = None) -> Dict[str, Any]:
        """
        Sweep one username across the selected sites (parallel).

        Returns a result dict shaped like UsernameTracker.track's output
        (same per-row keys) plus ``engine`` / ``dataset`` / ``filters``
        provenance blocks.
        """
        selected = self.sites
        if limit is not None and limit >= 0:
            selected = selected[:limit]

        result: Dict[str, Any] = {
            'username': username,
            'engine': 'whatsmyname',
            'dataset': {
                'source': self.dataset.source,
                'sha256': self.dataset.sha256,
                'fetched_at': self.dataset.fetched_at,
                'license': self.dataset.license,
                'sites_available': len(self.dataset.sites),
                'sites_selected': len(self.sites),
                'sites_checked_cap': len(selected),
            },
            'filters': {
                'categories': self.requested_categories or
                              sorted({s['cat'] for s in self.sites}),
                'include_protected': self.include_protected,
                'dropped_by_filter': dict(self.dropped_filters),
                'limit': limit,
            },
            'results': [],
            'found_count': 0,
            'not_found_count': 0,
            'unknown_count': 0,
            'total_checked': 0,
            'success': True,
            'errors': [],
        }

        workers = min(12, max(1, max_workers or config.app_config.max_workers))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {
                executor.submit(self._check_site, site, username): site
                for site in selected
            }
            for future in as_completed(future_map):
                site = future_map[future]
                try:
                    check = future.result()
                    result['results'].append(asdict(check))
                    result['total_checked'] += 1
                    if check.status == 'found':
                        result['found_count'] += 1
                    elif check.status == 'not_found':
                        result['not_found_count'] += 1
                    else:
                        result['unknown_count'] += 1
                except Exception as e:  # pragma: no cover - defensive
                    result['errors'].append(
                        f"{site['name']}: {type(e).__name__}")
                    result['unknown_count'] += 1

        result['results'].sort(key=lambda r: r['platform'])
        result['success'] = result['total_checked'] > 0 or not selected

        db.save_query('wmn', username, result, result['success'],
                      '; '.join(result['errors']) if result['errors'] else '')
        return result

    # ------------------------------------------------------------------
    # Per-site check
    # ------------------------------------------------------------------

    def _check_site(self, site: Dict[str, Any],
                    username: str) -> UsernameResult:
        name = site['name']
        check_url = site['uri_check'].replace('{account}', username)
        display_url = (site.get('uri_pretty') or site['uri_check']).replace(
            '{account}', username)
        started = time.time()

        try:
            if site.get('post_body'):
                body = site['post_body'].replace('{account}', username)
                response = http.post(check_url, data=body.encode('utf-8'),
                                     headers=site.get('headers') or {},
                                     allow_redirects=True)
            else:
                response = http.get(check_url, allow_redirects=True,
                                    headers=site.get('headers') or {})
        except Exception as e:
            return UsernameResult(
                platform=name, url=display_url, exists=False,
                status='unknown', confidence='low', reason='network error',
                status_code=0, response_time=round(time.time() - started, 2),
                error=type(e).__name__,
            )

        elapsed = round(time.time() - started, 2)
        status, confidence, reason = self._verdict(site, response)
        return UsernameResult(
            platform=name, url=display_url, exists=(status == 'found'),
            status=status, confidence=confidence, reason=reason,
            status_code=response.status_code, response_time=elapsed,
        )

    @staticmethod
    def _verdict(site: Dict[str, Any],
                 response: Any) -> Tuple[str, str, str]:
        """
        Map a WMN site spec + HTTP response to an honest verdict.

        Evidence strings are matched case-insensitively so a small layout
        change upstream cannot flip a verdict; when the response says
        nothing decisive the row stays ``unknown``.
        """
        code = response.status_code
        low = (response.text or '').lower()
        e_code = site.get('e_code')
        e_string = (site.get('e_string') or '').lower()
        m_code = site.get('m_code')
        m_string = (site.get('m_string') or '').lower()

        if code in BLOCKED_STATUSES:
            return 'unknown', 'low', f'bot wall / rate limit (HTTP {code})'

        if e_code is not None and code == e_code and (not e_string or e_string in low):
            if e_string:
                return 'found', 'high', f'HTTP {code} + evidence string matched'
            return 'found', 'medium', \
                f'HTTP {code} (community-verified status split)'

        if m_string and m_string in low:
            return 'not_found', 'high', 'missing-marker string present'

        if m_code is not None and code == m_code and not m_string:
            return 'not_found', 'medium', \
                f'HTTP {code} (community-verified missing split)'

        return 'unknown', 'low', f'no decisive signal (HTTP {code})'

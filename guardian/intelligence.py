"""Public threat intelligence; never opens URLs submitted by Discord users."""
import asyncio
import json
import logging
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

import aiohttp

log = logging.getLogger('guardian.intelligence')
SOURCES = {
    'discord-antiscam': {
        'url': 'https://raw.githubusercontent.com/Discord-AntiScam/scam-links/main/list.json',
        'format': 'json', 'subdomains': True,
    },
    'phishing-army': {
        'url': 'https://phishing.army/download/phishing_army_blocklist.txt',
        'format': 'text', 'subdomains': False,
    },
}
# Shared platforms must not be blocked wholesale by an upstream list mistake.
PROTECTED_ROOTS = {'discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net',
                   'github.com', 'github.io', 'google.com', 'youtube.com',
                   'cloudflare.com', 'pages.dev', 'workers.dev', 'amazonaws.com'}
DOMAIN = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
                    r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
MAX_BYTES = 12 * 1024 * 1024


def normalize_domain(value):
    if not isinstance(value, str):
        return None
    try:
        value = value.strip().rstrip('.').encode('idna').decode().lower()
    except UnicodeError:
        return None
    if not DOMAIN.fullmatch(value) or value in PROTECTED_ROOTS:
        return None
    return value


def parse_feed(body, kind):
    values = json.loads(body) if kind == 'json' else body.splitlines()
    if not isinstance(values, list) or len(values) > 1000000:
        raise ValueError('Invalid feed shape/size')
    domains = {d for item in values if (d := normalize_domain(item))}
    if len(domains) < 100:
        raise ValueError('Feed is empty or unexpectedly small')
    return domains


class Intelligence:
    def __init__(self, cache_path, enabled=True, max_age_hours=168):
        self.path, self.enabled = Path(cache_path), enabled
        self.max_age = timedelta(hours=max_age_hours)
        self.feeds = {}
        self.errors = {}
        self.lock = asyncio.Lock()
        if enabled:
            self._load()

    def _load(self):
        try:
            if self.path.stat().st_size > MAX_BYTES * len(SOURCES):
                raise ValueError('Oversized cache')
            raw = json.loads(self.path.read_text())
            if not isinstance(raw, dict):
                raise ValueError('Invalid cache shape')
            for name, record in raw.items():
                if name not in SOURCES:
                    continue
                stamp = datetime.fromisoformat(record['updated'])
                if stamp.tzinfo is None:
                    raise ValueError('Naive timestamp')
                values = record['domains']
                if not isinstance(values, list):
                    raise ValueError('Invalid cache domains')
                self.feeds[name] = {'domains': {d for v in values if (d := normalize_domain(v))},
                                    'updated': stamp}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, KeyError):
            log.warning('Threat cache could not be loaded; fresh download required')

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        raw = {name: {'updated': r['updated'].isoformat(), 'domains': sorted(r['domains'])}
               for name, r in self.feeds.items()}
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps(raw))
        temporary.replace(self.path)

    async def refresh(self):
        if not self.enabled:
            return
        async with self.lock:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=25), trust_env=True) as session:
                results = await asyncio.gather(*(self._fetch(session, name, spec)
                                                for name, spec in SOURCES.items()), return_exceptions=True)
            for name, result in zip(SOURCES, results):
                if isinstance(result, Exception):
                    self.errors[name] = type(result).__name__
                    log.warning('Feed %s refresh failed (%s); keeping previous snapshot', name, type(result).__name__)
                else:
                    self.feeds[name] = {'domains': result, 'updated': datetime.now(timezone.utc)}
                    self.errors.pop(name, None)
                    log.info('Feed %s: %d domains', name, len(result))
            try:
                await asyncio.to_thread(self._save)
            except OSError:
                log.error('Could not persist threat cache; in-memory data remains usable')

    async def _fetch(self, session, name, spec):
        async with session.get(spec['url'], allow_redirects=False) as response:
            response.raise_for_status()
            if response.status != 200:
                raise ValueError('Unexpected redirect or empty response')
            body = bytearray()
            async for chunk in response.content.iter_chunked(65536):
                body.extend(chunk)
                if len(body) > MAX_BYTES:
                    raise ValueError('Feed exceeds download limit')
        return await asyncio.to_thread(parse_feed, body.decode('utf-8-sig'), spec['format'])

    def lookup(self, host):
        if not self.enabled:
            return []
        now = datetime.now(timezone.utc)
        hits = []
        labels = host.split('.')
        suffixes = ['.'.join(labels[i:]) for i in range(len(labels) - 1)]
        for name, record in self.feeds.items():
            age = now - record['updated']
            if age < timedelta(minutes=-5) or age > self.max_age:
                continue
            candidates = suffixes if SOURCES[name]['subdomains'] else [host]
            if any(d in record['domains'] for d in candidates):
                hits.append(name)
        return hits

    def status(self):
        if not self.enabled:
            return '외부 위협 목록 비활성화'
        now = datetime.now(timezone.utc)
        lines = []
        for name in SOURCES:
            r = self.feeds.get(name)
            if not r:
                lines.append(f'{name}: 목록 없음 ({self.errors.get(name, "다운로드 대기")})')
                continue
            stale = now - r['updated'] > self.max_age
            lines.append(f"{name}: {len(r['domains']):,}개 / 갱신 {r['updated'].isoformat()}"
                         + (' / 만료: 자동 차단에 미사용' if stale else '')
                         + (f' / 갱신 실패: {self.errors[name]}' if name in self.errors else ''))
        return '\n'.join(lines)

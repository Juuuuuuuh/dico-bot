import hashlib
import re
import time
import unicodedata
from collections import OrderedDict, deque
from urllib.parse import urlsplit

URL = re.compile(r"(?:https?://|www\.)[^\s<>]+", re.I)
BARE_DOMAIN = re.compile(r'(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
                         r'(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?![\w.-])', re.I)


def domains(text):
    text = unicodedata.normalize('NFKC', text)
    text = ''.join(c for c in text if unicodedata.category(c) != 'Cf')
    text = re.sub(r'\[\.\]|\(dot\)', '.', text, flags=re.I)
    text = re.sub(r'\bhxxps?://', 'https://', text, flags=re.I)
    found = set()
    for value in URL.findall(text):
        try:
            value = value.rstrip('.,;!?)]}')
            host = urlsplit(value if '://' in value else 'https://' + value).hostname
            if host:
                found.add(host.rstrip('.').encode('idna').decode().lower())
        except (ValueError, UnicodeError):
            continue
    # Remove full URLs before bare-domain extraction: do not mistake userinfo
    # or a benign URL's path/query for its destination hostname.
    remainder = URL.sub(' ', text)
    found.update(match.group().lower().rstrip('.') for match in BARE_DOMAIN.finditer(remainder))
    return found


def blocked_domains(text, blocked, allowed):
    def matches(host, entries):
        return any(host == d or host.endswith('.' + d) for d in entries)
    return sorted(h for h in domains(text) if matches(h, blocked) and not matches(h, allowed))


class Detector:
    """Bounded per-account, cross-channel spam window; edits do not count twice."""
    def __init__(self, config, clock=time.monotonic, intelligence=None):
        self.config, self.clock = config, clock
        self.history = OrderedDict()
        self.intelligence = intelligence

    def inspect(self, guild_id, author_id, message_id, text, image_hashes=(), mentions=0):
        reasons = []
        bad = blocked_domains(text, self.config['blocked_domains'], self.config['allowed_domains'])
        if bad:
            reasons.append('차단 도메인: ' + ', '.join(bad))
        if self.intelligence:
            allowed = self.config['allowed_domains']
            for host in sorted(domains(text)):
                if any(host == d or host.endswith('.' + d) for d in allowed):
                    continue
                sources = self.intelligence.lookup(host)
                if sources:
                    reasons.append(f'공개 위협 목록 일치: {host} [{", ".join(sources)}]')
        if set(image_hashes) & set(self.config['blocked_image_sha256']):
            reasons.append('등록된 악성 이미지 SHA-256 일치')
        if mentions >= self.config['mention_limit']:
            reasons.append('과도한 멘션')
        now = self.clock()
        key = (guild_id, author_id)
        entries = self.history.pop(key, deque(maxlen=100))
        entries = deque((x for x in entries if now - x[0] < self.config['window_seconds']
                         and x[1] != message_id), maxlen=100)
        normalized = ' '.join(unicodedata.normalize('NFKC', text).casefold().split())
        fingerprint = hashlib.sha256((normalized + '|' + '|'.join(sorted(image_hashes))).encode()).hexdigest()
        entries.append((now, message_id, fingerprint))
        self.history[key] = entries
        while len(self.history) > 10000:
            self.history.popitem(last=False)
        if len(entries) >= self.config['message_limit']:
            reasons.append('짧은 시간 내 메시지 도배')
        if (normalized or image_hashes) and sum(x[2] == fingerprint for x in entries) >= self.config['repeat_limit']:
            reasons.append('동일 내용 또는 이미지 반복')
        return reasons

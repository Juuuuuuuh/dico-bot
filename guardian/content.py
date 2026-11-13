"""Explainable Korean/English scam promotion signals, not a trained ML model."""
import re
import unicodedata

from guardian.detection import domains

PATTERNS = {
    '보상·경품 미끼': r'무료\s*니트로|free\s*nitro|니트로\s*(?:증정|지급)|에어드[랍롭]|airdrop|giveaway|당첨|공짜|무료\s*코인',
    '지갑·비밀정보 요구': r'지갑\s*(?:연결|인증)|connect\s*(?:your\s*)?wallet|시드\s*(?:문구|구문)|seed\s*phrase|복구\s*구문|private\s*key|개인\s*키|토큰.{0,12}(?:입력|전송|제출)|(?:enter|send|paste).{0,12}token',
    '로그인·인증 유도': r'(?:로그인|인증).{0,12}(?:필수|완료|진행|하세요|해주)|verify\s*(?:your\s*)?(?:account|wallet)|scan.{0,12}qr|qr.{0,12}(?:스캔|인증)',
    '긴급·계정위협': r'지금\s*즉시|계정.{0,12}(?:정지|삭제)|서버.{0,12}추방|마감\s*임박|act\s*now|account.{0,15}(?:suspend|delet)|limited\s*time',
    '수익보장 광고': r'원금\s*보장|수익\s*보장|무조건.{0,8}수익|guaranteed\s*(?:profit|return)|risk.free\s*(?:profit|investment)',
}


def promotional_signals(text):
    cleaned = unicodedata.normalize('NFKC', text).casefold()
    cleaned = ''.join(c for c in cleaned if unicodedata.category(c) != 'Cf')
    signals = [name for name, pattern in PATTERNS.items() if re.search(pattern, cleaned, re.I)]
    linked = bool(domains(cleaned))
    # Unknown links and language alone are uncertain: only ask a human to review.
    review = linked and len(signals) >= 2
    return signals if review else []

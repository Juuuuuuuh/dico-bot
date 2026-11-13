import io
import json
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

from PIL import Image, ImageDraw, ImageFont
import zxingcpp

from guardian.content import promotional_signals
from guardian.detection import Detector, domains
from guardian.images import inspect_image, available_languages
from guardian.intelligence import Intelligence, parse_feed


class FeedTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'feeds.json'
        self.intel = Intelligence(self.path)

    async def asyncTearDown(self):
        self.tmp.cleanup()

    def populate(self):
        self.intel.feeds = {
            'discord-antiscam': {'domains': {'scam.example'}, 'updated': datetime.now(timezone.utc)},
            'phishing-army': {'domains': {'exact.example'}, 'updated': datetime.now(timezone.utc)},
        }

    def test_source_matching_and_domain_boundaries(self):
        self.populate()
        self.assertEqual(self.intel.lookup('sub.scam.example'), ['discord-antiscam'])
        self.assertEqual(self.intel.lookup('scam.example.good.test'), [])
        self.assertEqual(self.intel.lookup('sub.exact.example'), [])
        self.assertEqual(self.intel.lookup('exact.example'), ['phishing-army'])

    def test_expired_intelligence_not_used_for_punishment(self):
        self.populate()
        self.intel.feeds['discord-antiscam']['updated'] -= timedelta(days=8)
        self.assertEqual(self.intel.lookup('scam.example'), [])
        self.assertIn('만료', self.intel.status())

    async def test_failed_refresh_keeps_previous_good_snapshot(self):
        self.populate()
        with patch.object(self.intel, '_fetch', new=AsyncMock(side_effect=RuntimeError('network down'))):
            await self.intel.refresh()
        self.assertEqual(self.intel.lookup('scam.example'), ['discord-antiscam'])
        restored = Intelligence(self.path)
        self.assertEqual(restored.lookup('scam.example'), ['discord-antiscam'])
        self.assertIn('갱신 실패', self.intel.status())

    async def test_successful_refresh_replaces_removed_entries(self):
        self.populate()
        with patch.object(self.intel, '_fetch', new=AsyncMock(return_value={'new.example'})):
            await self.intel.refresh()
        self.assertEqual(self.intel.lookup('scam.example'), [])
        self.assertEqual(set(self.intel.lookup('new.example')), {'discord-antiscam', 'phishing-army'})

    def test_parsers_reject_empty_and_strip_comments_platform_roots(self):
        entries = [f'bad-{i}.example' for i in range(110)]
        body = '\n'.join(['# source header', 'https://not-a-domain.example/path', 'discord.com', *entries])
        self.assertEqual(parse_feed(body, 'text'), set(entries))
        self.assertEqual(parse_feed(json.dumps(entries), 'json'), set(entries))
        for value in ('[]', '{}', '["only.example"]'):
            with self.assertRaises(ValueError):
                parse_feed(value, 'json')

    def test_corrupt_cache_does_not_prevent_start(self):
        self.path.write_text('[]')
        self.assertEqual(Intelligence(self.path).lookup('scam.example'), [])

    def test_detector_feed_evidence_and_allowlist(self):
        self.populate()
        config = {'blocked_domains': [], 'allowed_domains': [], 'blocked_image_sha256': [],
                  'mention_limit': 8, 'window_seconds': 10, 'message_limit': 6, 'repeat_limit': 3}
        detector = Detector(config, intelligence=self.intel)
        self.assertIn('discord-antiscam', ';'.join(detector.inspect(1, 1, 1, 'https://scam.example')))
        config['allowed_domains'] = ['scam.example']
        self.assertEqual(detector.inspect(1, 1, 2, 'https://scam.example'), [])


class ContentTests(unittest.TestCase):
    def test_bare_and_defanged_links_and_url_userinfo(self):
        self.assertIn('scam.example', domains('visit scam.example please'))
        self.assertIn('scam.example', domains('hxxps://scam[.]example/a'))
        self.assertIn('scam.example', domains('(https://scam.example)'))
        self.assertEqual(domains('https://scam.example@good.example/path/scam.example'), {'good.example'})
        self.assertEqual(domains('mail user@scam.example'), set())

    def test_promotion_needs_multiple_signals_and_link(self):
        self.assertEqual(promotional_signals('코인에 대해 공부해요'), [])
        self.assertEqual(promotional_signals('free nitro'), [])
        self.assertEqual(promotional_signals('https://example.com free nitro'), [])
        self.assertGreaterEqual(len(promotional_signals(
            'https://example.com free nitro connect your wallet act now')), 2)
        self.assertGreaterEqual(len(promotional_signals(
            'https://example.com 에어드랍 지갑 연결 지금 즉시')), 2)


class ImageTests(unittest.TestCase):
    def test_real_qr_decode_without_visiting_destination(self):
        qr = zxingcpp.write_barcode(zxingcpp.BarcodeFormat.QRCode,
                                   'https://scam.example/test', width=300, height=300)
        image = Image.frombytes('L', (qr.shape[1], qr.shape[0]), bytes(qr))
        output = io.BytesIO()
        image.save(output, format='PNG')
        with patch('guardian.images.available_languages', return_value=()):
            result = inspect_image(output.getvalue())
        self.assertIn('https://scam.example/test', result.qr)
        self.assertIn('OCR 미검사', result.warning)

    @unittest.skipUnless('eng' in available_languages(), 'Tesseract English is not installed')
    def test_real_ocr_extracts_domain_from_image(self):
        image = Image.new('RGB', (1000, 160), 'white')
        ImageDraw.Draw(image).text((20, 40), 'https://scam.example',
                                   fill='black', font=ImageFont.load_default(size=48))
        output = io.BytesIO()
        image.save(output, format='PNG')
        result = inspect_image(output.getvalue(), 'eng')
        self.assertIn('scam.example', domains(result.text))

    def test_invalid_and_oversized_images_are_not_processed(self):
        self.assertTrue(inspect_image(b'not an image').warning)
        image = Image.new('RGB', (3000, 3000), 'white')
        output = io.BytesIO()
        image.save(output, format='PNG')
        self.assertIn('픽셀 제한', inspect_image(output.getvalue()).warning)

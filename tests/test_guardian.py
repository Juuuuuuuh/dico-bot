import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import discord
from guardian.bot import Guardian, install_commands, load_config
from guardian.detection import Detector, blocked_domains
from guardian.storage import Store
from guardian.images import ImageResult
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def config():
    c = json.loads((ROOT / 'config.example.json').read_text())
    c.update(guild_id=1, log_channel_id=2, blocked_domains=['scam.example'])
    return c


class DetectionTests(unittest.TestCase):
    def test_domain_boundary_allowlist_and_unicode(self):
        self.assertEqual(blocked_domains('https://x.scam.example/a', ['scam.example'], []), ['x.scam.example'])
        self.assertEqual(blocked_domains('https://scam.example.good.test', ['scam.example'], []), [])
        self.assertEqual(blocked_domains('https://safe.scam.example', ['scam.example'], ['safe.scam.example']), [])
        self.assertEqual(blocked_domains('https://sc\u200bam.example', ['scam.example'], []), ['scam.example'])
        self.assertEqual(blocked_domains('https://scam.example@good.example', ['scam.example'], []), [])

    def test_repeat_cross_channel_edit_and_expiry(self):
        now = [0]
        d = Detector(config(), lambda: now[0])
        for _ in range(5):
            self.assertEqual(d.inspect(1, 1, 1, 'same'), [])
        self.assertEqual(d.inspect(1, 1, 2, 'same'), [])
        self.assertIn('동일 내용 또는 이미지 반복', d.inspect(1, 1, 3, 'same'))
        self.assertEqual(d.inspect(1, 2, 4, 'same'), [])
        self.assertEqual(d.inspect(2, 1, 4, 'same'), [])
        now[0] = 11
        self.assertEqual(d.inspect(1, 1, 5, 'same'), [])

    def test_image_and_burst(self):
        c = config()
        c['blocked_image_sha256'] = ['a' * 64]
        d = Detector(c)
        self.assertIn('등록된 악성 이미지 SHA-256 일치', d.inspect(1, 1, 1, '', ['a' * 64]))
        for i in range(5):
            result = d.inspect(1, 2, i, str(i))
            self.assertNotIn('짧은 시간 내 메시지 도배', result)
        self.assertIn('짧은 시간 내 메시지 도배', d.inspect(1, 2, 6, 'six'))

    def test_config_defaults_and_validation(self):
        self.assertEqual(config()['timeout_hours'], 24)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'config.json'
            c = config()
            path.write_text(json.dumps(c))
            self.assertEqual(load_config(path)['timeout_hours'], 24)
            c['timeout_hours'] = 1000
            path.write_text(json.dumps(c))
            with self.assertRaises(ValueError):
                load_config(path)

    def test_storage_scoping_persistence_and_review(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'db.sqlite'
            store = Store(path)
            cid = store.add(1, 3, 4, 5, 'reason', 'evidence')
            store.action(cid, 'done')
            store.review(cid, 9, 'confirmed')
            store.db.close()
            reopened = Store(path)
            self.assertIsNone(reopened.get(2, cid))
            self.assertEqual(reopened.get(1, cid)['review'], 'confirmed')
            reopened.db.close()


class ModerationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / 'db.sqlite')
        self.bot = Guardian(config(), self.store)
        self.bot._connection.user = SimpleNamespace(id=99)
        self.bot.audit = AsyncMock()
        self.author = MagicMock(spec=discord.Member)
        self.author.id = 3
        self.author.bot = False
        self.author.roles = []
        self.author.guild_permissions = SimpleNamespace(administrator=False)
        self.author.is_timed_out.return_value = False
        self.author.timeout = AsyncMock()
        self.message = SimpleNamespace(guild=SimpleNamespace(id=1, owner_id=100), author=self.author,
            channel=SimpleNamespace(id=4), id=5, webhook_id=None, content='https://scam.example',
            embeds=[], attachments=[], mentions=[], role_mentions=[], mention_everyone=False,
            delete=AsyncMock())

    async def asyncTearDown(self):
        await self.bot.close()
        self.store.db.close()
        self.tmp.cleanup()

    async def test_dry_run_never_deletes_or_timeouts(self):
        await self.bot.inspect_message(self.message)
        self.message.delete.assert_not_awaited()
        self.author.timeout.assert_not_awaited()
        self.assertEqual(len(self.store.recent(1)), 1)

    async def test_live_deletes_and_timeouts_for_one_day(self):
        self.bot.config['dry_run'] = False
        await self.bot.inspect_message(self.message)
        self.message.delete.assert_awaited_once()
        self.assertEqual(self.author.timeout.await_args.args[0].total_seconds(), 86400)

    async def test_bots_webhooks_and_admins_not_timed_out(self):
        self.bot.config['dry_run'] = False
        self.author.bot = True
        await self.bot.inspect_message(self.message)
        self.author.timeout.assert_not_awaited()
        self.author.bot = False
        self.message.webhook_id = 123
        await self.bot.inspect_message(self.message)
        self.author.timeout.assert_not_awaited()
        self.message.webhook_id = None
        self.author.guild_permissions.administrator = True
        await self.bot.inspect_message(self.message)
        self.author.timeout.assert_not_awaited()

    async def test_existing_timeout_not_extended(self):
        self.bot.config['dry_run'] = False
        self.author.is_timed_out.return_value = True
        await self.bot.inspect_message(self.message)
        self.author.timeout.assert_not_awaited()

    async def test_suspicious_promotion_only_requests_human_review(self):
        self.bot.config['dry_run'] = False
        self.message.content = 'https://example.com free nitro connect your wallet act now'
        await self.bot.inspect_message(self.message)
        self.message.delete.assert_not_awaited()
        self.author.timeout.assert_not_awaited()
        self.assertIn('검토 알림만', self.store.recent(1)[0]['action'])

    async def test_image_extracted_link_reaches_live_enforcement(self):
        self.bot.config['dry_run'] = False
        self.message.content = ''
        self.message.attachments = [SimpleNamespace(content_type='image/png', size=10,
            filename='advert.png', read=AsyncMock(return_value=b'fixture'))]
        with patch('guardian.bot.inspect_image', return_value=ImageResult(qr=('https://scam.example',))):
            await self.bot.inspect_message(self.message)
        self.message.delete.assert_awaited_once()
        self.assertEqual(self.author.timeout.await_args.args[0].total_seconds(), 86400)
        self.assertIn('OCR / QR', self.store.recent(1)[0]['evidence'])

    async def test_commands_register_with_checks(self):
        install_commands(self.bot)
        for name in ('case', 'cases', 'review', 'protection'):
            command = self.bot.tree.get_command(name)
            self.assertTrue(command.checks)
            self.assertTrue(command.default_permissions.moderate_members)


if __name__ == '__main__':
    unittest.main()

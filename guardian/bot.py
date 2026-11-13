import asyncio
import hashlib
import io
import json
import logging
import os
from datetime import timedelta
from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv

from guardian.detection import Detector
from guardian.storage import Store

log = logging.getLogger('guardian')
MAX_IMAGE_BYTES = 5 * 1024 * 1024


def load_config(path):
    c = json.loads(Path(path).read_text())
    for name in ('guild_id', 'log_channel_id'):
        if type(c[name]) is not int or c[name] <= 0:
            raise ValueError(f'{name}: 실제 Discord ID를 입력하세요')
    if type(c['timeout_hours']) is not int or not 1 <= c['timeout_hours'] <= 672:
        raise ValueError('timeout_hours must be 1..672')
    for name in ('window_seconds', 'message_limit', 'repeat_limit', 'mention_limit', 'retention_days'):
        if type(c[name]) is not int or c[name] <= 0:
            raise ValueError(f'{name}: positive integer required')
    for name in ('dry_run', 'kick_blocked_bots'):
        if type(c[name]) is not bool:
            raise ValueError(f'{name}: boolean required')
    for name in ('blocked_bot_ids', 'trusted_bot_ids', 'exempt_role_ids'):
        if not isinstance(c[name], list) or any(type(i) is not int or i <= 0 for i in c[name]):
            raise ValueError(f'{name}: positive integer IDs required')
    for name in ('blocked_domains', 'allowed_domains'):
        if not isinstance(c[name], list):
            raise ValueError(f'{name}: list required')
        c[name] = [d.rstrip('.').encode('idna').decode().lower() for d in c[name]]
        if any(not d or '/' in d or ':' in d or ' ' in d for d in c[name]):
            raise ValueError(f'{name}: 도메인만 입력하세요 (URL 제외)')
    if not isinstance(c['blocked_image_sha256'], list) or any(
        not isinstance(h, str) or len(h) != 64 or any(x not in '0123456789abcdef' for x in h)
        for h in c['blocked_image_sha256']
    ):
        raise ValueError('blocked_image_sha256: lowercase SHA-256 required')
    return c


class Guardian(commands.Bot):
    def __init__(self, config, store):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        super().__init__(command_prefix=commands.when_mentioned, intents=intents,
                         allowed_mentions=discord.AllowedMentions.none(), max_messages=1000)
        self.config, self.store = config, store
        self.detector = Detector(config)
        self.scans = asyncio.Semaphore(4)
        self.actions = asyncio.Lock()

    async def setup_hook(self):
        guild = discord.Object(id=self.config['guild_id'])
        self.tree.copy_global_to(guild=guild)
        await self.tree.sync(guild=guild)
        self.cleanup.start()

    @tasks.loop(hours=24)
    async def cleanup(self):
        self.store.prune(self.config['retention_days'])

    async def audit(self, case_id):
        row = self.store.get(self.config['guild_id'], case_id)
        channel = self.get_channel(self.config['log_channel_id'])
        if channel is None:
            log.error('Case %s: log channel unavailable', case_id)
            return
        embed = discord.Embed(title=f'검토 사건 #{case_id}', color=discord.Color.orange())
        embed.description = f"계정 ID: {row['user_id']}\n채널 ID: {row['channel_id']}\n메시지 ID: {row['message_id']}"
        embed.add_field(name='탐지', value=discord.utils.escape_markdown(row['reason'])[:1000], inline=False)
        embed.add_field(name='조치', value=row['action'][:1000], inline=False)
        if row['reviewed_by']:
            embed.add_field(name='운영자 검토', value=discord.utils.escape_markdown(
                f"{row['reviewed_by']}: {row['review']}")[:1000], inline=False)
        embed.set_footer(text=f'/case case_id:{case_id} · /review 로 검토')
        try:
            await channel.send(embed=embed)
        except discord.HTTPException as exc:
            log.error('Case %s: audit delivery failed (%s)', case_id, type(exc).__name__)

    async def on_ready(self):
        guild = self.get_guild(self.config['guild_id'])
        channel = self.get_channel(self.config['log_channel_id'])
        if guild is None or channel is None or getattr(channel, 'guild', None) != guild:
            log.error('Guild/log channel configuration invalid; stopping')
            await self.close()
            return
        permissions = channel.permissions_for(guild.me)
        if not (permissions.view_channel and permissions.send_messages and permissions.embed_links):
            log.error('Missing log channel permissions; stopping')
            await self.close()
            return
        log.info('Ready. guild=%s dry_run=%s timeout=%sh', guild.id,
                 self.config['dry_run'], self.config['timeout_hours'])

    async def on_member_join(self, member):
        if member.guild.id != self.config['guild_id'] or not member.bot:
            return
        if member.id in self.config['trusted_bot_ids']:
            return
        case_id = self.store.add(member.guild.id, member.id, 0, 0, '새 봇 입장 — 운영자 확인 필요', '')
        action = '알림만 전송 (봇은 타임아웃 불가)'
        if member.id in self.config['blocked_bot_ids'] and self.config['kick_blocked_bots']:
            action = '모의 모드: 차단 봇 추방 예정'
            if not self.config['dry_run']:
                try:
                    await member.kick(reason=f'Guardian case #{case_id}: blocked bot ID')
                    action = '차단 봇 추방 완료'
                except discord.HTTPException as exc:
                    action = f'추방 실패: {type(exc).__name__} (권한·역할 순서 확인)'
        self.store.action(case_id, action)
        await self.audit(case_id)

    async def on_message(self, message):
        await self.inspect_message(message)

    async def on_raw_message_edit(self, payload):
        if payload.guild_id != self.config['guild_id']:
            return
        channel = self.get_channel(payload.channel_id)
        if channel:
            try:
                await self.inspect_message(await channel.fetch_message(payload.message_id))
            except discord.HTTPException:
                log.warning('Edited message could not be fetched: %s', payload.message_id)

    async def inspect_message(self, message):
        if not message.guild or message.guild.id != self.config['guild_id']:
            return
        if message.author.id == self.user.id or message.channel.id == self.config['log_channel_id']:
            return
        # Webhook authors are not Members and are never treated as trusted bots.
        if not message.webhook_id:
            if message.author.bot and message.author.id in self.config['trusted_bot_ids']:
                return
            if any(r.id in self.config['exempt_role_ids'] for r in getattr(message.author, 'roles', [])):
                return
        async with self.scans:
            hashes, skipped = [], 0
            for attachment in message.attachments[:4]:
                if not (attachment.content_type or '').startswith('image/'):
                    continue
                if attachment.size > MAX_IMAGE_BYTES:
                    skipped += 1
                    continue
                try:
                    data = await asyncio.wait_for(attachment.read(), timeout=8)
                    hashes.append(hashlib.sha256(data).hexdigest())
                except (discord.HTTPException, asyncio.TimeoutError):
                    skipped += 1
            text = message.content + '\n' + '\n'.join(
                json.dumps(e.to_dict(), ensure_ascii=False) for e in message.embeds)
            # Serialize decisions/actions to avoid duplicate 24-hour extensions.
            async with self.actions:
                reasons = self.detector.inspect(message.guild.id, message.author.id,
                    message.id, text, hashes,
                    len(message.mentions) + len(message.role_mentions) + (8 if message.mention_everyone else 0))
                if not reasons:
                    return
                evidence = (message.content + '\nImage SHA256: ' + ', '.join(hashes)
                            + f'\nUnscanned images: {skipped}'
                            + '\nAttachment names: ' + ', '.join(a.filename for a in message.attachments))
                case_id = self.store.add(message.guild.id, message.author.id, message.channel.id,
                                         message.id, '; '.join(reasons), evidence)
                result = []
                if self.config['dry_run']:
                    result.append('모의 모드: 삭제·제재 미실행')
                else:
                    try:
                        await message.delete()
                        result.append('메시지 삭제 완료')
                    except discord.HTTPException as exc:
                        result.append(f'삭제 실패: {type(exc).__name__}')
                    member = message.author
                    if message.webhook_id or member.bot or not isinstance(member, discord.Member):
                        result.append('봇/웹훅: 타임아웃 불가, 운영자 조치 필요')
                    elif member.id == message.guild.owner_id or member.guild_permissions.administrator:
                        result.append('소유자/관리자: 타임아웃 불가')
                    elif member.is_timed_out():
                        result.append('기존 타임아웃 유지')
                    else:
                        try:
                            await member.timeout(timedelta(hours=self.config['timeout_hours']),
                                                 reason=f'Guardian case #{case_id}')
                            result.append(f"{self.config['timeout_hours']}시간 타임아웃 완료")
                        except discord.HTTPException as exc:
                            result.append(f'타임아웃 실패: {type(exc).__name__} (권한·역할 순서 확인)')
                self.store.action(case_id, '; '.join(result))
                await self.audit(case_id)


def install_commands(bot):
    @bot.tree.command(name='cases', description='최근 검토 사건 10개')
    @app_commands.guild_only()
    @app_commands.default_permissions(moderate_members=True)
    @app_commands.checks.has_permissions(moderate_members=True)
    async def cases(interaction: discord.Interaction):
        rows = bot.store.recent(interaction.guild_id)
        await interaction.response.send_message('\n'.join(
            f"#{r['id']} 계정 {r['user_id']} — {r['action']}" for r in rows)[:1900] or '내역 없음', ephemeral=True)

    @bot.tree.command(name='case', description='사건 근거 보기 (운영자 전용 비공개 응답)')
    @app_commands.guild_only()
    @app_commands.default_permissions(moderate_members=True)
    @app_commands.checks.has_permissions(moderate_members=True)
    async def case(interaction: discord.Interaction, case_id: int):
        row = bot.store.get(interaction.guild_id, case_id)
        if row is None:
            await interaction.response.send_message('사건 없음', ephemeral=True)
            return
        # Text file keeps hostile links/content out of rendered messages.
        body = '\n'.join(f'{k}: {row[k]}' for k in row.keys())
        await interaction.response.send_message(f'사건 #{case_id}', ephemeral=True,
            file=discord.File(io.BytesIO(body.encode()), filename=f'case-{case_id}.txt'))

    @bot.tree.command(name='review', description='확인 처리 또는 현재 타임아웃 해제')
    @app_commands.guild_only()
    @app_commands.default_permissions(moderate_members=True)
    @app_commands.checks.has_permissions(moderate_members=True)
    @app_commands.choices(action=[app_commands.Choice(name='확인 완료', value='confirm'),
                                 app_commands.Choice(name='현재 타임아웃 해제', value='release')])
    async def review(interaction: discord.Interaction, case_id: int,
                     action: app_commands.Choice[str], note: str = ''):
        row = bot.store.get(interaction.guild_id, case_id)
        if row is None:
            await interaction.response.send_message('사건 없음', ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        if action.value == 'release':
            if bot.config['dry_run']:
                await interaction.followup.send('모의 모드에서는 타임아웃을 변경하지 않습니다.', ephemeral=True)
                return
            member = await interaction.guild.fetch_member(int(row['user_id']))
            if member.top_role >= interaction.user.top_role and interaction.user.id != interaction.guild.owner_id:
                await interaction.followup.send('자신과 같거나 높은 역할의 계정은 해제할 수 없습니다.', ephemeral=True)
                return
            await member.timeout(None, reason=f'Guardian review #{case_id} by {interaction.user.id}')
        bot.store.review(case_id, interaction.user.id, f'{action.value}: {note[:500]}')
        await bot.audit(case_id)
        await interaction.followup.send('검토 기록 저장 완료. 삭제한 메시지는 복원되지 않습니다.', ephemeral=True)

    @bot.tree.error
    async def command_error(interaction, error):
        log.warning('Command failed: %s', type(error).__name__)
        message = '명령 처리 실패: 운영 권한, 대상 계정 및 봇 역할 순서를 확인하세요.'
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)


def main():
    load_dotenv()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    config = load_config(os.getenv('CONFIG_PATH', 'config.json'))
    token = os.environ.get('DISCORD_TOKEN')
    if not token or token == 'replace_on_your_server_only':
        raise SystemExit('DISCORD_TOKEN을 서버 .env 파일에 설정하세요')
    bot = Guardian(config, Store(os.getenv('DATABASE_PATH', 'data/guardian.db')))
    install_commands(bot)
    bot.run(token, log_handler=None)


if __name__ == '__main__':
    main()

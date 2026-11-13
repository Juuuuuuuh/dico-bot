# Discord Guardian — 디스코드 스팸·스캠 관리 봇

Python 3.12 / discord.py 기반의 실제 실행 가능한 봇입니다. 개인 리눅스 서버에서 systemd로 상시 운영합니다. 탐지된 메시지를 삭제하고 일반 계정을 **24시간 타임아웃**한 뒤, 운영자가 사건 기록을 검토합니다.

## 구현 기능

- 설정된 악성 도메인과 하위 도메인 탐지: 메시지 본문·임베드·수정 메시지 검사
- 10초 내 6개 메시지 / 동일 내용 또는 동일 이미지 3회 / 과도한 멘션 탐지
- 이미지 SHA-256 차단 목록 대조 (최대 앞 4개 첨부, 각 5MiB 이하)
- 계정 단위로 채널을 넘나드는 도배 집계, 서버 간 분리
- 메시지 삭제 후 일반 계정 **24시간 타임아웃**, 기존 타임아웃 연장 방지
- 새 봇 입장 알림, 등록된 악성 봇 ID 선택적 자동 추방
- 봇·웹훅 메시지도 검사. Discord 제약으로 봇·웹훅·서버 소유자·관리자는 타임아웃 불가: 삭제 후 운영자에게 알림
- SQLite 사건 보존, 기본 30일 후 정리, 운영자 전용 `/cases`, `/case`, `/review`
- 기본 모의 실행 (`dry_run: true`): 기록만 남기며 삭제·타임아웃·추방·해제를 실행하지 않음
- 재부팅 자동 시작 / 장애 자동 재시작 systemd 서비스, GitHub Actions 테스트

## 탐지 범위와 한계

이 버전은 규칙 기반입니다. 차단 도메인·이미지 목록은 기본적으로 비어 있으므로 운영자가 등록해야 합니다. 모든 코인 문구나 모든 이미지를 악성으로 판정하지 않습니다. 이미지 속 글자 OCR, QR 해석, 이미지 의미 분류, 외부 평판 조회, 단축 URL 리디렉션 추적은 구현하지 않았습니다. 이미지의 크기 변경·재압축은 다른 해시가 되므로 기존 이미지 차단을 우회할 수 있습니다. 이미지 다운로드 실패·초과 크기는 악성으로 단정하지 않습니다. URL 없이 도메인만 적은 문구도 현재 차단 도메인 검사의 대상이 아닙니다.

사건에는 원문 일부·메시지/계정/채널 ID·이미지 해시·첨부 파일명·조치 결과가 남습니다. **이미지 원본은 저장하지 않으며**, 삭제 후 이미지를 다시 보여주지는 못합니다. 도배 집계는 메모리에 있어 프로세스 재시작 시 초기화됩니다. 이미 존재하던 봇은 입장 알림이 발생하지 않지만 이후 메시지는 검사합니다. 신뢰 봇·예외 역할·로그 채널은 검사에서 제외됩니다. 봇이 장악되면 봇으로 토큰 탈취 자체를 예방할 수는 없으며, 메시지와 서버 행동을 제한하는 도구입니다.

## 1. 디스코드 앱 준비

1. [Discord Developer Portal](https://discord.com/developers/applications)에서 Application과 Bot을 만듭니다.
2. Bot 페이지에서 **Server Members Intent**, **Message Content Intent**를 켭니다. 필요한 경우 Discord 승인을 받습니다.
3. OAuth2 URL Generator에서 `bot`, `applications.commands`를 선택합니다.
4. 권한: View Channels, Send Messages, Embed Links, Attach Files, Read Message History, Manage Messages, Moderate Members. 악성 봇 자동 추방을 쓸 때만 Kick Members도 추가합니다. Administrator 권한은 필요하지 않습니다.
5. 봇을 서버에 초대하고 봇 역할을 관리 대상 역할보다 위로 이동합니다.
6. Discord 개발자 모드를 켜 서버 ID와 **운영자만 볼 수 있는 로그 채널 ID**를 복사합니다. 해당 채널은 봇이 볼 수 있고 쓰기 가능한 일반 텍스트 채널이어야 합니다.

## 2. 리눅스 설치 (Ubuntu/Debian, Python 3.12)

아래 명령은 사용자 서버에서 실행합니다. Python 3.12를 제공하지 않는 배포판에서는 먼저 해당 버전을 준비하세요.

```bash
sudo apt update
sudo apt install -y git python3.12 python3.12-venv
sudo useradd --system --home /opt/discord-guardian --shell /usr/sbin/nologin discord-guardian
sudo git clone https://github.com/Juuuuuuuh/dico-bot.git /opt/discord-guardian
cd /opt/discord-guardian
sudo python3.12 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
sudo cp .env.example .env
sudo cp config.example.json config.json
sudo mkdir -p data
sudo chown -R root:discord-guardian /opt/discord-guardian
sudo chmod 750 /opt/discord-guardian
sudo chown discord-guardian:discord-guardian data
sudo chmod 700 data
sudo chmod 640 .env config.json
sudoedit .env
sudoedit config.json
```

`.env`의 `DISCORD_TOKEN`에 실제 봇 토큰을 입력합니다. 토큰은 채팅·GitHub·스크린샷에 공유하지 마세요. 나머지 기본 경로는 그대로 사용할 수 있습니다.

`config.json`의 `guild_id`, `log_channel_id`를 실제 숫자 ID로 바꿉니다. 한 프로세스가 한 서버를 보호합니다. 여러 서버에는 별도 프로세스와 DB를 사용하세요.

```json
{
  "guild_id": 123456789012345678,
  "log_channel_id": 234567890123456789,
  "timeout_hours": 24,
  "dry_run": true,
  "blocked_domains": ["scam.example"],
  "allowed_domains": [],
  "blocked_image_sha256": [],
  "blocked_bot_ids": [],
  "kick_blocked_bots": false,
  "trusted_bot_ids": [],
  "exempt_role_ids": [],
  "window_seconds": 10,
  "message_limit": 6,
  "repeat_limit": 3,
  "mention_limit": 8,
  "retention_days": 30
}
```

`scam.example`은 동작 확인용 예약 도메인입니다. 실사용 시 실제 차단할 도메인을 추가하세요. 도메인에는 `https://`나 경로를 넣지 않습니다. 허용 목록은 해당 도메인 및 하위 도메인의 **도메인 탐지만** 제외하며 도배 탐지는 계속합니다. 봇 ID·역할 ID는 정수 배열입니다. 이미지 해시는 신뢰할 수 있는 파일에 `sha256sum 파일명`을 실행해 얻은 소문자 64자리 값입니다. 설정 수정 후 서비스를 재시작합니다.

## 3. 24시간 서비스 등록

```bash
sudo cp deploy/discord-guardian.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now discord-guardian
sudo systemctl status discord-guardian
sudo journalctl -u discord-guardian -f
```

로그에 `Ready`가 표시되면 테스트 서버의 일반 채널에서 `https://scam.example/test`를 보내세요. 처음에는 모의 모드이므로 삭제·제재 없이 로그에 사건이 생깁니다. `/cases`와 `/case`로 검토하고 오탐을 확인한 뒤 `config.json`을 `"dry_run": false`로 바꾸고 재시작하세요.

```bash
sudo systemctl restart discord-guardian
```

관리자·서버 소유자는 타임아웃되지 않으므로 실제 24시간 제재 검증에는 일반 테스트 계정과 별도의 테스트 서버를 사용하세요. 모든 채널의 권한 덮어쓰기도 확인해야 합니다. 봇이 오프라인일 때 메시지는 검사하지 못합니다. Discord 장애·서버/네트워크 중단 중에도 작동을 보장할 수는 없으며 discord.py 재연결과 systemd 재시작으로 복구합니다. 인바운드 포트는 필요 없으며 Discord HTTPS/WebSocket 아웃바운드 연결이 필요합니다.

## 운영자 명령

| 명령 | 기능 |
| --- | --- |
| `/cases` | 최근 사건 10개 (비공개 응답) |
| `/case case_id:1` | 근거·처리·검토 기록 텍스트 파일 (비공개 응답) |
| `/review case_id:1 action:확인 완료 note:...` | 검토 결과 기록 |
| `/review case_id:1 action:현재 타임아웃 해제 note:오탐` | 해당 계정의 **현재 타임아웃** 해제 및 검토 기록 |

명령 실행 시 Moderate Members 권한을 다시 검사합니다. 해제는 해당 사건 이후 다른 운영자가 적용한 타임아웃도 해제할 수 있으므로 현재 상황을 확인하고 실행하세요. 삭제한 메시지는 복원되지 않습니다. 봇/웹훅 차단, 영구 밴 등은 Discord 관리 화면에서 확인 후 처리하세요. 로그 채널에는 링크 원문을 게시하지 않으며 멘션은 비활성화했습니다. 사건 원문은 로컬 DB에 보관하므로 서버 운영자만 접근하도록 유지하세요.

## 유지보수

```bash
# 업데이트 전 백업: DB의 WAL을 함께 다루기 위해 서비스를 먼저 중지
sudo systemctl stop discord-guardian
sudo cp -a data data-backup
sudo git pull --ff-only
sudo .venv/bin/pip install -r requirements.txt
sudo systemctl start discord-guardian

# 테스트
.venv/bin/python -m unittest discover -s tests -v
```

상시 운영 서버에서는 디스크 사용량과 서비스 상태를 모니터링하세요. 사건 정리는 시작 시와 24시간마다 수행하며 SQLite 파일 크기를 즉시 줄이는 작업은 수행하지 않습니다. 백업에도 개인정보가 포함됩니다. 테스트는 Discord API 모의를 사용하며 실제 Discord 접속/운영 서버 설치 검증은 별도입니다.

개발 과정과 확인된 제한은 [개발 기록](docs/DEVELOPMENT.md), 운영 전 점검은 [운영 검증](docs/OPERATIONS.md)을 참고하세요.

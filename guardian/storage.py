import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY, guild_id TEXT, user_id TEXT, channel_id TEXT,
            message_id TEXT, created TEXT, reason TEXT, evidence TEXT,
            action TEXT, reviewed_by TEXT, review TEXT)''')
        self.db.commit()

    def add(self, guild, user, channel, message, reason, evidence):
        with self.db:
            c = self.db.execute('''INSERT INTO cases
                (guild_id,user_id,channel_id,message_id,created,reason,evidence,action)
                VALUES (?,?,?,?,?,?,?,?)''',
                (str(guild), str(user), str(channel), str(message), datetime.now(timezone.utc).isoformat(),
                 reason, evidence[:6000], '처리 중'))
        return c.lastrowid

    def action(self, case_id, value):
        with self.db:
            self.db.execute('UPDATE cases SET action=? WHERE id=?', (value, case_id))

    def get(self, guild, case_id):
        return self.db.execute('SELECT * FROM cases WHERE guild_id=? AND id=?', (str(guild), case_id)).fetchone()

    def recent(self, guild):
        return self.db.execute('SELECT * FROM cases WHERE guild_id=? ORDER BY id DESC LIMIT 10', (str(guild),)).fetchall()

    def review(self, case_id, moderator, note):
        with self.db:
            self.db.execute('UPDATE cases SET reviewed_by=?,review=? WHERE id=?', (str(moderator), note, case_id))

    def prune(self, days):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self.db:
            self.db.execute('DELETE FROM cases WHERE created < ?', (cutoff,))

"""
unbanner.py — Background loop that releases bans when their duration expires.

Runs in its own thread, checks every 30 seconds.
"""

import time
import threading


class Unbanner:
    def __init__(self, blocker, notifier):
        self.blocker = blocker
        self.notifier = notifier
        self.thread = None
        self.running = False

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            try:
                self._check_expirations()
            except Exception as e:
                print(f"[unbanner] error: {e}")
            time.sleep(30)

    def _check_expirations(self):
        now = time.time()
        # Snapshot the bans so we don't mutate while iterating.
        bans = self.blocker.list_bans()
        for ban in bans:
            if ban['duration'] < 0:
                continue   # permanent
            if ban['remaining'] <= 0:
                ip = ban['ip']
                if self.blocker.unban(ip):
                    self.notifier.send_unban(ip, ban['duration'])

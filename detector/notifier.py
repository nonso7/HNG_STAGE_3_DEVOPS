"""
notifier.py — Sends alerts to Slack via Incoming Webhook.

Posts are fire-and-forget on a background thread to avoid blocking detection.
"""

import threading
import requests
from datetime import datetime


class Notifier:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def _post(self, text):
        """Background-thread-friendly POST that swallows errors."""
        def _do():
            try:
                requests.post(self.webhook_url, json={'text': text}, timeout=5)
            except Exception as e:
                print(f"[notifier] Slack post failed: {e}")
        threading.Thread(target=_do, daemon=True).start()

    def send_ban(self, ip, reason, rate, baseline, duration):
        ts = datetime.utcnow().isoformat() + 'Z'
        dur = f"{duration}s" if duration > 0 else "permanent"
        text = (
            f":no_entry: *IP BANNED* `{ip}`\n"
            f"• Condition: {reason}\n"
            f"• Current rate: {rate:.1f} req/s\n"
            f"• Baseline: {baseline:.1f} req/s\n"
            f"• Ban duration: {dur}\n"
            f"• Time: {ts}"
        )
        self._post(text)

    def send_unban(self, ip, duration_served):
        ts = datetime.utcnow().isoformat() + 'Z'
        text = (
            f":white_check_mark: *IP UNBANNED* `{ip}`\n"
            f"• Duration served: {duration_served}s\n"
            f"• Time: {ts}"
        )
        self._post(text)

    def send_global_alert(self, reason, rate, baseline):
        ts = datetime.utcnow().isoformat() + 'Z'
        text = (
            f":rotating_light: *GLOBAL ANOMALY*\n"
            f"• Condition: {reason}\n"
            f"• Current rate: {rate:.1f} req/s\n"
            f"• Baseline: {baseline:.1f} req/s\n"
            f"• Time: {ts}"
        )
        self._post(text)

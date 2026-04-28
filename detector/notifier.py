import logging

import requests

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


class Notifier:
    """Sends alerts to a webhook (Slack/Discord-compatible JSON payload)."""

    def __init__(self, cfg: dict):
        self.enabled = cfg.get("enabled", False)
        self.webhook_url = cfg.get("webhook_url", "")
        self.min_severity = cfg.get("min_severity", "warning")
        self.log = logging.getLogger("notifier")

    def send(self, severity: str, message: str) -> bool:
        if not self.enabled:
            self.log.info("[%s] %s", severity, message)
            return False
        if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(self.min_severity, 0):
            return False
        if not self.webhook_url:
            self.log.warning("notifier enabled but no webhook_url configured")
            return False
        try:
            requests.post(
                self.webhook_url,
                json={"text": f"[{severity.upper()}] {message}"},
                timeout=5,
            )
            return True
        except requests.RequestException:
            self.log.exception("failed to deliver notification")
            return False

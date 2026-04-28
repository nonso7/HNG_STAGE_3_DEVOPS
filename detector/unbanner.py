import logging


class Unbanner:
    """Periodically lifts blocks whose ban duration has elapsed."""

    def __init__(self, cfg: dict, blocker):
        self.blocker = blocker
        self.interval = max(5, cfg["ban_duration_seconds"] // 10)
        self.log = logging.getLogger("unbanner")

    def run(self, stop_event):
        while not stop_event.is_set():
            for ip in self.blocker.expired():
                self.blocker.unblock(ip)
            stop_event.wait(self.interval)

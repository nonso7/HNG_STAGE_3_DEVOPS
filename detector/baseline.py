import logging
import threading
import time
from collections import deque


class Baseline:
    """Maintains a rolling baseline of per-IP and global request rates."""

    def __init__(self, cfg: dict):
        self.window = cfg["window_seconds"]
        self.refresh = cfg["refresh_seconds"]
        self.min_samples = cfg["min_samples"]
        self.events = deque()
        self.lock = threading.Lock()
        self.log = logging.getLogger("baseline")

        self.global_rps = 0.0
        self.error_rate = 0.0

    def record(self, event: dict):
        with self.lock:
            self.events.append(event)
            self._evict_locked()

    def _evict_locked(self):
        cutoff = time.time() - self.window
        while self.events and self.events[0]["ts"] < cutoff:
            self.events.popleft()

    def snapshot(self) -> dict:
        with self.lock:
            self._evict_locked()
            total = len(self.events)
            if total == 0:
                return {"total": 0, "rps": 0.0, "error_rate": 0.0, "ready": False}
            errors = sum(1 for e in self.events if e["status"] >= 500)
            rps = total / self.window
            err_rate = errors / total
            self.global_rps = rps
            self.error_rate = err_rate
            return {
                "total": total,
                "rps": rps,
                "error_rate": err_rate,
                "ready": total >= self.min_samples,
            }

import logging
import threading
import time
from collections import defaultdict, deque


class Detector:
    """Scores per-IP traffic against baseline and asks the blocker to act."""

    def __init__(self, cfg: dict, baseline, blocker, notifier):
        self.rps_multiplier = cfg["rps_multiplier"]
        self.error_threshold = cfg["error_rate_threshold"]
        self.unique_path_threshold = cfg["unique_path_threshold"]
        self.interval = cfg["evaluation_interval_seconds"]

        self.baseline = baseline
        self.blocker = blocker
        self.notifier = notifier

        self.window_seconds = 60
        self.per_ip = defaultdict(lambda: deque())
        self.lock = threading.Lock()
        self.log = logging.getLogger("detector")
        self.last_alerts: list[dict] = []

    def record(self, event: dict):
        with self.lock:
            self.per_ip[event["ip"]].append(event)

    def _evict_locked(self):
        cutoff = time.time() - self.window_seconds
        for ip, events in list(self.per_ip.items()):
            while events and events[0]["ts"] < cutoff:
                events.popleft()
            if not events:
                del self.per_ip[ip]

    def evaluate(self) -> list[dict]:
        base = self.baseline.snapshot()
        offenders: list[dict] = []
        with self.lock:
            self._evict_locked()
            for ip, events in self.per_ip.items():
                if not events:
                    continue
                rps = len(events) / self.window_seconds
                errors = sum(1 for e in events if e["status"] >= 500)
                err_rate = errors / len(events)
                unique_paths = len({e["path"] for e in events})

                triggers = []
                if base["ready"] and rps > base["rps"] * self.rps_multiplier:
                    triggers.append(f"rps {rps:.1f} > baseline {base['rps']:.1f}x{self.rps_multiplier}")
                if err_rate > self.error_threshold:
                    triggers.append(f"error_rate {err_rate:.2f}")
                if unique_paths > self.unique_path_threshold:
                    triggers.append(f"unique_paths {unique_paths}")

                if triggers:
                    offenders.append({"ip": ip, "rps": rps, "reasons": triggers})

        for o in offenders:
            if self.blocker.block(o["ip"], reason="; ".join(o["reasons"])):
                self.notifier.send(severity="warning", message=f"blocked {o['ip']}: {o['reasons']}")
        self.last_alerts = offenders
        return offenders

    def run(self, stop_event):
        while not stop_event.is_set():
            try:
                self.evaluate()
            except Exception:
                self.log.exception("evaluation failed")
            stop_event.wait(self.interval)

import logging
import re
import time
from pathlib import Path

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\d+)'
)


class Monitor:
    """Tails the nginx access log and feeds parsed events to baseline + detector."""

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log = logging.getLogger("monitor")

    def _tail(self, stop_event):
        while not stop_event.is_set():
            if not self.log_path.exists():
                self.log.warning("log file %s missing; retrying", self.log_path)
                time.sleep(2)
                continue
            with self.log_path.open() as f:
                f.seek(0, 2)
                while not stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    yield line.rstrip("\n")

    def run(self, stop_event, baseline, detector):
        for line in self._tail(stop_event):
            event = self.parse(line)
            if event is None:
                continue
            baseline.record(event)
            detector.record(event)

    @staticmethod
    def parse(line: str):
        m = LOG_PATTERN.match(line)
        if not m:
            return None
        d = m.groupdict()
        return {
            "ip": d["ip"],
            "ts": time.time(),
            "method": d["method"],
            "path": d["path"],
            "status": int(d["status"]),
            "size": int(d["size"]),
        }

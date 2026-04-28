import argparse
import logging
import signal
import sys
import threading
import time
from pathlib import Path

import yaml

from baseline import Baseline
from blocker import Blocker
from dashboard import Dashboard
from detector import Detector
from monitor import Monitor
from notifier import Notifier
from unbanner import Unbanner


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main() -> int:
    parser = argparse.ArgumentParser(description="DDoS detection and mitigation daemon")
    parser.add_argument("--config", default=str(Path(__file__).parent / "config.yaml"))
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    log = logging.getLogger("main")

    cfg = load_config(args.config)

    monitor = Monitor(cfg["nginx"]["access_log"])
    baseline = Baseline(cfg["baseline"])
    blocker = Blocker(cfg["blocker"])
    notifier = Notifier(cfg["notifier"])
    detector = Detector(cfg["detector"], baseline, blocker, notifier)
    unbanner = Unbanner(cfg["blocker"], blocker)
    dashboard = Dashboard(cfg["dashboard"], baseline, blocker, detector)

    stop_event = threading.Event()

    def shutdown(signum, _frame):
        log.info("received signal %s, shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    threads = [
        threading.Thread(target=monitor.run, args=(stop_event, baseline, detector), daemon=True),
        threading.Thread(target=detector.run, args=(stop_event,), daemon=True),
        threading.Thread(target=unbanner.run, args=(stop_event,), daemon=True),
        threading.Thread(target=dashboard.run, daemon=True),
    ]
    for t in threads:
        t.start()

    log.info("detector started")
    while not stop_event.is_set():
        time.sleep(1)

    log.info("detector stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

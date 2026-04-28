"""
main.py — Entry point. Loads config, starts threads, runs the main detection loop.
"""

import os
import sys
import time
import yaml
import threading
from datetime import datetime, timezone

from monitor import tail_log
from baseline import Baseline
from detector import Detector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import run_dashboard


class AuditLogger:
    """Writes structured audit entries: [timestamp] ACTION key=value | key=value | ..."""
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def log(self, action, **kwargs):
        ts = datetime.now(timezone.utc).isoformat()
        parts = [f"{k}={v}" for k, v in kwargs.items()]
        line = f"[{ts}] {action} | {' | '.join(parts)}\n"
        with self.lock:
            with open(self.path, 'a') as f:
                f.write(line)
        # Also print to stdout for `docker logs` visibility.
        print(line.strip())


def load_config(path='/app/config.yaml'):
    with open(path) as f:
        return yaml.safe_load(f)


def parse_timestamp(ts_str):
    """Convert Nginx ISO 8601 timestamp to Unix epoch seconds."""
    try:
        # Nginx $time_iso8601 looks like '2026-04-28T14:23:11+00:00'.
        return datetime.fromisoformat(ts_str).timestamp()
    except (ValueError, TypeError):
        return time.time()


def baseline_recalc_loop(baseline, audit, interval):
    """Background thread: recalculates baseline every `interval` seconds."""
    while True:
        time.sleep(interval)
        try:
            result = baseline.recalculate()
            if result:
                audit.log(
                    'BASELINE_RECALC',
                    mean=f"{result['mean']:.2f}",
                    stddev=f"{result['stddev']:.2f}",
                    error_mean=f"{result['error_mean']:.2f}",
                    samples=result['samples'],
                    source=result['source'],
                )
        except Exception as e:
            print(f"[baseline] recalc error: {e}")


def per_second_aggregator(detector, baseline):
    """
    Background thread that records per-second request counts to the baseline.
    Reads from the global window every second.
    """
    last_total = 0
    last_errors = 0
    # Snapshot counters: total events and total errors observed so far.
    while True:
        time.sleep(1)
        with detector.lock:
            total = sum(w.request_count() for w in detector.ip_windows.values())
            # Approximation: count current window events as "this second".
            # More accurate: maintain dedicated per-second counters.
            current = detector.global_window.request_count()
            errors_now = len(detector.global_window.errors)
        # Better: just use the size of the global window's last 1 second
        # but for simplicity we record the current 1-sec slice from a counter.
        # Here we use a simpler approach: count events whose timestamp is within last 1 second.
        now = time.time()
        with detector.lock:
            recent = sum(1 for t in detector.global_window.events if t >= now - 1)
            recent_err = sum(1 for t in detector.global_window.errors if t >= now - 1)
        baseline.record_second(recent, recent_err)


def main():
    config = load_config()

    audit = AuditLogger(config['audit_log_path'])
    audit.log('STARTUP', config_loaded=True)

    baseline = Baseline(config['baseline_window_seconds'])
    detector = Detector(baseline, config)
    notifier = Notifier(config['slack_webhook'])
    blocker = Blocker(config, audit)
    unbanner = Unbanner(blocker, notifier)

    start_time = time.time()

    # Start background threads.
    threading.Thread(
        target=baseline_recalc_loop,
        args=(baseline, audit, config['baseline_recalc_interval']),
        daemon=True,
    ).start()

    threading.Thread(
        target=per_second_aggregator,
        args=(detector, baseline),
        daemon=True,
    ).start()

    unbanner.start()

    threading.Thread(
        target=run_dashboard,
        args=(detector, baseline, blocker, start_time, config['dashboard_port']),
        daemon=True,
    ).start()

    print("[main] All threads started, beginning log tail")

    # Track last anomaly check per IP to throttle ban attempts.
    last_global_alert = 0
    GLOBAL_ALERT_COOLDOWN = 60   # don't spam global alerts

    for event in tail_log(config['log_path']):
        ip = event.get('source_ip', '').split(',')[0].strip()
        ts = parse_timestamp(event.get('timestamp', ''))
        status = int(event.get('status', 0))

        if not ip:
            continue

        detector.record(ip, ts, status)

        # Per-IP check.
        is_anomalous, reason, rate = detector.check_ip(ip)
        if is_anomalous:
            ban_info = blocker.ban(
                ip, reason, rate, baseline.effective_mean,
            )
            if ban_info:
                notifier.send_ban(
                    ip, reason, rate, baseline.effective_mean,
                    ban_info['duration'],
                )

        # Global check (throttled).
        now = time.time()
        if now - last_global_alert > GLOBAL_ALERT_COOLDOWN:
            is_anom, reason, grate = detector.check_global()
            if is_anom:
                notifier.send_global_alert(reason, grate, baseline.effective_mean)
                audit.log(
                    'GLOBAL_ANOMALY', condition=reason,
                    rate=f"{grate:.1f}", baseline=f"{baseline.effective_mean:.1f}",
                )
                last_global_alert = now


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[main] shutdown")
        sys.exit(0)

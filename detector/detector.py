"""
detector.py — The core detection logic.

Maintains two sliding windows:
  - Global window: all requests across all IPs in the last 60s
  - Per-IP windows: each IP gets its own window

Computes z-scores and rate multipliers against the baseline.
"""

import time
import threading
from collections import deque, defaultdict


class SlidingWindow:
    """A 60-second sliding window of event timestamps."""

    def __init__(self, window_seconds=60):
        self.window = window_seconds
        self.events = deque()       # timestamps of events in window
        self.errors = deque()       # subset: timestamps of 4xx/5xx events

    def add(self, timestamp, is_error=False):
        self.events.append(timestamp)
        if is_error:
            self.errors.append(timestamp)
        self._evict(timestamp)

    def _evict(self, now):
        """Remove events older than window_seconds. O(1) amortized."""
        cutoff = now - self.window
        while self.events and self.events[0] < cutoff:
            self.events.popleft()
        while self.errors and self.errors[0] < cutoff:
            self.errors.popleft()

    def rate(self):
        """Requests per second over the window."""
        # Evict stale events first in case nothing has been added recently.
        self._evict(time.time())
        return len(self.events) / self.window

    def error_rate(self):
        self._evict(time.time())
        return len(self.errors) / self.window

    def request_count(self):
        return len(self.events)


class Detector:
    def __init__(self, baseline, config):
        self.baseline = baseline
        self.config = config
        self.global_window = SlidingWindow(config['window_seconds'])
        # defaultdict means new IPs auto-create a window the first time we see them.
        self.ip_windows = defaultdict(lambda: SlidingWindow(config['window_seconds']))
        self.lock = threading.Lock()

    def record(self, ip, timestamp, status):
        """Add an event from monitor."""
        is_error = status >= 400
        with self.lock:
            self.global_window.add(timestamp, is_error)
            self.ip_windows[ip].add(timestamp, is_error)

    def cleanup_idle_ips(self):
        """Remove per-IP windows that have no events in the window — saves memory."""
        with self.lock:
            now = time.time()
            stale = [ip for ip, w in self.ip_windows.items()
                     if not w.events or w.events[-1] < now - self.config['window_seconds']]
            for ip in stale:
                del self.ip_windows[ip]

    def check_ip(self, ip):
        """
        Return (is_anomalous, reason, current_rate) for a single IP.
        Returns (False, None, rate) if the IP looks normal.
        """
        with self.lock:
            window = self.ip_windows.get(ip)
            if window is None:
                return False, None, 0.0
            rate = window.rate()
            error_rate = window.error_rate()

        mean = self.baseline.effective_mean
        stddev = self.baseline.effective_stddev

        # Detect error surge — if this IP is producing 3x the baseline error rate,
        # tighten the z-score threshold for it.
        z_threshold = self.config['z_score_threshold']
        if error_rate > self.config['error_surge_multiplier'] * self.baseline.effective_error_mean:
            z_threshold = self.config['tight_z_score_threshold']

        # Trigger condition 1: z-score too high.
        z = (rate - mean) / stddev
        if z > z_threshold:
            return True, f"z-score {z:.2f} > {z_threshold}", rate

        # Trigger condition 2: rate is more than Nx the mean.
        multiplier = self.config['rate_multiplier_threshold']
        if rate > multiplier * mean:
            return True, f"rate {rate:.1f} > {multiplier}x baseline ({mean:.1f})", rate

        return False, None, rate

    def check_global(self):
        """Same logic but for the global window. Returns (is_anomalous, reason, rate)."""
        rate = self.global_window.rate()
        mean = self.baseline.effective_mean
        stddev = self.baseline.effective_stddev

        z = (rate - mean) / stddev
        if z > self.config['z_score_threshold']:
            return True, f"global z-score {z:.2f}", rate

        if rate > self.config['rate_multiplier_threshold'] * mean:
            return True, f"global rate {rate:.1f} > {self.config['rate_multiplier_threshold']}x baseline", rate

        return False, None, rate

    def top_ips(self, n=10):
        """Return list of (ip, request_count) for top N noisy IPs."""
        with self.lock:
            counts = [(ip, w.request_count()) for ip, w in self.ip_windows.items()]
        counts.sort(key=lambda x: x[1], reverse=True)
        return counts[:n]

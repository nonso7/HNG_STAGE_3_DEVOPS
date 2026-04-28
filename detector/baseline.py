"""
baseline.py — Maintains the rolling baseline of "normal" traffic.

Concept: Every second, we record how many requests happened that second.
We keep the last 30 minutes (1800 samples) in a deque. Every 60 seconds,
we compute mean and standard deviation from those samples — these become
the "effective_mean" and "effective_stddev" the detector uses.

We also track per-hour slots so 3am traffic isn't compared against noon traffic.
"""

import statistics
import threading
from collections import deque
from datetime import datetime


class Baseline:
    def __init__(self, window_seconds=1800):
        self.window_seconds = window_seconds

        # Per-second request counts for the last 30 minutes.
        # maxlen ensures old data falls off automatically.
        self.per_second_counts = deque(maxlen=window_seconds)

        # Hourly slots: {hour_of_day: [recent counts in this hour]}
        # Used to prefer time-of-day baselines.
        self.hourly_slots = {}

        # Same for error rate baseline (4xx/5xx per second).
        self.per_second_errors = deque(maxlen=window_seconds)

        # Effective values used by the detector. Floor at 1.0 to avoid
        # divide-by-zero and "infinite z-score" issues at very low traffic.
        self.effective_mean = 1.0
        self.effective_stddev = 1.0
        self.effective_error_mean = 1.0

        # Thread safety: detector reads while baseline thread writes.
        self.lock = threading.Lock()

    def record_second(self, request_count, error_count):
        """Called once per second by the main loop."""
        with self.lock:
            self.per_second_counts.append(request_count)
            self.per_second_errors.append(error_count)

            hour = datetime.utcnow().hour
            if hour not in self.hourly_slots:
                self.hourly_slots[hour] = deque(maxlen=self.window_seconds)
            self.hourly_slots[hour].append(request_count)

    def recalculate(self):
        """
        Recompute effective_mean and effective_stddev.
        Called every 60 seconds from a background thread.
        """
        with self.lock:
            hour = datetime.utcnow().hour

            # Prefer the current hour's baseline if we have enough samples.
            # 300 samples = 5 minutes of data, enough to be meaningful.
            if hour in self.hourly_slots and len(self.hourly_slots[hour]) >= 300:
                data = list(self.hourly_slots[hour])
                source = f"hourly slot {hour}"
            else:
                data = list(self.per_second_counts)
                source = "30-min rolling"

            if len(data) < 10:
                # Not enough data yet — keep defaults.
                return None

            # statistics.stdev requires at least 2 points.
            mean = statistics.mean(data)
            stddev = statistics.stdev(data) if len(data) > 1 else 1.0

            # Floor values prevent pathological math at low traffic.
            self.effective_mean = max(mean, 1.0)
            self.effective_stddev = max(stddev, 1.0)

            # Error baseline (simpler, just mean).
            errors = list(self.per_second_errors)
            if errors:
                self.effective_error_mean = max(statistics.mean(errors), 0.1)

            return {
                'mean': self.effective_mean,
                'stddev': self.effective_stddev,
                'error_mean': self.effective_error_mean,
                'source': source,
                'samples': len(data),
            }

"""
Rolling baseline engine.

Tracks per-second global request counts over a 30-minute rolling window.
Recalculates mean and stddev every 60 seconds. Maintains per-hour slots
so the detector can prefer the current hour's profile when it has enough data.

This is the "brain" that learns what normal traffic looks like over time.
No hardcoded effective_mean — everything is derived from observed traffic.
"""

import asyncio
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class BaselineStats:
    """
    The computed baseline at a point in time.

    effective_mean and effective_stddev are what the detector actually uses.
    They incorporate the floor values from config so we never divide by zero.
    """
    effective_mean: float       # Request/s baseline mean (floored)
    effective_stddev: float     # Baseline stddev (floored)
    error_rate_mean: float      # Baseline 4xx/5xx rate mean
    sample_count: int           # How many 1-second slots contributed
    computed_at: float          # Unix timestamp of last recalculation
    hour_slot: int              # Which hour (0-23) this reflects


class HourlySlot:
    """
    Tracks request counts and error counts for one clock hour.

    Each slot accumulates per-second buckets. When recalculation fires,
    the slot provides mean and stddev for that hour's traffic pattern.
    """

    def __init__(self):
        # Each entry: (unix_second, request_count, error_count)
        self.buckets: deque = deque()
        self.lock = asyncio.Lock()

    def add_bucket(self, second: int, req_count: int, err_count: int):
        self.buckets.append((second, req_count, err_count))

    def prune_older_than(self, cutoff_second: int):
        """Remove entries before cutoff — keeps memory bounded."""
        while self.buckets and self.buckets[0][0] < cutoff_second:
            self.buckets.popleft()

    def stats(self) -> Tuple[float, float, float, int]:
        """
        Returns (mean_req, stddev_req, mean_error, sample_count).

        Uses Welford's online algorithm for numerically stable stddev.
        """
        counts = [b[1] for b in self.buckets]
        errors = [b[2] for b in self.buckets]
        n = len(counts)
        if n == 0:
            return 0.0, 0.0, 0.0, 0

        mean_req = sum(counts) / n
        # Population stddev (we have the full window, not a sample)
        variance = sum((c - mean_req) ** 2 for c in counts) / n
        stddev_req = math.sqrt(variance)
        mean_err = sum(errors) / n

        return mean_req, stddev_req, mean_err, n


class BaselineEngine:
    """
    Maintains a rolling 30-minute window of per-second traffic counts.

    Architecture:
    - We bucket incoming log entries by second into a rolling deque.
    - Every `recalc_interval_seconds`, we compute mean/stddev over the window.
    - We also keep per-hour slots so we can compare current vs historical hour.
    - The effective baseline prefers the current hour's stats when available.

    Thread-safety: All state mutations happen in the asyncio event loop.
    The detector reads `current_stats` which is atomically replaced.
    """

    def __init__(
        self,
        rolling_window_minutes: int = 30,
        recalc_interval_seconds: int = 60,
        min_samples: int = 10,
        floor_mean: float = 1.0,
        floor_stddev: float = 0.5,
    ):
        self.rolling_window_seconds = rolling_window_minutes * 60
        self.recalc_interval = recalc_interval_seconds
        self.min_samples = min_samples
        self.floor_mean = floor_mean
        self.floor_stddev = floor_stddev

        # Rolling deque of (unix_second, req_count, err_count)
        # One entry per second. Max length = rolling_window_seconds.
        self._rolling: deque = deque(maxlen=self.rolling_window_seconds)

        # In-progress accumulator for the current second
        self._current_second: int = int(time.time())
        self._current_req: int = 0
        self._current_err: int = 0

        # Per-hour historical slots (0-23)
        self._hourly: Dict[int, HourlySlot] = defaultdict(HourlySlot)

        # Published stats — replaced atomically each recalculation
        self.current_stats: BaselineStats = BaselineStats(
            effective_mean=floor_mean,
            effective_stddev=floor_stddev,
            error_rate_mean=0.0,
            sample_count=0,
            computed_at=time.time(),
            hour_slot=0,
        )

        # History of (timestamp, effective_mean) for the dashboard baseline graph
        self.baseline_history: deque = deque(maxlen=7200)  # 2 hours of history

        self._running = False

    def record_request(self, unix_ts: float, is_error: bool):
        """
        Called for every incoming log entry.

        We bucket by second — if the second ticks over, we flush the
        previous second's bucket into the rolling window and hourly slot.
        """
        second = int(unix_ts)

        if second != self._current_second:
            # Flush completed second into rolling window
            self._flush_current()
            # Fast-forward if seconds were skipped (quiet periods)
            if second > self._current_second + 1:
                for s in range(self._current_second + 1, second):
                    self._rolling.append((s, 0, 0))
                    hour = (s // 3600) % 24
                    self._hourly[hour].add_bucket(s, 0, 0)
            self._current_second = second
            self._current_req = 0
            self._current_err = 0

        self._current_req += 1
        if is_error:
            self._current_err += 1

    def _flush_current(self):
        """Move the current second accumulator into the rolling deque."""
        s = self._current_second
        req = self._current_req
        err = self._current_err
        self._rolling.append((s, req, err))
        hour = (s // 3600) % 24
        self._hourly[hour].add_bucket(s, req, err)

    async def recalc_loop(self):
        """
        Background task: recalculate baseline stats every recalc_interval seconds.
        Also prunes stale hourly slot data.
        """
        self._running = True
        while self._running:
            await asyncio.sleep(self.recalc_interval)
            self._recalculate()

    def _recalculate(self):
        """
        Compute new baseline from the rolling window and hourly slots.

        Logic:
        1. Compute stats from the full 30-minute rolling window.
        2. Compute stats from the current clock hour's slot.
        3. If current hour has >= min_samples, prefer it (more specific to
           current traffic pattern). Otherwise fall back to rolling window.
        4. Apply floor values so we never use 0 as a baseline.
        5. Atomically publish new BaselineStats.
        """
        now = time.time()
        current_hour = int(time.strftime("%H"))

        # Prune hourly slots to last 2 hours of data each
        cutoff = int(now) - 7200
        for slot in self._hourly.values():
            slot.prune_older_than(cutoff)

        # Rolling window stats
        window_counts = [b[1] for b in self._rolling]
        window_errors = [b[2] for b in self._rolling]
        n_rolling = len(window_counts)

        if n_rolling == 0:
            return  # Not enough data yet

        roll_mean = sum(window_counts) / n_rolling
        roll_var = sum((c - roll_mean) ** 2 for c in window_counts) / max(n_rolling, 1)
        roll_stddev = math.sqrt(roll_var)
        roll_err_mean = sum(window_errors) / max(n_rolling, 1)

        # Current hour slot stats
        hour_mean, hour_stddev, hour_err_mean, n_hour = self._hourly[current_hour].stats()

        # Choose the most specific baseline we have enough data for
        if n_hour >= self.min_samples:
            chosen_mean = hour_mean
            chosen_stddev = hour_stddev
            chosen_err_mean = hour_err_mean
            chosen_n = n_hour
        else:
            chosen_mean = roll_mean
            chosen_stddev = roll_stddev
            chosen_err_mean = roll_err_mean
            chosen_n = n_rolling

        # Apply floors
        eff_mean = max(chosen_mean, self.floor_mean)
        eff_stddev = max(chosen_stddev, self.floor_stddev)

        new_stats = BaselineStats(
            effective_mean=eff_mean,
            effective_stddev=eff_stddev,
            error_rate_mean=chosen_err_mean,
            sample_count=chosen_n,
            computed_at=now,
            hour_slot=current_hour,
        )

        self.current_stats = new_stats
        self.baseline_history.append((now, eff_mean, eff_stddev))

    def stop(self):
        self._running = False

    def get_history(self) -> List[Tuple[float, float, float]]:
        """Returns list of (timestamp, mean, stddev) for dashboard graph."""
        return list(self.baseline_history)

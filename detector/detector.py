"""
Anomaly detection using sliding windows and z-score analysis.

Two sliding windows (deque-based):
  1. Per-IP window: tracks all requests from a single IP in the last 60 seconds.
  2. Global window:  tracks all requests from all IPs in the last 60 seconds.

For each new log entry:
  - Add to both windows, evicting entries older than the window duration.
  - Compute current rate (requests in window / window_seconds).
  - Compare rate against baseline using z-score AND raw multiplier check.
  - Fire anomaly if z-score > threshold OR rate > N×baseline_mean.
  - If IP has elevated error rate, tighten its detection thresholds.
"""

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from baseline import BaselineEngine, BaselineStats
from monitor import LogEntry


@dataclass
class AnomalyEvent:
    """Emitted when an anomaly is detected."""
    kind: str            # "per_ip" or "global"
    source_ip: str       # "" for global
    current_rate: float  # Requests/second in the window
    baseline_mean: float
    baseline_stddev: float
    zscore: float
    condition: str       # Human-readable description of which threshold fired
    timestamp: float


class SlidingWindow:
    """
    Deque-based sliding window that tracks timestamped events.

    Eviction logic:
    - On each insertion, we append the current timestamp.
    - Before computing the rate, we pop from the left (popleft) while
      the oldest timestamp is older than (now - window_seconds).
    - This gives us an O(1) amortized insert and an O(k) eviction
      where k is the number of expired entries — k is typically tiny.

    The window stores raw Unix timestamps (floats), not counters,
    so we can compute exact rates at any moment without drift.
    """

    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self._events: deque = deque()  # Each entry: unix timestamp float
        self._error_events: deque = deque()  # Timestamps of error responses

    def add(self, ts: float, is_error: bool = False):
        """Record a request at time ts."""
        self._events.append(ts)
        if is_error:
            self._error_events.append(ts)

    def _evict(self, now: float):
        """Remove events outside the window from both deques."""
        cutoff = now - self.window_seconds
        # Main events
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        # Error events
        while self._error_events and self._error_events[0] < cutoff:
            self._error_events.popleft()

    def rate(self, now: Optional[float] = None) -> float:
        """
        Current request rate in requests/second.

        We evict stale entries first, then divide the count by the
        window duration. This is the key metric compared to baseline.
        """
        if now is None:
            now = time.time()
        self._evict(now)
        return len(self._events) / self.window_seconds

    def error_rate(self, now: Optional[float] = None) -> float:
        """Current 4xx/5xx rate in errors/second."""
        if now is None:
            now = time.time()
        self._evict(now)
        return len(self._error_events) / self.window_seconds

    def count(self, now: Optional[float] = None) -> int:
        """Number of events currently in the window."""
        if now is None:
            now = time.time()
        self._evict(now)
        return len(self._events)


class AnomalyDetector:
    """
    Core detection engine.

    Maintains:
    - One global SlidingWindow for aggregate traffic.
    - One SlidingWindow per source IP (created on first request, pruned when idle).
    - A reference to the BaselineEngine for current stats.
    - Callbacks for ban actions and Slack alerts.

    Detection algorithm (per IP and global):
    1. Compute z-score = (current_rate - baseline_mean) / baseline_stddev
    2. Check if rate > rate_multiplier × baseline_mean
    3. If IP has elevated errors, use tightened thresholds (lower z, lower mult)
    4. Fire anomaly if EITHER condition is met.

    We emit at most one anomaly event per IP per 60 seconds (cooldown)
    to prevent alert storms.
    """

    def __init__(
        self,
        baseline: BaselineEngine,
        window_seconds: int = 60,
        zscore_threshold: float = 3.0,
        rate_multiplier: float = 5.0,
        error_rate_multiplier: float = 3.0,
        tightened_zscore: float = 2.0,
        tightened_multiplier: float = 3.0,
        on_anomaly: Optional[Callable] = None,
    ):
        self.baseline = baseline
        self.window_seconds = window_seconds
        self.zscore_threshold = zscore_threshold
        self.rate_multiplier = rate_multiplier
        self.error_rate_multiplier = error_rate_multiplier
        self.tightened_zscore = tightened_zscore
        self.tightened_multiplier = tightened_multiplier
        self.on_anomaly = on_anomaly

        # Global window — all traffic
        self._global_window = SlidingWindow(window_seconds)

        # Per-IP windows — created lazily
        self._ip_windows: Dict[str, SlidingWindow] = {}

        # Cooldown: track last anomaly time per IP (and "global")
        self._last_anomaly: Dict[str, float] = {}
        self._anomaly_cooldown = 60.0

        # Counters for dashboard
        self.total_requests = 0
        self.total_anomalies = 0

        # Top-IP tracking: {ip: request_count_all_time}
        self._ip_totals: Dict[str, int] = defaultdict(int)

    def process(self, entry: LogEntry):
        """
        Process one log entry from the monitor queue.

        This is the hot path — it runs for every incoming request.
        Keep it fast; all heavy work is amortized in the deque eviction.
        """
        now = time.time()
        is_error = entry.status >= 400
        ip = entry.source_ip

        self.total_requests += 1
        self._ip_totals[ip] += 1

        # Feed the baseline engine (it tracks per-second counts)
        self.baseline.record_request(entry.timestamp, is_error)

        # Update global window
        self._global_window.add(entry.timestamp, is_error)

        # Update per-IP window
        if ip not in self._ip_windows:
            self._ip_windows[ip] = SlidingWindow(self.window_seconds)
        self._ip_windows[ip].add(entry.timestamp, is_error)

        # Run detection checks
        stats = self.baseline.current_stats

        # Per-IP check
        self._check_ip(ip, now, stats)

        # Global check (once per second is enough — throttle it)
        self._check_global(now, stats)

    def _check_ip(self, ip: str, now: float, stats: BaselineStats):
        """Evaluate per-IP sliding window against baseline."""
        win = self._ip_windows[ip]
        ip_rate = win.rate(now)
        ip_err_rate = win.error_rate(now)

        # Determine if this IP's error profile is elevated
        elevated_errors = (
            stats.error_rate_mean > 0
            and ip_err_rate > self.error_rate_multiplier * stats.error_rate_mean
        )

        # Choose thresholds
        z_thresh = self.tightened_zscore if elevated_errors else self.zscore_threshold
        mult = self.tightened_multiplier if elevated_errors else self.rate_multiplier

        anomaly, condition = self._is_anomalous(ip_rate, stats, z_thresh, mult)
        if elevated_errors and not anomaly:
            condition = f"elevated_errors({ip_err_rate:.2f}/s)"

        if anomaly:
            self._emit_anomaly("per_ip", ip, ip_rate, stats, condition, now)

    def _check_global(self, now: float, stats: BaselineStats):
        """Evaluate global sliding window against baseline."""
        # Throttle: only check global once per second
        last = self._last_anomaly.get("__global_check__", 0)
        if now - last < 1.0:
            return
        self._last_anomaly["__global_check__"] = now

        global_rate = self._global_window.rate(now)
        anomaly, condition = self._is_anomalous(
            global_rate, stats, self.zscore_threshold, self.rate_multiplier
        )
        if anomaly:
            self._emit_anomaly("global", "", global_rate, stats, condition, now)

    def _is_anomalous(
        self,
        rate: float,
        stats: BaselineStats,
        z_thresh: float,
        mult: float,
    ) -> Tuple[bool, str]:
        """
        Returns (is_anomalous, condition_description).

        Z-score: measures how many standard deviations above the mean.
        Multiplier: catches fast-rising bursts before stddev can react.
        Whichever fires first wins.
        """
        if stats.sample_count < 10:
            # Not enough data to make a judgement yet
            return False, ""

        zscore = (rate - stats.effective_mean) / stats.effective_stddev

        if zscore > z_thresh:
            return True, f"zscore={zscore:.2f}>{z_thresh}"

        if rate > mult * stats.effective_mean:
            return True, f"rate={rate:.2f}>{mult}x_mean({stats.effective_mean:.2f})"

        return False, ""

    def _emit_anomaly(
        self,
        kind: str,
        ip: str,
        rate: float,
        stats: BaselineStats,
        condition: str,
        now: float,
    ):
        """Fire an anomaly event, respecting per-IP cooldown."""
        cooldown_key = ip if ip else "__global__"
        last_fired = self._last_anomaly.get(cooldown_key, 0)
        if now - last_fired < self._anomaly_cooldown:
            return

        self._last_anomaly[cooldown_key] = now
        self.total_anomalies += 1

        zscore = (rate - stats.effective_mean) / stats.effective_stddev

        event = AnomalyEvent(
            kind=kind,
            source_ip=ip,
            current_rate=rate,
            baseline_mean=stats.effective_mean,
            baseline_stddev=stats.effective_stddev,
            zscore=zscore,
            condition=condition,
            timestamp=now,
        )

        if self.on_anomaly:
            asyncio.ensure_future(self.on_anomaly(event))

    def get_global_rate(self) -> float:
        return self._global_window.rate()

    def get_top_ips(self, n: int = 10) -> List[Tuple[str, int]]:
        """Returns top N IPs by all-time request count."""
        sorted_ips = sorted(self._ip_totals.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:n]

    def get_ip_rate(self, ip: str) -> float:
        if ip in self._ip_windows:
            return self._ip_windows[ip].rate()
        return 0.0

    def prune_idle_ip_windows(self, idle_threshold_seconds: int = 300):
        """
        Remove per-IP windows that have been empty for a while.
        Called periodically to prevent unbounded memory growth.
        """
        now = time.time()
        to_remove = []
        for ip, win in self._ip_windows.items():
            if win.count(now) == 0 and self._ip_totals.get(ip, 0) > 0:
                # Window is empty — check if last request was long ago
                to_remove.append(ip)
        for ip in to_remove[:100]:  # Prune at most 100 at a time
            del self._ip_windows[ip]

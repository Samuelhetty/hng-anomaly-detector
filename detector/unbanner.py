"""
Audit logging for all ban/unban/baseline events.

Writes structured log entries in the required format:
  [timestamp] ACTION ip | condition | rate | baseline | duration

Also re-exports the audit_log path for other modules to import.
"""

import time
import os
from typing import Optional
from blocker import BanRecord


class AuditLogger:
    """
    Writes structured audit entries to a log file.

    Format (required by spec):
      [2024-01-15T14:23:01Z] BAN 1.2.3.4 | zscore=4.2>3.0 | rate=45.2 | baseline=8.1 | duration=10m
      [2024-01-15T14:33:01Z] UNBAN 1.2.3.4 | schedule_expired | rate=0.0 | baseline=8.1 | duration=10m
      [2024-01-15T14:24:00Z] BASELINE_RECALC - | - | mean=8.1 stddev=2.3 | samples=1800 | hour=14
    """

    def __init__(self, audit_log_path: str):
        self.path = audit_log_path
        os.makedirs(os.path.dirname(audit_log_path), exist_ok=True)

    def _write(self, line: str):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry = f"[{ts}] {line}\n"
        try:
            with open(self.path, "a") as f:
                f.write(entry)
            print(entry, end="")  # Also echo to stdout for container logs
        except Exception as e:
            print(f"[audit] Failed to write log: {e}")

    def log_ban(self, record: BanRecord):
        duration_str = "permanent" if record.duration_minutes == -1 else f"{record.duration_minutes}m"
        self._write(
            f"BAN {record.ip} | {record.condition} | "
            f"rate={record.current_rate:.2f} | "
            f"baseline={record.baseline_mean:.2f} | "
            f"duration={duration_str}"
        )

    def log_unban(self, record: BanRecord, reason: str):
        duration_str = "permanent" if record.duration_minutes == -1 else f"{record.duration_minutes}m"
        self._write(
            f"UNBAN {record.ip} | {reason} | "
            f"rate=0.0 | "
            f"baseline={record.baseline_mean:.2f} | "
            f"duration={duration_str}"
        )

    def log_baseline_recalc(
        self,
        mean: float,
        stddev: float,
        sample_count: int,
        hour: int,
    ):
        self._write(
            f"BASELINE_RECALC - | - | "
            f"mean={mean:.3f} stddev={stddev:.3f} | "
            f"samples={sample_count} | "
            f"hour={hour}"
        )

    def log_global_anomaly(self, rate: float, mean: float, condition: str):
        self._write(
            f"GLOBAL_ANOMALY - | {condition} | "
            f"rate={rate:.2f} | "
            f"baseline={mean:.2f} | "
            f"duration=N/A"
        )

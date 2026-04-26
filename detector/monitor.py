"""
This module continuously tails and parses the Nginx JSON access log.

Reads line-by-line from hng-access.log using non-blocking I/O with inotify-style
polling fallback. Each parsed line is pushed into a shared asyncio Queue for
downstream processing by the detector and baseline modules.
"""

import asyncio
import json
import os
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class LogEntry:
    """Represents one parsed Nginx access log line."""
    source_ip: str
    timestamp: float          # Unix epoch float
    method: str
    path: str
    status: int
    response_size: int
    raw: str                  # Original line for debugging


def _parse_line(line: str) -> Optional[LogEntry]:
    """
    Parse a single JSON log line from Nginx.

    Nginx logs are configured to emit JSON like:
    {"source_ip":"1.2.3.4","timestamp":"...","method":"GET",
     "path":"/","status":200,"response_size":512}

    Returns None on any parse failure — we never crash on bad lines.
    """
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
        # Support both Unix epoch and ISO8601 timestamps from Nginx
        ts_raw = obj.get("timestamp", obj.get("time_local", ""))
        if isinstance(ts_raw, (int, float)):
            ts = float(ts_raw)
        else:
            # Try parsing ISO8601 / Nginx common log time
            from dateutil import parser as dtparser
            ts = dtparser.parse(ts_raw).timestamp()

        return LogEntry(
            source_ip=obj.get("source_ip", obj.get("remote_addr", "unknown")),
            timestamp=ts,
            method=obj.get("method", obj.get("request_method", "GET")),
            path=obj.get("path", obj.get("request_uri", "/")),
            status=int(obj.get("status", 200)),
            response_size=int(obj.get("response_size", obj.get("body_bytes_sent", 0))),
            raw=line,
        )
    except Exception:
        return None


class LogMonitor:
    """
    Tails the Nginx access log file continuously.

    Strategy:
    - Open the file and seek to EOF on start (we only care about new traffic).
    - Poll every `poll_interval_ms` milliseconds for new lines.
    - If the file is rotated (inode changes or file shrinks), re-open it.
    - Push each valid LogEntry onto `queue` for the detector to consume.
    """

    def __init__(self, log_path: str, queue: asyncio.Queue, poll_interval_ms: int = 100):
        self.log_path = log_path
        self.queue = queue
        self.poll_interval = poll_interval_ms / 1000.0
        self._running = False
        self._lines_parsed = 0
        self._last_inode: Optional[int] = None
        self._file_handle = None

    async def start(self):
        """Begin tailing. Runs until stop() is called."""
        self._running = True
        await self._tail_loop()

    def stop(self):
        self._running = False

    @property
    def lines_parsed(self) -> int:
        return self._lines_parsed

    async def _open_log(self):
        """Open the log file and seek to end (only tail new lines)."""
        if self._file_handle:
            self._file_handle.close()
        # Wait for file to exist (on first startup Nginx may not have written yet)
        while self._running:
            if os.path.exists(self.log_path):
                break
            await asyncio.sleep(1)

        self._file_handle = open(self.log_path, "r", encoding="utf-8", errors="replace")
        self._file_handle.seek(0, 2)  # Seek to EOF
        stat = os.stat(self.log_path)
        self._last_inode = stat.st_ino
        self._last_size = stat.st_size

    async def _tail_loop(self):
        """
        Core polling loop.

        Each iteration:
        1. Check if file still exists and hasn't been rotated.
        2. Read any new lines.
        3. Parse and enqueue each valid line.
        4. Sleep for poll_interval.
        """
        await self._open_log()

        while self._running:
            try:
                # Rotation / truncation detection
                if os.path.exists(self.log_path):
                    stat = os.stat(self.log_path)
                    if stat.st_ino != self._last_inode or stat.st_size < self._last_size:
                        # File was rotated or truncated — re-open
                        await self._open_log()
                    self._last_size = stat.st_size

                # Read all available lines without blocking
                while True:
                    line = self._file_handle.readline()
                    if not line:
                        break
                    entry = _parse_line(line)
                    if entry:
                        self._lines_parsed += 1
                        await self.queue.put(entry)

            except Exception as e:
                # Never crash the monitor; log and retry
                print(f"[monitor] Error reading log: {e}")
                await asyncio.sleep(1)
                await self._open_log()

            await asyncio.sleep(self.poll_interval)

"""
Iptables-based IP blocking.

Adds DROP rules for anomalous source IPs using iptables.
Tracks ban state (ban count, duration schedule) per IP.
Does NOT use any rate-limiting library — pure subprocess calls to iptables.

Ban schedule (from config): 10 min → 30 min → 2 hours → permanent
Each subsequent ban for the same IP escalates to the next tier.
"""

import asyncio
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class BanRecord:
    """State for a currently-banned IP."""
    ip: str
    banned_at: float
    duration_minutes: int          # -1 = permanent
    ban_count: int                 # How many times this IP has been banned
    condition: str                 # What triggered the ban
    current_rate: float
    baseline_mean: float
    unban_at: Optional[float]      # None if permanent


class Blocker:
    """
    Manages iptables DROP rules for anomalous IPs.

    Architecture:
    - `ban(ip)` adds an iptables rule and records the BanRecord.
    - `unban_loop()` runs as a background task, checking every 30 seconds
      whether any temporary bans have expired.
    - Ban count per IP persists across ban/unban cycles within a session,
      so repeated offenders escalate automatically.
    - We maintain a whitelist of IPs that should never be banned
      (e.g., localhost, monitoring systems).
    """

    # IPs that must never be blocked
    WHITELIST = {
        "127.0.0.1",
        "::1",
        "localhost",
    }

    def __init__(
        self,
        ban_schedule_minutes: List[int],
        on_ban: Optional[callable] = None,
        on_unban: Optional[callable] = None,
    ):
        """
        ban_schedule_minutes: e.g. [10, 30, 120, -1]
        on_ban / on_unban: async callbacks for Slack notifications
        """
        self.ban_schedule = ban_schedule_minutes
        self.on_ban = on_ban
        self.on_unban = on_unban

        # Active bans: {ip: BanRecord}
        self._active_bans: Dict[str, BanRecord] = {}
        # Ban counts persist: {ip: count}
        self._ban_counts: Dict[str, int] = {}

        self._running = False

    # Public API

    async def ban(
        self,
        ip: str,
        condition: str,
        current_rate: float,
        baseline_mean: float,
    ) -> Optional[BanRecord]:
        """
        Ban an IP:
        1. Validate it's not whitelisted or already banned.
        2. Determine duration from ban schedule.
        3. Add iptables DROP rule.
        4. Record the ban and notify.

        Returns the BanRecord, or None if ban was skipped.
        """
        if ip in self.WHITELIST:
            return None

        if ip in self._active_bans:
            # Already banned — skip (unban_loop will handle escalation if needed)
            return None

        # Increment ban count and pick duration from schedule
        count = self._ban_counts.get(ip, 0)
        self._ban_counts[ip] = count + 1
        schedule_idx = min(count, len(self.ban_schedule) - 1)
        duration_minutes = self.ban_schedule[schedule_idx]

        now = time.time()
        unban_at = None if duration_minutes == -1 else now + duration_minutes * 60

        record = BanRecord(
            ip=ip,
            banned_at=now,
            duration_minutes=duration_minutes,
            ban_count=count + 1,
            condition=condition,
            current_rate=current_rate,
            baseline_mean=baseline_mean,
            unban_at=unban_at,
        )

        # Add iptables rule
        success = await self._iptables_ban(ip)
        if not success:
            return None

        self._active_bans[ip] = record

        # Notify
        if self.on_ban:
            asyncio.ensure_future(self.on_ban(record))

        return record

    async def unban(self, ip: str, reason: str = "schedule"):
        """Remove an IP's ban — called by unban_loop or manually."""
        if ip not in self._active_bans:
            return

        record = self._active_bans.pop(ip)
        await self._iptables_unban(ip)

        if self.on_unban:
            asyncio.ensure_future(self.on_unban(record, reason))

    async def unban_loop(self):
        """
        Background task that checks every 30 seconds for expired bans.

        Permanent bans (duration_minutes == -1) are never auto-released.
        """
        self._running = True
        while self._running:
            await asyncio.sleep(30)
            now = time.time()
            expired = [
                ip for ip, rec in self._active_bans.items()
                if rec.unban_at is not None and now >= rec.unban_at
            ]
            for ip in expired:
                await self.unban(ip, reason="schedule_expired")

    def stop(self):
        self._running = False

    # Properties for dashboard

    @property
    def active_bans(self) -> Dict[str, BanRecord]:
        return dict(self._active_bans)

    def is_banned(self, ip: str) -> bool:
        return ip in self._active_bans

    # iptables helpers

    async def _iptables_ban(self, ip: str) -> bool:
        """
        Add an iptables INPUT DROP rule for the IP.

        We insert at position 1 (before any ACCEPT rules) to ensure
        the DROP takes effect immediately.
        """
        try:
            result = await asyncio.create_subprocess_exec(
                "iptables", "-I", "INPUT", "1",
                "-s", ip,
                "-j", "DROP",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            _, stderr = await result.communicate()
            if result.returncode != 0:
                print(f"[blocker] iptables ban failed for {ip}: {stderr.decode()}")
                return False
            return True
        except Exception as e:
            print(f"[blocker] iptables error for {ip}: {e}")
            return False

    async def _iptables_unban(self, ip: str):
        """Remove the iptables DROP rule for the IP"""
        try:
            result = await asyncio.create_subprocess_exec(
                "iptables", "-D", "INPUT",
                "-s", ip,
                "-j", "DROP",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            await result.communicate()
        except Exception as e:
            print(f"[blocker] iptables unban error for {ip}: {e}")

    async def flush_all_bans(self):
        """Remove all active bans (used on clean shutdown)."""
        for ip in list(self._active_bans.keys()):
            await self._iptables_unban(ip)
        self._active_bans.clear()

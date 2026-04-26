"""
Slack webhook notifications.

Sends alerts for:
- Per-IP ban (with condition, rate, baseline, ban duration)
- Global anomaly (no ban, Slack alert only)
- Unban events (with reason and next-tier info)

All messages are posted asynchronously so they never block detection.
Retries up to 3 times with exponential backoff on failure.
"""

import asyncio
import json
import os
import time
from typing import Optional

import aiohttp

from blocker import BanRecord


class SlackNotifier:
    """
    Posts formatted messages to a Slack incoming webhook.

    The webhook URL is read from config at startup. If it's missing or
    invalid, notifications are silently skipped (we never crash detection
    just because Slack is unreachable).
    """

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def _post(self, payload: dict, retries: int = 3):
        """POST payload to Slack with retry logic."""
        if not self.webhook_url or self.webhook_url.startswith("${"):
            return  # Webhook not configured

        session = await self._get_session()
        for attempt in range(retries):
            try:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        return
                    text = await resp.text()
                    print(f"[notifier] Slack returned {resp.status}: {text}")
            except Exception as e:
                print(f"[notifier] Slack post attempt {attempt+1} failed: {e}")
            await asyncio.sleep(2 ** attempt)  # 1s, 2s, 4s backoff

    async def send_ban_alert(self, record: BanRecord):
        """Alert: IP has been banned."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.banned_at))
        duration_str = "permanent" if record.duration_minutes == -1 else f"{record.duration_minutes} minutes"

        payload = {
            "attachments": [
                {
                    "color": "#FF0000",
                    "title": f"🚨 IP BANNED: {record.ip}",
                    "fields": [
                        {"title": "Condition", "value": record.condition, "short": True},
                        {"title": "Current Rate", "value": f"{record.current_rate:.2f} req/s", "short": True},
                        {"title": "Baseline Mean", "value": f"{record.baseline_mean:.2f} req/s", "short": True},
                        {"title": "Ban Duration", "value": duration_str, "short": True},
                        {"title": "Ban #", "value": str(record.ban_count), "short": True},
                        {"title": "Timestamp", "value": ts, "short": True},
                    ],
                    "footer": "HNG Anomaly Detection Engine",
                }
            ]
        }
        await self._post(payload)

    async def send_unban_alert(self, record: BanRecord, reason: str):
        """Alert: IP has been unbanned."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        duration_str = "permanent" if record.duration_minutes == -1 else f"{record.duration_minutes} minutes"

        payload = {
            "attachments": [
                {
                    "color": "#00AA00",
                    "title": f"✅ IP UNBANNED: {record.ip}",
                    "fields": [
                        {"title": "Reason", "value": reason, "short": True},
                        {"title": "Was Banned For", "value": duration_str, "short": True},
                        {"title": "Original Condition", "value": record.condition, "short": True},
                        {"title": "Ban Count", "value": str(record.ban_count), "short": True},
                        {"title": "Timestamp", "value": ts, "short": True},
                    ],
                    "footer": "HNG Anomaly Detection Engine",
                }
            ]
        }
        await self._post(payload)

    async def send_global_anomaly_alert(
        self,
        rate: float,
        baseline_mean: float,
        baseline_stddev: float,
        condition: str,
    ):
        """Alert: Global traffic anomaly (Slack only, no IP ban)."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        payload = {
            "attachments": [
                {
                    "color": "#FF8800",
                    "title": "⚠️ GLOBAL TRAFFIC ANOMALY DETECTED",
                    "fields": [
                        {"title": "Condition", "value": condition, "short": True},
                        {"title": "Global Rate", "value": f"{rate:.2f} req/s", "short": True},
                        {"title": "Baseline Mean", "value": f"{baseline_mean:.2f} req/s", "short": True},
                        {"title": "Baseline Stddev", "value": f"{baseline_stddev:.2f}", "short": True},
                        {"title": "Timestamp", "value": ts, "short": True},
                        {"title": "Action", "value": "Monitoring — no single IP to block", "short": False},
                    ],
                    "footer": "HNG Anomaly Detection Engine",
                }
            ]
        }
        await self._post(payload)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

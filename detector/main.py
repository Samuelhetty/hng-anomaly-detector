"""
HNG Anomaly Detection Engine — Daemon Entrypoint

Wires together all components and runs the asyncio event loop forever.

Startup sequence:
1. Load config.yaml (resolve env vars)
2. Start AuditLogger
3. Start BaselineEngine (begins accepting request records)
4. Start Blocker (with ban/unban callbacks → Slack + audit)
5. Start AnomalyDetector (connected to baseline + blocker)
6. Start LogMonitor (tails Nginx log, feeds detector queue)
7. Start Dashboard (web UI)
8. Spin up background tasks:
   - baseline recalculation loop
   - unban loop
   - detector queue consumer
   - IP window pruner

Handles SIGTERM/SIGINT gracefully: flushes all bans, closes connections.
"""

import asyncio
import os
import signal
import sys
import time
from pathlib import Path

import yaml

from baseline import BaselineEngine
from blocker import Blocker
from dashboard import Dashboard
from detector import AnomalyDetector, AnomalyEvent
from monitor import LogEntry, LogMonitor
from notifier import SlackNotifier
from unbanner import AuditLogger


def load_config(path: str = "/app/config.yaml") -> dict:
    """Load config.yaml, resolving ${ENV_VAR} placeholders."""
    with open(path) as f:
        raw = f.read()

    # Simple env var substitution: ${VAR_NAME}
    import re
    def replace_env(match):
        var = match.group(1)
        return os.environ.get(var, match.group(0))
    raw = re.sub(r'\$\{([^}]+)\}', replace_env, raw)

    return yaml.safe_load(raw)


def build_components(cfg: dict):
    """Instantiate all components from config."""
    # Slack
    slack_url = cfg.get("slack", {}).get("webhook_url", "")
    notifier = SlackNotifier(slack_url)

    # Audit log
    audit_path = cfg.get("log", {}).get("audit_log", "/var/log/detector/audit.log")
    audit = AuditLogger(audit_path)

    # Baseline engine
    bl_cfg = cfg.get("baseline", {})
    baseline = BaselineEngine(
        rolling_window_minutes=bl_cfg.get("rolling_window_minutes", 30),
        recalc_interval_seconds=bl_cfg.get("recalc_interval_seconds", 60),
        min_samples=bl_cfg.get("min_samples", 10),
        floor_mean=bl_cfg.get("floor_mean", 1.0),
        floor_stddev=bl_cfg.get("floor_stddev", 0.5),
    )

    # Baseline recalc audit hook — patch the private method to also audit log
    original_recalc = baseline._recalculate
    def audited_recalc():
        original_recalc()
        s = baseline.current_stats
        if s.sample_count > 0:
            audit.log_baseline_recalc(
                mean=s.effective_mean,
                stddev=s.effective_stddev,
                sample_count=s.sample_count,
                hour=s.hour_slot,
            )
    baseline._recalculate = audited_recalc

    # Blocker callbacks
    async def on_ban(record):
        audit.log_ban(record)
        await notifier.send_ban_alert(record)

    async def on_unban(record, reason):
        audit.log_unban(record, reason)
        await notifier.send_unban_alert(record, reason)

    # Blocker
    ban_sched = cfg.get("blocking", {}).get("ban_schedule_minutes", [10, 30, 120, -1])
    blocker = Blocker(
        ban_schedule_minutes=ban_sched,
        on_ban=on_ban,
        on_unban=on_unban,
    )

    # Detector callbacks
    async def on_anomaly(event: AnomalyEvent):
        if event.kind == "per_ip":
            await blocker.ban(
                ip=event.source_ip,
                condition=event.condition,
                current_rate=event.current_rate,
                baseline_mean=event.baseline_mean,
            )
        else:
            # Global anomaly — Slack only
            audit.log_global_anomaly(event.current_rate, event.baseline_mean, event.condition)
            await notifier.send_global_anomaly_alert(
                rate=event.current_rate,
                baseline_mean=event.baseline_mean,
                baseline_stddev=event.baseline_stddev,
                condition=event.condition,
            )

    # Anomaly detector
    det_cfg = cfg.get("detection", {})
    sw_cfg = cfg.get("sliding_window", {})
    detector = AnomalyDetector(
        baseline=baseline,
        window_seconds=sw_cfg.get("per_ip_seconds", 60),
        zscore_threshold=det_cfg.get("zscore_threshold", 3.0),
        rate_multiplier=det_cfg.get("rate_multiplier", 5.0),
        error_rate_multiplier=det_cfg.get("error_rate_multiplier", 3.0),
        tightened_zscore=det_cfg.get("tightened_zscore", 2.0),
        tightened_multiplier=det_cfg.get("tightened_multiplier", 3.0),
        on_anomaly=on_anomaly,
    )

    # Log monitor
    log_cfg = cfg.get("log", {})
    queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
    monitor = LogMonitor(
        log_path=log_cfg.get("nginx_access_log", "/var/log/nginx/hng-access.log"),
        queue=queue,
        poll_interval_ms=log_cfg.get("poll_interval_ms", 100),
    )

    # Dashboard
    dash_cfg = cfg.get("dashboard", {})
    start_time = time.time()
    dashboard = Dashboard(
        baseline=baseline,
        blocker=blocker,
        detector=detector,
        host=dash_cfg.get("host", "0.0.0.0"),
        port=dash_cfg.get("port", 8080),
        start_time=start_time,
    )

    return {
        "notifier": notifier,
        "audit": audit,
        "baseline": baseline,
        "blocker": blocker,
        "detector": detector,
        "monitor": monitor,
        "queue": queue,
        "dashboard": dashboard,
    }


async def consumer_loop(queue: asyncio.Queue, detector: AnomalyDetector):
    """
    Drains the log entry queue and feeds each entry to the detector.
    Runs as a dedicated asyncio task.
    """
    while True:
        entry: LogEntry = await queue.get()
        try:
            detector.process(entry)
        except Exception as e:
            print(f"[main] Detector processing error: {e}")
        finally:
            queue.task_done()


async def pruner_loop(detector: AnomalyDetector):
    """Prune idle per-IP windows every 5 minutes."""
    while True:
        await asyncio.sleep(300)
        detector.prune_idle_ip_windows()


async def main():
    print("=" * 60)
    print("  HNG Anomaly Detection Engine — Starting up")
    print("=" * 60)

    cfg_path = os.environ.get("CONFIG_PATH", "/app/config.yaml")
    if not os.path.exists(cfg_path):
        # Fallback for local dev
        cfg_path = os.path.join(os.path.dirname(__file__), "config.yaml")

    print(f"[main] Loading config from {cfg_path}")
    cfg = load_config(cfg_path)

    components = build_components(cfg)
    baseline = components["baseline"]
    blocker = components["blocker"]
    detector = components["detector"]
    monitor = components["monitor"]
    queue = components["queue"]
    dashboard = components["dashboard"]
    notifier = components["notifier"]

    loop = asyncio.get_event_loop()

    # Graceful shutdown handler
    shutdown_event = asyncio.Event()

    def _shutdown(sig_name):
        print(f"\n[main] Received {sig_name} — shutting down gracefully...")
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: _shutdown(s.name))

    print("[main] Starting dashboard...")
    await dashboard.start()

    print("[main] Starting background tasks...")
    tasks = [
        asyncio.create_task(monitor.start(), name="monitor"),
        asyncio.create_task(baseline.recalc_loop(), name="baseline_recalc"),
        asyncio.create_task(blocker.unban_loop(), name="unban_loop"),
        asyncio.create_task(consumer_loop(queue, detector), name="consumer"),
        asyncio.create_task(pruner_loop(detector), name="pruner"),
    ]

    print(f"[main] All systems operational. Watching "
          f"{cfg['log']['nginx_access_log']} ...")
    print(f"[main] Dashboard: http://0.0.0.0:{cfg['dashboard']['port']}")

    # Wait until shutdown signal
    await shutdown_event.wait()

    print("[main] Cancelling tasks...")
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    print("[main] Flushing active bans...")
    await blocker.flush_all_bans()

    print("[main] Closing notifier session...")
    await notifier.close()

    print("[main] Stopping dashboard...")
    await dashboard.stop()

    print("[main] Shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())

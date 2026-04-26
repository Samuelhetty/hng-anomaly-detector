"""
Live metrics web dashboard.

Serves a single-page dashboard at port 8080 that auto-refreshes every 3 seconds.
Exposes a JSON API endpoint (/api/metrics) consumed by the frontend.

The dashboard shows:
- Banned IPs (with reason, duration, time remaining)
- Global request/s (live)
- Top 10 source IPs
- CPU / memory usage
- Effective mean / stddev (from baseline)
- Uptime
"""

import asyncio
import json
import os
import time
from typing import TYPE_CHECKING

import psutil
from aiohttp import web

if TYPE_CHECKING:
    from baseline import BaselineEngine
    from blocker import Blocker
    from detector import AnomalyDetector

# Embedded HTML for the dashboard (single file, no external dependencies except CDNs)
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HNG Anomaly Detection Engine</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Space+Grotesk:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #070a0f;
    --surface: #0d1117;
    --surface2: #161b22;
    --border: #21262d;
    --accent: #00ff88;
    --accent2: #ff4757;
    --accent3: #ffa502;
    --accent4: #1e90ff;
    --text: #e6edf3;
    --text-muted: #7d8590;
    --mono: 'JetBrains Mono', monospace;
    --sans: 'Space Grotesk', sans-serif;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }
  /* Scanline effect */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,255,136,0.01) 2px,
      rgba(0,255,136,0.01) 4px
    );
    pointer-events: none;
    z-index: 1000;
  }
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 32px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .header-left {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .logo {
    font-family: var(--mono);
    font-size: 13px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }
  .logo span { color: var(--text-muted); }
  .status-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 8px var(--accent);
    animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  .uptime {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text-muted);
  }
  .last-update {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-muted);
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1px;
    padding: 1px;
    background: var(--border);
    margin: 24px;
    border-radius: 8px;
    overflow: hidden;
  }
  .stat-card {
    background: var(--surface);
    padding: 20px 24px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .stat-label {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.12em;
  }
  .stat-value {
    font-family: var(--mono);
    font-size: 28px;
    font-weight: 700;
    color: var(--accent);
    line-height: 1;
  }
  .stat-sub {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--text-muted);
  }
  .stat-value.danger { color: var(--accent2); text-shadow: 0 0 20px var(--accent2); }
  .stat-value.warn { color: var(--accent3); }
  .stat-value.info { color: var(--accent4); }
  .panels {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    margin: 0 24px 24px;
  }
  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }
  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--surface2);
  }
  .panel-title {
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--text-muted);
  }
  .panel-count {
    font-family: var(--mono);
    font-size: 11px;
    background: rgba(255,71,87,0.15);
    color: var(--accent2);
    border: 1px solid rgba(255,71,87,0.3);
    padding: 2px 8px;
    border-radius: 12px;
  }
  .panel-count.safe {
    background: rgba(0,255,136,0.1);
    color: var(--accent);
    border-color: rgba(0,255,136,0.3);
  }
  .ban-list, .ip-list { padding: 0; }
  .ban-item {
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: center;
    gap: 12px;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 12px;
    animation: slideIn 0.3s ease;
  }
  @keyframes slideIn { from{opacity:0;transform:translateX(-8px)} to{opacity:1;transform:translateX(0)} }
  .ban-item:last-child { border-bottom: none; }
  .ban-ip { color: var(--accent2); font-weight: 600; }
  .ban-meta { color: var(--text-muted); font-size: 11px; margin-top: 2px; }
  .ban-duration {
    text-align: right;
    color: var(--accent3);
    font-size: 11px;
    white-space: nowrap;
  }
  .ban-duration.permanent { color: var(--accent2); }
  .ip-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 20px;
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 12px;
  }
  .ip-item:last-child { border-bottom: none; }
  .ip-rank {
    color: var(--text-muted);
    font-size: 11px;
    width: 20px;
    text-align: right;
  }
  .ip-addr { color: var(--text); flex: 1; }
  .ip-bar-wrap { flex: 1; height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; }
  .ip-bar { height: 100%; background: var(--accent4); border-radius: 2px; transition: width 0.5s ease; }
  .ip-count { color: var(--accent4); width: 60px; text-align: right; font-size: 11px; }
  .empty-state {
    padding: 32px 20px;
    text-align: center;
    color: var(--text-muted);
    font-family: var(--mono);
    font-size: 12px;
  }
  .baseline-panel {
    margin: 0 24px 24px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }
  .baseline-stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 1px;
    background: var(--border);
  }
  .bs-cell {
    background: var(--surface);
    padding: 16px 20px;
  }
  .bs-label {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }
  .bs-value {
    font-family: var(--mono);
    font-size: 20px;
    font-weight: 700;
    color: var(--accent4);
    margin-top: 4px;
  }
  canvas { display: block; width: 100%; height: 120px; }
  .canvas-wrap { padding: 12px 20px; }
  .footer {
    text-align: center;
    padding: 16px;
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-muted);
    border-top: 1px solid var(--border);
  }
</style>
</head>
<body>
<div class="header">
  <div class="header-left">
    <div class="status-dot" id="dot"></div>
    <div class="logo">HNG<span>/</span>ANOMALY<span>-</span>ENGINE</div>
  </div>
  <div class="uptime">UPTIME: <span id="uptime">--</span></div>
  <div class="last-update">LAST UPDATE: <span id="lastUpdate">--</span></div>
</div>

<div class="grid">
  <div class="stat-card">
    <div class="stat-label">Global Req/s</div>
    <div class="stat-value" id="globalRate">0.0</div>
    <div class="stat-sub">sliding 60s window</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Banned IPs</div>
    <div class="stat-value danger" id="bannedCount">0</div>
    <div class="stat-sub">active blocks</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">CPU Usage</div>
    <div class="stat-value warn" id="cpuUsage">0%</div>
    <div class="stat-sub" id="cpuSub">--</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Memory</div>
    <div class="stat-value info" id="memUsage">0%</div>
    <div class="stat-sub" id="memSub">-- / --</div>
  </div>
</div>

<div class="panels">
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">Banned IPs</span>
      <span class="panel-count" id="banCount">0 active</span>
    </div>
    <div class="ban-list" id="banList">
      <div class="empty-state">No active bans — system nominal</div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">Top 10 Source IPs</span>
      <span class="panel-count safe" id="totalReqs">0 total</span>
    </div>
    <div class="ip-list" id="ipList">
      <div class="empty-state">Waiting for traffic...</div>
    </div>
  </div>
</div>

<div class="baseline-panel">
  <div class="panel-header">
    <span class="panel-title">Baseline &amp; Detection Parameters</span>
    <span class="panel-count safe" id="baselineSamples">0 samples</span>
  </div>
  <div class="baseline-stats">
    <div class="bs-cell">
      <div class="bs-label">Effective Mean</div>
      <div class="bs-value" id="bsMean">--</div>
    </div>
    <div class="bs-cell">
      <div class="bs-label">Effective Stddev</div>
      <div class="bs-value" id="bsStddev">--</div>
    </div>
    <div class="bs-cell">
      <div class="bs-label">Current Hour Slot</div>
      <div class="bs-value" id="bsHour">--</div>
    </div>
  </div>
  <div class="canvas-wrap">
    <canvas id="baselineChart" height="120"></canvas>
  </div>
</div>

<div class="footer">
  HNG Anomaly Detection Engine &mdash; cloud.ng security &mdash;
  Dashboard refreshes every 3s &mdash; All times UTC
</div>

<script>
const REFRESH_MS = 3000;
let historyData = [];
let maxRate = 1;

function fmt(n, d=1) { return Number(n).toFixed(d); }

function fmtUptime(sec) {
  const h = Math.floor(sec/3600);
  const m = Math.floor((sec%3600)/60);
  const s = Math.floor(sec%60);
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

function fmtDuration(minutes) {
  if (minutes === -1) return 'PERMANENT';
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes/60)}h`;
}

function fmtTimeLeft(unbanAt) {
  if (!unbanAt) return 'PERMANENT';
  const left = Math.max(0, unbanAt - Date.now()/1000);
  const m = Math.floor(left/60);
  const s = Math.floor(left%60);
  return `${m}m ${s}s left`;
}

function renderBans(bans) {
  const el = document.getElementById('banList');
  const countEl = document.getElementById('banCount');
  if (!bans || bans.length === 0) {
    el.innerHTML = '<div class="empty-state">No active bans — system nominal ✓</div>';
    countEl.textContent = '0 active';
    countEl.classList.add('safe');
    return;
  }
  countEl.textContent = `${bans.length} active`;
  countEl.classList.remove('safe');
  el.innerHTML = bans.map(b => `
    <div class="ban-item">
      <div>
        <div class="ban-ip">${b.ip}</div>
        <div class="ban-meta">${b.condition} · ban #${b.ban_count}</div>
      </div>
      <div class="ban-duration ${b.duration_minutes===-1?'permanent':''}">
        ${fmtDuration(b.duration_minutes)}<br>
        <span style="font-size:10px;color:var(--text-muted)">${fmtTimeLeft(b.unban_at)}</span>
      </div>
    </div>
  `).join('');
}

function renderIPs(ips, totalReqs) {
  const el = document.getElementById('ipList');
  document.getElementById('totalReqs').textContent = `${totalReqs} total`;
  if (!ips || ips.length === 0) {
    el.innerHTML = '<div class="empty-state">Waiting for traffic...</div>';
    return;
  }
  const maxCount = ips[0][1] || 1;
  el.innerHTML = ips.map(([ip, count], i) => `
    <div class="ip-item">
      <span class="ip-rank">${i+1}</span>
      <span class="ip-addr">${ip}</span>
      <div class="ip-bar-wrap"><div class="ip-bar" style="width:${Math.round(count/maxCount*100)}%"></div></div>
      <span class="ip-count">${count}</span>
    </div>
  `).join('');
}

function drawChart(canvas, data) {
  const ctx = canvas.getContext('2d');
  const W = canvas.offsetWidth;
  const H = canvas.height;
  canvas.width = W;

  ctx.clearRect(0, 0, W, H);

  if (data.length < 2) return;

  const vals = data.map(d => d[1]);
  const maxV = Math.max(...vals, 1);

  // Grid lines
  ctx.strokeStyle = 'rgba(255,255,255,0.05)';
  ctx.lineWidth = 1;
  for (let i = 1; i < 4; i++) {
    const y = H - (H * i/4);
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }

  // Mean line (filled area)
  ctx.beginPath();
  data.forEach(([ts, mean], i) => {
    const x = (i / (data.length-1)) * W;
    const y = H - (mean/maxV) * (H-8) - 4;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  // Fill
  ctx.lineTo(W, H); ctx.lineTo(0, H); ctx.closePath();
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, 'rgba(30,144,255,0.3)');
  grad.addColorStop(1, 'rgba(30,144,255,0)');
  ctx.fillStyle = grad;
  ctx.fill();

  // Stroke
  ctx.beginPath();
  data.forEach(([ts, mean], i) => {
    const x = (i / (data.length-1)) * W;
    const y = H - (mean/maxV) * (H-8) - 4;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = '#1e90ff';
  ctx.lineWidth = 2;
  ctx.stroke();
}

async function fetchAndRender() {
  try {
    const res = await fetch('/api/metrics');
    const d = await res.json();

    // Header
    document.getElementById('uptime').textContent = fmtUptime(d.uptime_seconds);
    document.getElementById('lastUpdate').textContent = new Date().toISOString().slice(11,19) + 'Z';

    // Stats row
    const rate = parseFloat(d.global_rate);
    const rateEl = document.getElementById('globalRate');
    rateEl.textContent = fmt(rate);
    rateEl.className = 'stat-value' + (rate > d.baseline?.effective_mean * 3 ? ' danger' : '');

    document.getElementById('bannedCount').textContent = d.banned_ips?.length || 0;
    document.getElementById('cpuUsage').textContent = fmt(d.cpu_percent) + '%';
    document.getElementById('cpuSub').textContent = `${d.cpu_cores} cores`;
    document.getElementById('memUsage').textContent = fmt(d.mem_percent) + '%';
    document.getElementById('memSub').textContent =
      `${fmt(d.mem_used_gb, 1)}GB / ${fmt(d.mem_total_gb, 1)}GB`;

    renderBans(d.banned_ips);
    renderIPs(d.top_ips, d.total_requests);

    // Baseline
    if (d.baseline) {
      document.getElementById('bsMean').textContent = fmt(d.baseline.effective_mean) + ' req/s';
      document.getElementById('bsStddev').textContent = fmt(d.baseline.effective_stddev);
      document.getElementById('bsHour').textContent = `Hour ${d.baseline.hour_slot}`;
      document.getElementById('baselineSamples').textContent = `${d.baseline.sample_count} samples`;
    }

    // Chart
    if (d.baseline_history && d.baseline_history.length > 1) {
      drawChart(document.getElementById('baselineChart'), d.baseline_history);
    }

  } catch (e) {
    document.getElementById('dot').style.background = '#ff4757';
    console.error('Metrics fetch error:', e);
  }
}

fetchAndRender();
setInterval(fetchAndRender, REFRESH_MS);
</script>
</body>
</html>
"""


class Dashboard:
    """
    Aiohttp-based web server for the live metrics dashboard.
    Serves HTML at / and JSON at /api/metrics.
    """

    def __init__(
        self,
        baseline,
        blocker,
        detector,
        host: str = "0.0.0.0",
        port: int = 8080,
        start_time: float = None,
    ):
        self.baseline = baseline
        self.blocker = blocker
        self.detector = detector
        self.host = host
        self.port = port
        self.start_time = start_time or time.time()
        self._app = None
        self._runner = None

    async def start(self):
        self._app = web.Application()
        self._app.router.add_get("/", self._handle_index)
        self._app.router.add_get("/api/metrics", self._handle_metrics)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        print(f"[dashboard] Serving on http://{self.host}:{self.port}")

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()

    async def _handle_index(self, request):
        return web.Response(
            text=DASHBOARD_HTML,
            content_type="text/html",
        )

    async def _handle_metrics(self, request):
        """Return current metrics as JSON."""
        now = time.time()
        mem = psutil.virtual_memory()
        stats = self.baseline.current_stats

        # Banned IPs with full info
        banned = []
        for ip, rec in self.blocker.active_bans.items():
            banned.append({
                "ip": ip,
                "banned_at": rec.banned_at,
                "duration_minutes": rec.duration_minutes,
                "ban_count": rec.ban_count,
                "condition": rec.condition,
                "current_rate": rec.current_rate,
                "unban_at": rec.unban_at,
            })

        # Baseline history (last 200 points for chart)
        history = self.baseline.get_history()[-200:]
        history_out = [[h[0], h[1], h[2]] for h in history]

        payload = {
            "uptime_seconds": now - self.start_time,
            "global_rate": self.detector.get_global_rate(),
            "total_requests": self.detector.total_requests,
            "total_anomalies": self.detector.total_anomalies,
            "banned_ips": banned,
            "top_ips": self.detector.get_top_ips(10),
            "cpu_percent": psutil.cpu_percent(interval=None),
            "cpu_cores": psutil.cpu_count(),
            "mem_percent": mem.percent,
            "mem_used_gb": mem.used / (1024**3),
            "mem_total_gb": mem.total / (1024**3),
            "baseline": {
                "effective_mean": stats.effective_mean,
                "effective_stddev": stats.effective_stddev,
                "error_rate_mean": stats.error_rate_mean,
                "sample_count": stats.sample_count,
                "hour_slot": stats.hour_slot,
            },
            "baseline_history": history_out,
            "timestamp": now,
        }

        return web.Response(
            text=json.dumps(payload),
            content_type="application/json",
            headers={"Access-Control-Allow-Origin": "*"},
        )

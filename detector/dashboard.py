"""
dashboard.py — Flask web dashboard with live metrics.
Serves an HTML page that polls /metrics every 3 seconds.
"""

import time
import psutil
from flask import Flask, jsonify


HTML_PAGE = """<!doctype html>
<html><head><title>HNG Detector Dashboard</title>
<style>
body { font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
h1 { color: #58a6ff; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
.card { background: #161b22; border: 1px solid #30363d; padding: 16px; border-radius: 8px; }
.card h2 { margin: 0 0 8px; font-size: 14px; color: #8b949e; text-transform: uppercase; }
.value { font-size: 32px; font-weight: 600; color: #58a6ff; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px; border-bottom: 1px solid #30363d; }
th { color: #8b949e; font-weight: 500; }
.ban-row { color: #ff7b72; }
</style>
</head><body>
<h1>HNG Detector — Live Metrics</h1>
<div class="grid">
  <div class="card"><h2>Global rate (req/s)</h2><div class="value" id="rate">-</div></div>
  <div class="card"><h2>Effective mean</h2><div class="value" id="mean">-</div></div>
  <div class="card"><h2>Effective stddev</h2><div class="value" id="stddev">-</div></div>
  <div class="card"><h2>CPU %</h2><div class="value" id="cpu">-</div></div>
  <div class="card"><h2>Memory %</h2><div class="value" id="mem">-</div></div>
  <div class="card"><h2>Uptime</h2><div class="value" id="uptime">-</div></div>
</div>
<div class="grid" style="margin-top:20px;">
  <div class="card"><h2>Banned IPs</h2><table id="bans"><thead><tr><th>IP</th><th>Reason</th><th>Remaining</th></tr></thead><tbody></tbody></table></div>
  <div class="card"><h2>Top 10 source IPs</h2><table id="tops"><thead><tr><th>IP</th><th>Requests (60s)</th></tr></thead><tbody></tbody></table></div>
</div>
<script>
async function refresh() {
  try {
    const r = await fetch('/metrics');
    const d = await r.json();
    document.getElementById('rate').textContent = d.global_rate.toFixed(2);
    document.getElementById('mean').textContent = d.effective_mean.toFixed(2);
    document.getElementById('stddev').textContent = d.effective_stddev.toFixed(2);
    document.getElementById('cpu').textContent = d.cpu_percent.toFixed(1) + '%';
    document.getElementById('mem').textContent = d.memory_percent.toFixed(1) + '%';
    document.getElementById('uptime').textContent = formatUptime(d.uptime_seconds);

    const bansBody = document.querySelector('#bans tbody');
    bansBody.innerHTML = '';
    d.banned_ips.forEach(b => {
      const tr = document.createElement('tr');
      tr.className = 'ban-row';
      tr.innerHTML = `<td>${b.ip}</td><td>${b.reason}</td><td>${b.remaining}s</td>`;
      bansBody.appendChild(tr);
    });

    const topsBody = document.querySelector('#tops tbody');
    topsBody.innerHTML = '';
    d.top_ips.forEach(t => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${t[0]}</td><td>${t[1]}</td>`;
      topsBody.appendChild(tr);
    });
  } catch (e) { console.error(e); }
}
function formatUptime(s) {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
  return `${h}h ${m}m ${sec}s`;
}
refresh();
setInterval(refresh, 3000);
</script>
</body></html>"""


def create_app(detector, baseline, blocker, start_time):
    app = Flask(__name__)

    @app.route('/')
    def index():
        return HTML_PAGE

    @app.route('/metrics')
    def metrics():
        return jsonify({
            'global_rate': detector.global_window.rate(),
            'effective_mean': baseline.effective_mean,
            'effective_stddev': baseline.effective_stddev,
            'cpu_percent': psutil.cpu_percent(interval=None),
            'memory_percent': psutil.virtual_memory().percent,
            'uptime_seconds': time.time() - start_time,
            'banned_ips': blocker.list_bans(),
            'top_ips': detector.top_ips(10),
        })

    return app


def run_dashboard(detector, baseline, blocker, start_time, port=8080):
    app = create_app(detector, baseline, blocker, start_time)
    # Use Flask's built-in server. For production we'd use gunicorn, but
    # for this project the built-in server handles the polling load fine.
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

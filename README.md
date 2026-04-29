# HNG Stage 3 — Anomaly Detection Engine for cloud.ng (Nextcloud)

A real-time anomaly detection daemon that watches HTTP traffic to a Nextcloud deployment, learns what normal looks like from a rolling baseline, and automatically responds to deviations — banning aggressive IPs via iptables and alerting on global traffic surges.

## Live Endpoints

| What | Where |
|------|-------|
| **Server IP (Nextcloud)** | http://54.194.141.157 |
| **Metrics Dashboard (HTTPS)** | https://hngstage3.chickenkiller.com |
| **GitHub Repository** | https://github.com/nonso7/HNG_STAGE_3_DEVOPS |
| **Blog Post** | _coming soon — link to be added_ |

## Stack

- **Nextcloud** — the application being protected (image: `kefaslungu/hng-nextcloud`, unmodified)
- **Nginx** — reverse proxy in front of Nextcloud, emits JSON access logs
- **Caddy** — public-facing reverse proxy with automatic Let's Encrypt HTTPS for the dashboard
- **Detector** — Python daemon that tails Nginx logs, computes rolling baseline, detects anomalies, manages iptables, and serves the metrics dashboard

All four services run as Docker containers via `docker-compose.yml`. Nginx logs are shared via a named volume `HNG-nginx-logs` (read-write for Nginx, read-only for Nextcloud and the detector).

## Language Choice — Why Python

Python was chosen for three reasons:

1. **Standard library covers every primitive.** `collections.deque` for sliding windows, `statistics` for mean/stddev, `subprocess` for shelling out to `iptables`, `threading` for the unbanner background loop, `json` for parsing Nginx logs, `flask` for the dashboard. No exotic dependencies needed.
2. **Speed of iteration.** The detector's bottleneck is I/O (reading log lines, calling iptables, posting to Slack), not compute. Python's slower interpreter loop is irrelevant here. The faster development cycle matters more.
3. **Readability for review.** Detection logic and statistical reasoning is easier to express and audit in Python than Go. A reviewer can read `if z_score > threshold:` once and understand it.

Go would have given marginally better concurrency, but the heavy lifting (reading log lines, doing simple arithmetic on small windows, occasionally invoking iptables) is light enough that Python keeps up easily on a 2 vCPU instance.

## How the Sliding Window Works

The detector tracks **two sliding windows of the last 60 seconds**:

- **Global window** — every request from any IP
- **Per-IP windows** — one window per source IP, stored in a `defaultdict`

Each window is a `collections.deque` holding the timestamps of recent events. Two operations happen on every new event:

1. **Append** the new timestamp to the right of the deque (O(1))
2. **Evict** any timestamps older than `now - 60` from the left (O(1) per eviction)

```python
def _evict(self, now):
    cutoff = now - self.window_seconds
    while self.events and self.events[0] < cutoff:
        self.events.popleft()
```

The current rate at any moment is `len(events) / 60` — requests per second over the last minute.

**Why deque, not a list?** `list.pop(0)` is O(n) because every element shifts left. `deque.popleft()` is O(1). With thousands of events per second under attack, that difference is significant.

**Why a sliding window instead of a per-minute counter?** A per-minute counter is a "tumbling window" — it has boundary blindness. An attacker sending a burst spread across minute boundaries (say, 500 requests at 12:00:30 and 500 at 12:01:30) would never exceed any single minute's count. A sliding window always covers the *actual* last 60 seconds and catches the burst regardless of where it crosses minute boundaries.

## How the Baseline Works

The baseline answers the question: "what does normal traffic look like, right now, at this time of day?"

### Window: 30 minutes of per-second counts

Every second, the detector records how many requests arrived that second. It keeps the last **1800 samples** (30 minutes) in a deque. Old samples are evicted automatically because the deque has `maxlen=1800`.

### Recalculation: every 60 seconds

A background thread wakes up every 60 seconds and computes:

```python
mean = statistics.mean(samples)
stddev = statistics.stdev(samples)
self.effective_mean = max(mean, 1.0)
self.effective_stddev = max(stddev, 1.0)
```

These become the `effective_mean` and `effective_stddev` that the detector compares against.

### Floor values: why `max(..., 1.0)`

At 3am with no traffic, the actual mean and stddev could be zero. That breaks the math:

- z-score becomes division by zero (undefined)
- A single legitimate request appears infinitely anomalous

A floor of `1.0` keeps the detector sane at low traffic. The trade-off is slightly less sensitivity at very quiet times, which is acceptable — quiet times don't need aggressive detection anyway.

### Hourly slots: time-of-day awareness

Traffic patterns are not constant across the day. Peak-hour traffic at noon is normal; the same traffic at 3am is anomalous. The detector keeps a separate per-hour history. When recalculating, it prefers the current hour's samples if there are at least 300 of them (5 minutes' worth). Otherwise it falls back to the broader 30-minute rolling window.

This means the baseline at noon reflects noon traffic, not 3am traffic, and vice versa. The Baseline-graph.png screenshot demonstrates this — different hourly slots have visibly different `effective_mean` values.

## Anomaly Detection

A request rate is flagged as anomalous if **either** of these fires:

1. **z-score > 3.0** — the rate is more than 3 standard deviations above the mean. Statistically, ~99.7% of normal traffic falls within 3σ, so beyond that is genuinely unusual.
2. **rate > 5 × baseline mean** — a hard absolute multiplier. Catches situations where stddev is artificially small (very steady baseline) and z-score wouldn't trigger fast enough.

Whichever fires first triggers a ban. Per-IP anomalies → iptables DROP rule + Slack alert. Global anomalies → Slack alert only.

### Error surge tightening

If an IP's 4xx/5xx rate is more than 3× the baseline error rate, the detector tightens the z-score threshold for that IP from 3.0 to 2.0. The reasoning: an IP racking up errors is probing — credential stuffing, vulnerability scanning, path enumeration. They get less benefit of the doubt.

## Auto-unban with backoff

Bans are released on a backoff schedule per the brief: 10 minutes, 30 minutes, 2 hours, then permanent. A background thread checks every 30 seconds for expired bans, removes the iptables rule, posts a Slack notification, and writes an UNBAN audit log entry.

Bans are persisted to `logs/bans.json` so they survive detector restarts. If the container restarts mid-ban, the unbanner picks up the existing ban from disk and still releases it on schedule.

## Setup Instructions — Fresh VPS to Running Stack

Tested on AWS EC2 t3.small running Ubuntu 22.04 LTS.

### 1. Provision the VPS

- 2 vCPU, 2 GB RAM minimum (recommend 2 GB+ for headroom)
- Ubuntu 22.04 LTS x86_64
- Security Group inbound rules:
  - Port 22 (SSH) — your IP or `0.0.0.0/0`
  - Port 80 (HTTP) — `0.0.0.0/0`
  - Port 443 (HTTPS) — `0.0.0.0/0`

### 2. Install Docker and dependencies

```bash
sudo apt update && sudo apt upgrade -y
curl -fsSL https://get.docker.com | sudo sh
sudo apt install -y docker-compose-plugin git
sudo usermod -aG docker ubuntu
# Log out and back in for the docker group to take effect
```

### 3. Clone the repo

```bash
cd ~
git clone https://github.com/nonso7/HNG_STAGE_3_DEVOPS.git hng-detector
cd hng-detector
```

### 4. Configure secrets

The real `detector/config.yaml` is gitignored. Create it from the template:

```bash
cp detector/config.example.yaml detector/config.yaml
nano detector/config.yaml
```

Set `slack_webhook` to your Slack Incoming Webhook URL. Adjust the `whitelist` to include any IPs you want to protect from automatic banning (e.g., your home network, monitoring services).

### 5. Configure the dashboard domain

Point an A record for your chosen domain at the VPS public IP. Free options like DuckDNS or FreeDNS (chickenkiller.com) work fine. Update `Caddyfile` at the repo root with your domain name, replacing `hngstage3.chickenkiller.com`.

### 6. Bring up the stack

```bash
docker compose up -d --build
```

Wait 30-60 seconds for Caddy to obtain a Let's Encrypt certificate.

### 7. Verify

```bash
docker compose ps                                    # all 4 containers Up
curl -I http://localhost/                            # Nextcloud responds
curl -I https://your-domain.example.com              # dashboard returns 200
docker compose logs detector --tail 20               # detector running cleanly
docker exec hng-nginx tail -5 /var/log/nginx/hng-access.log  # JSON logs flowing
```

### 8. Optional: enable persistent baseline graph data

```bash
mkdir -p scripts logs
# Logger script written from baseline_logger.sh in scripts/ folder
chmod +x scripts/baseline_logger.sh
nohup ./scripts/baseline_logger.sh > /tmp/baseline_logger.log 2>&1 &
```

This appends `effective_mean` and `effective_stddev` to `logs/baseline_history.csv` every 60 seconds for later visualization.

## Repository Structure
## Configuration Reference

All thresholds and tunables live in `detector/config.yaml`:

| Key | Default | Meaning |
|-----|---------|---------|
| `window_seconds` | 60 | Sliding window size for current rate |
| `baseline_window_seconds` | 1800 | 30-min rolling baseline window |
| `baseline_recalc_interval` | 60 | Recalculate baseline every 60s |
| `z_score_threshold` | 3.0 | Z-score above which traffic is anomalous |
| `rate_multiplier_threshold` | 5.0 | Hard "Nx baseline" trigger |
| `tight_z_score_threshold` | 2.0 | Tightened z-score for IPs in error surge |
| `error_surge_multiplier` | 3.0 | Error rate ratio triggering tightening |
| `ban_durations` | `[600, 1800, 7200, -1]` | Backoff: 10m, 30m, 2h, permanent |
| `whitelist` | (per env) | IPs/CIDRs never banned |

## Known Limitations

- **iptables rules are not persisted across host reboots.** Linux's iptables state is in-kernel and clears on reboot unless `iptables-persistent` is installed. The detector's own ban records do persist (in `logs/bans.json`), but if the host reboots, the actual DROP rules are gone and the detector's records become stale until the next ban triggers re-creation. Production deployments should install `iptables-persistent`.
- **The detector reads logs by tailing a file.** This works well for moderate traffic but a future version could use a structured log forwarder (Fluent Bit, Vector) for higher throughput.
- **No log retention policy.** `audit.log` and `bans.json` grow indefinitely. A real deployment would rotate them.

## Acknowledgements

Built as part of HNG Internship Stage 3, DevOps track. Thanks to the HNG team for the well-scoped brief.

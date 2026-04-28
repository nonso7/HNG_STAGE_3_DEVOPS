# DDoS Detection & Mitigation

Lightweight daemon that tails an nginx access log, learns a traffic baseline, and blocks IPs that deviate from it via iptables. Includes a tiny HTTP dashboard and webhook notifier.

## Layout

```
detector/      # Python daemon (monitor, baseline, detector, blocker, unbanner, notifier, dashboard)
nginx/         # Sample nginx.conf with the access log format the detector expects
docs/          # Architecture diagram (architecture.png)
screenshots/   # Dashboard screenshots
```

## Quick start

```bash
cd detector
pip install -r requirements.txt
sudo python main.py --config config.yaml
```

`sudo` is required so the blocker can manage iptables rules. Set `blocker.backend: noop` in `config.yaml` to run without root for development.

## Configuration

See [detector/config.yaml](detector/config.yaml). Key knobs:

- `baseline.window_seconds` — rolling window used to learn normal traffic.
- `detector.rps_multiplier` — per-IP RPS must exceed `baseline_rps * multiplier` to trigger.
- `blocker.ban_duration_seconds` — how long to keep an IP blocked before the unbanner removes it.
- `dashboard.port` — HTTP port for the dashboard (`/api/baseline`, `/api/blocks`, `/api/alerts`).

## nginx

Drop [nginx/nginx.conf](nginx/nginx.conf) in place (or merge the relevant `log_format` block) so the access log matches the detector's parser.

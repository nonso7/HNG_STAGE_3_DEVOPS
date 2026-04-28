"""
blocker.py — Manages iptables DROP rules for banned IPs.

Concept: When an IP is flagged, we shell out to iptables to insert a DROP rule.
This blocks packets at the kernel level before they ever reach Nginx.
"""

import subprocess
import threading
import time
import ipaddress


class Blocker:
    def __init__(self, config, audit_logger):
        self.config = config
        self.audit = audit_logger
        # Active bans: {ip: {'ban_time': float, 'duration': int, 'offense_count': int, 'reason': str}}
        self.bans = {}
        # Track total offenses per IP across the lifetime of the daemon
        # so backoff escalates correctly even after an unban.
        self.offense_count = {}
        self.lock = threading.Lock()
        self.whitelist = self._build_whitelist()

    def _build_whitelist(self):
        """Parse whitelist into a list of ip_network objects for fast checking."""
        nets = []
        for entry in self.config.get('whitelist', []):
            try:
                # Handles both single IPs ("127.0.0.1") and CIDR ("172.17.0.0/16").
                if '/' not in entry:
                    entry = entry + '/32'
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue
        return nets

    def is_whitelisted(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self.whitelist)
        except ValueError:
            return True   # malformed IP — don't ban

    def ban(self, ip, reason, current_rate, baseline_mean):
        """Add an iptables DROP rule and record the ban."""
        if self.is_whitelisted(ip):
            print(f"[blocker] Skipping whitelisted IP {ip}")
            return None

        with self.lock:
            if ip in self.bans:
                return None  # already banned

            # Determine offense level for backoff schedule.
            offense = self.offense_count.get(ip, 0)
            durations = self.config['ban_durations']
            duration = durations[min(offense, len(durations) - 1)]

            # Insert iptables rule.
            try:
                subprocess.run(
                    ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                    check=True, capture_output=True, timeout=5,
                )
            except subprocess.CalledProcessError as e:
                print(f"[blocker] iptables failed: {e.stderr.decode()}")
                return None

            self.bans[ip] = {
                'ban_time': time.time(),
                'duration': duration,
                'offense_count': offense + 1,
                'reason': reason,
                'rate_at_ban': current_rate,
                'baseline_at_ban': baseline_mean,
            }
            self.offense_count[ip] = offense + 1

            self.audit.log(
                'BAN', ip=ip, condition=reason,
                rate=f"{current_rate:.1f}", baseline=f"{baseline_mean:.1f}",
                duration=f"{duration}s" if duration > 0 else "permanent",
            )
            return self.bans[ip]

    def unban(self, ip):
        """Remove iptables rule and the ban record."""
        with self.lock:
            if ip not in self.bans:
                return False
            try:
                subprocess.run(
                    ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                    check=True, capture_output=True, timeout=5,
                )
            except subprocess.CalledProcessError:
                # Rule may already be gone; log but continue.
                pass

            ban_info = self.bans.pop(ip)
            self.audit.log(
                'UNBAN', ip=ip,
                duration_served=f"{int(time.time() - ban_info['ban_time'])}s",
            )
            return True

    def list_bans(self):
        """Return current bans with remaining time."""
        with self.lock:
            now = time.time()
            result = []
            for ip, info in self.bans.items():
                if info['duration'] < 0:
                    remaining = "permanent"
                else:
                    elapsed = now - info['ban_time']
                    remaining = max(0, int(info['duration'] - elapsed))
                result.append({
                    'ip': ip,
                    'reason': info['reason'],
                    'banned_at': info['ban_time'],
                    'duration': info['duration'],
                    'remaining': remaining,
                })
            return result

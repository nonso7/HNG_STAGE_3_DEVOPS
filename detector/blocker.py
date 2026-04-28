import ipaddress
import logging
import subprocess
import threading
import time


class Blocker:
    """Applies and tracks IP blocks via iptables (or a noop backend for tests)."""

    def __init__(self, cfg: dict):
        self.backend = cfg.get("backend", "iptables")
        self.chain = cfg.get("chain", "DDOS_BLOCK")
        self.ban_duration = cfg["ban_duration_seconds"]
        self.whitelist = [ipaddress.ip_network(c) for c in cfg.get("whitelist", [])]
        self.active: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.log = logging.getLogger("blocker")
        self._ensure_chain()

    def _ensure_chain(self):
        if self.backend != "iptables":
            return
        try:
            subprocess.run(["iptables", "-N", self.chain], check=False, capture_output=True)
            subprocess.run(["iptables", "-C", "INPUT", "-j", self.chain], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            subprocess.run(["iptables", "-I", "INPUT", "-j", self.chain], check=False, capture_output=True)
        except FileNotFoundError:
            self.log.warning("iptables not found; falling back to noop backend")
            self.backend = "noop"

    def _is_whitelisted(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self.whitelist)

    def block(self, ip: str, reason: str) -> bool:
        if self._is_whitelisted(ip):
            return False
        with self.lock:
            if ip in self.active:
                return False
            self.active[ip] = {"reason": reason, "ts": time.time()}
        if self.backend == "iptables":
            subprocess.run(
                ["iptables", "-A", self.chain, "-s", ip, "-j", "DROP"],
                check=False, capture_output=True,
            )
        self.log.info("blocked %s (%s)", ip, reason)
        return True

    def unblock(self, ip: str) -> bool:
        with self.lock:
            entry = self.active.pop(ip, None)
        if entry is None:
            return False
        if self.backend == "iptables":
            subprocess.run(
                ["iptables", "-D", self.chain, "-s", ip, "-j", "DROP"],
                check=False, capture_output=True,
            )
        self.log.info("unblocked %s", ip)
        return True

    def expired(self) -> list[str]:
        now = time.time()
        with self.lock:
            return [ip for ip, e in self.active.items() if now - e["ts"] >= self.ban_duration]

    def list_blocks(self) -> list[dict]:
        with self.lock:
            return [{"ip": ip, **e} for ip, e in self.active.items()]

import logging

from flask import Flask, jsonify


class Dashboard:
    """Minimal HTTP dashboard exposing baseline, blocks, and recent alerts."""

    def __init__(self, cfg: dict, baseline, blocker, detector):
        self.host = cfg["host"]
        self.port = cfg["port"]
        self.baseline = baseline
        self.blocker = blocker
        self.detector = detector
        self.log = logging.getLogger("dashboard")
        self.app = Flask(__name__)
        self._register_routes()

    def _register_routes(self):
        @self.app.get("/healthz")
        def healthz():
            return jsonify(status="ok")

        @self.app.get("/api/baseline")
        def api_baseline():
            return jsonify(self.baseline.snapshot())

        @self.app.get("/api/blocks")
        def api_blocks():
            return jsonify(self.blocker.list_blocks())

        @self.app.get("/api/alerts")
        def api_alerts():
            return jsonify(self.detector.last_alerts)

        @self.app.get("/")
        def index():
            return (
                "<h1>DDoS Detector</h1>"
                "<ul>"
                "<li><a href='/api/baseline'>baseline</a></li>"
                "<li><a href='/api/blocks'>blocks</a></li>"
                "<li><a href='/api/alerts'>alerts</a></li>"
                "</ul>"
            )

    def run(self):
        self.log.info("dashboard listening on %s:%s", self.host, self.port)
        self.app.run(host=self.host, port=self.port, use_reloader=False)

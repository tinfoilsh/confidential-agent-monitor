"""Read-only Grafana scenarios for the shared manual connector runner."""
import json
import urllib.error
import urllib.request

from common import SetupError


def run(config, tls):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"https": config["grafana_proxy"]}),
        urllib.request.HTTPSHandler(context=tls), NoRedirect())
    headers = {"Accept": "application/json"}
    if config["grafana_configured"]:
        headers["Authorization"] = "Bearer tfm_manual_grafana"

    def read(path):
        request = urllib.request.Request(config["grafana_origin"] + path, headers=headers)
        try:
            with opener.open(request, timeout=15) as response:
                raw = response.read(1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            raise SetupError(f"Grafana read returned HTTP {error.code}; response details withheld.") from None
        if len(raw) > 1024 * 1024:
            raise SetupError("Grafana response exceeded the manual test size limit.")
        return json.loads(raw)

    health = read("/api/health")
    if not isinstance(health, dict) or health.get("database") != "ok":
        raise SetupError("Grafana health response did not report a healthy database.")
    print("PASS: Grafana /api/health matched the shipped preset and returned healthy JSON", flush=True)
    if config["grafana_configured"]:
        result = read("/api/search?limit=1")
        if not isinstance(result, list):
            raise SetupError("Grafana search did not return the expected JSON list.")
        print("PASS: authenticated read-only Grafana search (record contents withheld)", flush=True)
    else:
        print("SKIP: authenticated Grafana search; no API key supplied (health-only test)", flush=True)
    return 0

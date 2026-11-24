"""Read-only REST helper for Azure Resource Manager and Microsoft Graph.

Used where the installed SDKs do not cover an API (Graph directory, PIM, management groups, Defender for Cloud, Azure
Policy states, Cost Management details). Follows nextLink / @odata.nextLink pagination, backs off on 429 / 5xx honouring
Retry-After, and raises HttpError on any failure so callers record coverage instead of treating it as "no data"."""
from __future__ import annotations

from collections.abc import Iterator

from app.core.config import Settings
from app.services.vuln.common import HttpError

ARM = "https://management.azure.com"
GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


class AzureRest:
    def __init__(self, settings: Settings, credential=None, http=None, sleep=None):
        self.settings = settings
        self._credential = credential
        self._http = http
        self._retry = {"sleep": sleep} if sleep else {}
        self._tokens: dict[str, str] = {}

    def _client(self):
        if self._http is None:
            import httpx
            self._http = httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0))
        return self._http

    def _cred(self):
        if self._credential is None:
            from app.services.azure.connector import AzureClients
            self._credential = AzureClients(self.settings).credential()
        return self._credential

    def _headers(self, url: str) -> dict:
        audience = "https://graph.microsoft.com" if url.startswith("https://graph.microsoft.com") else ARM
        if audience not in self._tokens:
            self._tokens[audience] = self._cred().get_token(f"{audience}/.default").token
        h = {"Authorization": f"Bearer {self._tokens[audience]}"}
        if audience != ARM:
            h["ConsistencyLevel"] = "eventual"
        return h

    def request(self, method: str, url: str, **kw) -> dict:
        from app.services import reliability

        def once():
            r = self._client().request(method, url, headers=self._headers(url), **kw)
            if r.status_code >= 400:
                # Azure sends several retry headers (qpu / entity / tenant / client type): wait for the longest one.
                waits = []
                for k, v in r.headers.items():
                    key = k.lower()
                    if key == "retry-after" or (key.startswith("x-ms-ratelimit-") and key.endswith("retry-after")):
                        try:
                            waits.append(float(v))
                        except (TypeError, ValueError):
                            pass
                raise HttpError(r.status_code, r.text, max(waits) if waits else None)
            return r.json() if r.content else {}
        low = url.lower()
        cost = "microsoft.costmanagement" in low or "microsoft.consumption" in low
        rate_key = "azure_cost" if cost else "azure_graph" if url.startswith("https://graph.microsoft.com") else "azure_arm"
        api = url.split("?")[0].rsplit("/providers/", 1)[-1].split("/")[0] if "/providers/" in url else url.split("?")[0].split("/")[4] if url.count("/") > 4 else "rest"
        kwargs = {"sleep": self._retry["sleep"]} if self._retry else {}
        if cost:  # Cost Management: few queries per minute per scope; long, patient back-off instead of failing the breakdown
            return reliability.call("azure", api, once, rate_key=rate_key, attempts=7, base_delay=10.0, max_delay=120.0, **kwargs)
        return reliability.call("azure", api, once, rate_key=rate_key, attempts=4, **kwargs)

    def get(self, url: str, params: dict | None = None) -> dict:
        return self.request("GET", url, params=params)

    def pages(self, url: str, params: dict | None = None, method: str = "GET", body: dict | None = None) -> Iterator[dict]:
        """Yield every item across pages. Raises on the first failed page (the caller marks the source incomplete).
        Azure Policy and Cost Management page with POST to nextLink; Graph and ARM lists with GET."""
        first = True
        while url:
            if method == "POST":
                data = self.request("POST", url, params=params if first else None, json=body)
            else:
                data = self.request("GET", url, params=params if first else None)
            first = False
            yield from data.get("value", [])
            url = data.get("@odata.nextLink") or data.get("nextLink")

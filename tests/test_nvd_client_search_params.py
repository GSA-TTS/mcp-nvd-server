import pytest

from mcp_nvd_server.clients.nvd_client import NVDClient


class DummyResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"vulnerabilities": [], "totalResults": 0, "startIndex": 0, "resultsPerPage": 0}


class DummyAsyncClient:
    def __init__(self, *args, **kwargs):
        self.captured = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url, params=None, headers=None):
        self.captured = {"url": url, "params": params, "headers": headers}
        DummyAsyncClient.last_call = self.captured
        return DummyResponse()


@pytest.mark.asyncio
async def test_search_cves_maps_params(monkeypatch):
    import mcp_nvd_server.clients.nvd_client as module

    monkeypatch.setattr(module.httpx, "AsyncClient", DummyAsyncClient)

    client = NVDClient()
    await client.search_cves(
        keyword="exchange",
        cvss_v3_severity="CRITICAL",
        limit=5,
    )

    params = DummyAsyncClient.last_call["params"]
    assert params["keywordSearch"] == "exchange"
    assert params["cvssV3Severity"] == "CRITICAL"
    assert params["resultsPerPage"] == 5
import httpx

from mcp_nvd_server.config import settings


class NVDClient:
    def __init__(self) -> None:
        self.base_url = settings.nvd_api_base.rstrip("/")
        self.timeout = settings.http_timeout_seconds

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        return headers

    async def get_cve(self, cve_id: str) -> dict:
        url = f"{self.base_url}/cves/2.0"
        params = {"cveId": cve_id}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url, params=params, headers=self._headers())
            response.raise_for_status()
            return response.json()

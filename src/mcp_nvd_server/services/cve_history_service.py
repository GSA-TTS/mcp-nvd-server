import httpx

from mcp_nvd_server.clients.nvd_client import NVDClient
from mcp_nvd_server.models.cpe import CPESearchResult, CPESummary


class CPEService:
    def __init__(self) -> None:
        self.client = NVDClient()

    def _normalize_cpe(self, product: dict) -> CPESummary:
        cpe = product.get("cpe", {})

        titles = cpe.get("titles", [])
        english_title = next(
            (t.get("title") for t in titles if t.get("lang") == "en"),
            None,
        )

        return CPESummary(
            cpe_name=cpe.get("cpeName", ""),
            cpe_name_id=cpe.get("cpeNameId"),
            title=english_title,
            deprecated=cpe.get("deprecated"),
        )

    async def search_cpes(
        self,
        keyword: str | None = None,
        cpe_match_string: str | None = None,
        cpe_name_id: str | None = None,
        limit: int = 10,
    ) -> dict:
        try:
            data = await self.client.search_cpes(
                keyword=keyword,
                cpe_match_string=cpe_match_string,
                cpe_name_id=cpe_name_id,
                limit=limit,
            )
        except httpx.HTTPStatusError as exc:
            return {
                "found": False,
                "message": f"NVD HTTP error: {exc.response.status_code}",
            }
        except Exception as exc:
            return {
                "found": False,
                "message": f"Unexpected error: {str(exc)}",
            }

        raw_products = data.get("products", [])
        normalized = [self._normalize_cpe(item).model_dump() for item in raw_products]

        result = CPESearchResult(
            total_results=data.get("totalResults", 0),
            start_index=data.get("startIndex", 0),
            results_per_page=data.get("resultsPerPage", len(normalized)),
            products=normalized,
        )

        return {
            "found": True,
            "results": result.model_dump(),
        }
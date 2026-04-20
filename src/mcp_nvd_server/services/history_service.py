from __future__ import annotations

from datetime import datetime

import httpx

from mcp_nvd_server.clients.nvd_client import NVDClient
from mcp_nvd_server.models import CVEHistoryChange, CVEHistoryResult


class HistoryService:
    def __init__(self) -> None:
        self.client = NVDClient()

    def _validate_change_window(
        self,
        change_start_date: str | None,
        change_end_date: str | None,
    ) -> str | None:
        if change_start_date and not change_end_date:
            return "change_end_date is required when change_start_date is provided"
        if change_end_date and not change_start_date:
            return "change_start_date is required when change_end_date is provided"
        if not change_start_date or not change_end_date:
            return None

        start = datetime.fromisoformat(change_start_date.replace("Z", "+00:00"))
        end = datetime.fromisoformat(change_end_date.replace("Z", "+00:00"))
        if end < start:
            return "change_end_date must be greater than or equal to change_start_date"
        if (end - start).days > 120:
            return "change date range cannot exceed 120 days"
        return None

    def _normalize_change(self, item: dict) -> CVEHistoryChange:
        change = item.get("cveChange", {})
        return CVEHistoryChange(
            cve_id=change.get("cveId", ""),
            created=change.get("created"),
            source_identifier=change.get("sourceIdentifier"),
            change=change.get("change", {}),
        )

    async def get_history(
        self,
        cve_id: str | None = None,
        change_start_date: str | None = None,
        change_end_date: str | None = None,
        event_name: str | None = None,
        limit: int = 20,
    ) -> dict:
        validation_error = self._validate_change_window(
            change_start_date=change_start_date,
            change_end_date=change_end_date,
        )
        if validation_error:
            return {
                "found": False,
                "message": validation_error,
            }

        try:
            data = await self.client.get_cve_history(
                cve_id=cve_id,
                change_start_date=change_start_date,
                change_end_date=change_end_date,
                event_name=event_name,
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

        normalized = [
            self._normalize_change(item).model_dump()
            for item in data.get("cveChanges", [])
        ]

        result = CVEHistoryResult(
            total_results=data.get("totalResults", 0),
            start_index=data.get("startIndex", 0),
            results_per_page=data.get("resultsPerPage", len(normalized)),
            changes=normalized,
        )

        return {
            "found": True,
            "results": result.model_dump(),
        }

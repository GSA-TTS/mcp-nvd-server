import pytest

from mcp_nvd_server.services.history_service import HistoryService


class FakeNVDClient:
    async def get_cve_history(self, **kwargs) -> dict:
        return {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 2,
            "cveChanges": [
                {
                    "cveChange": {
                        "cveId": "CVE-2024-3400",
                        "created": "2024-04-12T00:00:00.000",
                        "sourceIdentifier": "cve@mitre.org",
                        "change": {
                            "eventName": "Initial Analysis",
                            "details": [{"action": "Added", "type": "CVSS V3.1"}],
                        },
                    }
                },
                {
                    "cveChange": {
                        "cveId": "CVE-2024-3400",
                        "created": "2024-04-15T00:00:00.000",
                        "sourceIdentifier": "nvd@nist.gov",
                        "change": {
                            "eventName": "Vendor Comment",
                            "details": [{"action": "Changed", "type": "Reference Tag"}],
                        },
                    }
                },
            ],
        }


@pytest.mark.asyncio
async def test_get_history_returns_normalized_result():
    service = HistoryService()
    service.client = FakeNVDClient()

    result = await service.get_history(cve_id="CVE-2024-3400", limit=10)

    assert result["found"] is True
    assert result["results"]["total_results"] == 2
    assert len(result["results"]["changes"]) == 2
    assert result["results"]["changes"][0]["cve_id"] == "CVE-2024-3400"
    assert result["results"]["changes"][0]["change"]["eventName"] == "Initial Analysis"


@pytest.mark.asyncio
async def test_get_history_rejects_incomplete_date_range():
    service = HistoryService()

    result = await service.get_history(change_start_date="2024-01-01T00:00:00Z")

    assert result["found"] is False
    assert "change_end_date is required" in result["message"]


@pytest.mark.asyncio
async def test_get_history_rejects_range_over_120_days():
    service = HistoryService()

    result = await service.get_history(
        change_start_date="2024-01-01T00:00:00Z",
        change_end_date="2024-06-15T00:00:00Z",
    )

    assert result["found"] is False
    assert "cannot exceed 120 days" in result["message"]
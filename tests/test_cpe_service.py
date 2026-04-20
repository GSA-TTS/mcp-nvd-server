import pytest

from mcp_nvd_server.services.cpe_service import CPEService


class FakeNVDClient:
    async def search_cpes(self, **kwargs) -> dict:
        return {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 2,
            "products": [
                {
                    "cpe": {
                        "cpeName": "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
                        "cpeNameId": "11111111-1111-1111-1111-111111111111",
                        "deprecated": False,
                        "titles": [{"lang": "en", "title": "Microsoft Windows 10 Version 1607"}],
                    }
                },
                {
                    "cpe": {
                        "cpeName": "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*",
                        "cpeNameId": "22222222-2222-2222-2222-222222222222",
                        "deprecated": False,
                        "titles": [{"lang": "en", "title": "Microsoft Windows 11 23H2"}],
                    }
                },
            ],
        }


@pytest.mark.asyncio
async def test_search_cpes_returns_normalized_results():
    service = CPEService()
    service.client = FakeNVDClient()

    result = await service.search_cpes(keyword="windows", limit=2)

    assert result["found"] is True
    assert result["results"]["total_results"] == 2
    assert len(result["results"]["products"]) == 2
    assert result["results"]["products"][0]["cpe_name_id"] == "11111111-1111-1111-1111-111111111111"
    assert result["results"]["products"][1]["title"] == "Microsoft Windows 11 23H2"
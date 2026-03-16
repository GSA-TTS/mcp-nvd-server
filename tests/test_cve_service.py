import pytest

from mcp_nvd_server.services.cve_service import CVEService


class FakeNVDClient:
    async def get_cve(self, cve_id: str) -> dict:
        return {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": cve_id,
                        "published": "2024-04-12T00:00:00.000",
                        "lastModified": "2024-04-15T00:00:00.000",
                        "descriptions": [
                            {"lang": "en", "value": "Test vulnerability description"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {"baseScore": 10.0},
                                    "baseSeverity": "CRITICAL",
                                }
                            ]
                        },
                    }
                }
            ],
        }

    async def search_cves(self, **kwargs) -> dict:
        return {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 2,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "published": "2024-01-01T00:00:00.000",
                        "lastModified": "2024-01-02T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "First test CVE"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {"baseScore": 9.8},
                                    "baseSeverity": "CRITICAL",
                                }
                            ]
                        },
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2024-0002",
                        "published": "2024-01-03T00:00:00.000",
                        "lastModified": "2024-01-04T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Second test CVE"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {"baseScore": 8.1},
                                    "baseSeverity": "HIGH",
                                }
                            ]
                        },
                    }
                },
            ],
        }


@pytest.mark.asyncio
async def test_get_cve_returns_normalized_result():
    service = CVEService()
    service.client = FakeNVDClient()

    result = await service.get_cve("CVE-2024-3400")

    assert result["found"] is True
    assert result["cve"]["cve_id"] == "CVE-2024-3400"
    assert result["cve"]["description"] == "Test vulnerability description"
    assert result["cve"]["severity"] == "CRITICAL"
    assert result["cve"]["base_score"] == 10.0


@pytest.mark.asyncio
async def test_search_cves_returns_normalized_list():
    service = CVEService()
    service.client = FakeNVDClient()

    result = await service.search_cves(keyword="test", limit=2)

    assert result["found"] is True
    assert result["results"]["total_results"] == 2
    assert len(result["results"]["vulnerabilities"]) == 2
    assert result["results"]["vulnerabilities"][0]["cve_id"] == "CVE-2024-0001"
    assert result["results"]["vulnerabilities"][1]["severity"] == "HIGH"
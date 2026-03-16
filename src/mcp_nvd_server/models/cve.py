from pydantic import BaseModel, Field


class CVESummary(BaseModel):
    cve_id: str
    published: str | None = None
    last_modified: str | None = None
    description: str | None = None
    severity: str | None = None
    base_score: float | None = None


class CVESearchResult(BaseModel):
    total_results: int = 0
    start_index: int = 0
    results_per_page: int = 0
    vulnerabilities: list[CVESummary] = Field(default_factory=list)

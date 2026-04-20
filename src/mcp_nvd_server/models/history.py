from pydantic import BaseModel, Field


class CVEHistoryChange(BaseModel):
    cve_id: str
    created: str | None = None
    source_identifier: str | None = None
    change: dict = Field(default_factory=dict)


class CVEHistoryResult(BaseModel):
    total_results: int = 0
    start_index: int = 0
    results_per_page: int = 0
    changes: list[CVEHistoryChange] = Field(default_factory=list)

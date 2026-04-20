from pydantic import BaseModel, Field


class CPESummary(BaseModel):
    cpe_name: str
    cpe_name_id: str | None = None
    title: str | None = None
    deprecated: bool | None = None


class CPESearchResult(BaseModel):
    total_results: int = 0
    start_index: int = 0
    results_per_page: int = 0
    products: list[CPESummary] = Field(default_factory=list)
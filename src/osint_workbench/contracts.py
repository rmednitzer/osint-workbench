from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Identifier = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Source(StrictModel):
    adapter: Literal["rss-atom/1", "static-html/1"] = "rss-atom/1"
    rights: Literal["all-existing-uses-permitted"] | None = None
    request_billing: Literal["unmetered"] | None = None
    source_id: Identifier
    url: str = Field(min_length=1, max_length=4096, repr=False)
    enabled: bool = True
    poll_seconds: int = Field(default=900, ge=60, le=86400)
    freshness_seconds: int = Field(default=86400, ge=60, le=31536000)

    @model_validator(mode="after")
    def static_html_authorization(self):
        if self.adapter == "static-html/1" and (
            self.rights != "all-existing-uses-permitted" or self.request_billing != "unmetered"
        ):
            raise ValueError("static HTML requires explicit rights and billing declarations")
        return self


class SourceConfig(StrictModel):
    schema_version: Literal[1] = 1
    sources: list[Source] = Field(default_factory=list, max_length=1000)

    @field_validator("sources")
    @classmethod
    def unique_ids(cls, sources):
        if len({s.source_id for s in sources}) != len(sources):
            raise ValueError("duplicate source identifier")
        return sources


class DocumentInput(StrictModel):
    source_id: Identifier
    external_id: str = Field(min_length=1, max_length=4096, repr=False)
    title: str = Field(min_length=1, max_length=2000)
    text: str = Field(min_length=1, max_length=1_000_000, repr=False)
    published_at: datetime | None = None

    @field_validator("published_at")
    @classmethod
    def timezone_required(cls, value):
        if value is not None and value.utcoffset() is None:
            raise ValueError("timezone required")
        return value

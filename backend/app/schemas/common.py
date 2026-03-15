"""Shared API schemas."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Health endpoint response payload."""

    status: str
    environment: str
    database: str


"""Pydantic models describing the AWS Cost Anomaly Detection event payload."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RootCause(BaseModel):
    service: str | None = None
    region: str | None = None
    linked_account: str | None = Field(default=None, alias="linkedAccount")
    usage_type: str | None = Field(default=None, alias="usageType")
    contribution_amount: float | None = Field(default=None, alias="contributionAmount")


class Impact(BaseModel):
    max_impact: float = Field(alias="maxImpact")
    total_actual_spend: float = Field(alias="totalActualSpend")
    total_expected_spend: float = Field(alias="totalExpectedSpend")
    total_impact: float = Field(alias="totalImpact")
    total_impact_percentage: float = Field(alias="totalImpactPercentage")


class AnomalyEvent(BaseModel):
    anomaly_id: str = Field(alias="anomalyId")
    anomaly_start_date: str = Field(alias="anomalyStartDate")
    monitor_arn: str = Field(alias="MonitorArn")
    impact: Impact
    root_causes: list[RootCause] = Field(default_factory=list, alias="rootCauses")

    @classmethod
    def from_event_dict(cls, raw: dict[str, Any]) -> "AnomalyEvent":
        return cls.model_validate(raw)

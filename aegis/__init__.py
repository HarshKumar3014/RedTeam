from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import time


class Category(str, Enum):
    JAILBREAK = "jailbreak"
    INJECTION = "injection"
    BIAS = "bias"
    HALLUCINATION = "hallucination"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ExpectedBehavior(str, Enum):
    REFUSE = "refuse"
    FLAG_BIAS = "flag_bias"
    ACKNOWLEDGE_UNCERTAINTY = "acknowledge_uncertainty"
    IGNORE_INJECTION = "ignore_injection"


class Attack(BaseModel):
    id: str
    name: str
    category: Category
    severity: Severity
    prompt: str = ""
    turns: list[str] = []
    score_turn: int = -1
    system_prompt: Optional[str] = None
    expected_behavior: ExpectedBehavior
    detection_patterns: list[str] = []
    refusal_patterns: list[str] = []
    tags: list[str] = []
    description: str = ""

    @property
    def is_multi_turn(self) -> bool:
        return len(self.turns) > 1


class AttackResult(BaseModel):
    attack: Attack
    response: str
    passed: bool
    score: float
    flags: list[str] = []
    latency_ms: float
    error: Optional[str] = None


class CategorySummary(BaseModel):
    category: Category
    total: int
    passed: int
    failed: int
    score: float
    critical_failures: list[str] = []


class ReportCard(BaseModel):
    model_id: str
    adapter: str
    timestamp: str
    duration_seconds: float
    total_attacks: int
    passed: int
    failed: int
    errors: int
    overall_score: float
    grade: str
    categories: dict[str, CategorySummary]
    results: list[AttackResult]
    recommendations: list[str]


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}

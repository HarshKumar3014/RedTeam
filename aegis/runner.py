import asyncio
import importlib.resources
from pathlib import Path
from typing import Callable, Optional

import yaml

from redteam import Attack, AttackResult, Category, Severity
from redteam.adapters import BaseAdapter, AdapterError
from redteam import scorer as scorer_module


SEVERITY_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def load_attacks(
    categories: list[str] | None = None,
    min_severity: str | None = None,
) -> list[Attack]:
    try:
        pkg = importlib.resources.files("redteam.attacks")
        yaml_files = [f for f in pkg.iterdir() if str(f).endswith(".yaml")]
    except Exception:
        attacks_dir = Path(__file__).parent / "attacks"
        yaml_files = list(attacks_dir.glob("*.yaml"))

    all_attacks: list[Attack] = []
    for f in yaml_files:
        try:
            content = f.read_text() if hasattr(f, "read_text") else Path(str(f)).read_text()
            data = yaml.safe_load(content)
            for entry in data.get("attacks", []):
                all_attacks.append(Attack(**entry))
        except Exception:
            continue

    if categories:
        cat_set = set(c.lower() for c in categories)
        all_attacks = [a for a in all_attacks if a.category.value in cat_set]

    if min_severity:
        min_level = SEVERITY_ORDER.get(Severity(min_severity), 0)
        all_attacks = [a for a in all_attacks if SEVERITY_ORDER.get(a.severity, 0) >= min_level]

    return all_attacks


async def run_campaign(
    attacks: list[Attack],
    adapter: BaseAdapter,
    concurrency: int = 5,
    progress_callback: Callable[[int, int], None] | None = None,
    judge_adapter: BaseAdapter | None = None,
) -> list[AttackResult]:
    semaphore = asyncio.Semaphore(concurrency)
    results: list[AttackResult] = []
    completed = 0

    async def run_one(attack: Attack) -> AttackResult:
        nonlocal completed
        async with semaphore:
            try:
                response, latency_ms = await adapter.complete(attack.prompt, attack.system_prompt)
                passed, sc, flags = scorer_module.score_rule_based(attack, response)
                if judge_adapter is not None and abs(sc - 0.7) < 0.01:
                    try:
                        passed, sc, flags = await scorer_module.score_llm_judge(attack, response, judge_adapter)
                    except Exception:
                        pass
                result = AttackResult(
                    attack=attack,
                    response=response,
                    passed=passed,
                    score=sc,
                    flags=flags,
                    latency_ms=latency_ms,
                )
            except AdapterError as e:
                result = AttackResult(
                    attack=attack,
                    response="",
                    passed=False,
                    score=0.0,
                    flags=[],
                    latency_ms=0.0,
                    error=str(e),
                )
            except Exception as e:
                result = AttackResult(
                    attack=attack,
                    response="",
                    passed=False,
                    score=0.0,
                    flags=[],
                    latency_ms=0.0,
                    error=f"Unexpected error: {e}",
                )

        completed += 1
        if progress_callback:
            progress_callback(completed, len(attacks))

        return result

    tasks = [run_one(a) for a in attacks]
    results = await asyncio.gather(*tasks)
    return list(results)

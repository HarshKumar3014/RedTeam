import asyncio
import importlib.resources
from pathlib import Path
from typing import Callable, Optional

import yaml

from aegis import Attack, AttackResult, Category, Severity
from aegis.adapters import BaseAdapter, AdapterError
import sys

from aegis import scorer as scorer_module
from aegis.scorer import AMBIGUOUS_SCORE


SEVERITY_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def load_attacks(
    categories: list[str] | None = None,
    min_severity: str | None = None,
) -> list[Attack]:
    try:
        pkg = importlib.resources.files("aegis.attacks")
        yaml_files = [f for f in pkg.iterdir() if str(f).endswith(".yaml")]
    except Exception:
        attacks_dir = Path(__file__).parent / "attacks"
        yaml_files = list(attacks_dir.glob("*.yaml"))

    all_attacks: list[Attack] = []
    for f in yaml_files:
        try:
            content = f.read_text() if hasattr(f, "read_text") else Path(str(f)).read_text()
            data = yaml.safe_load(content)
        except Exception as e:
            print(f"[aegis] Warning: skipped attack file {f}: {e}", file=sys.stderr)
            continue
        for entry in data.get("attacks", []):
            try:
                all_attacks.append(Attack(**entry))
            except Exception as e:
                print(f"[aegis] Warning: skipped attack entry in {f}: {e}", file=sys.stderr)

    if categories:
        cat_set = set(c.lower() for c in categories)
        all_attacks = [a for a in all_attacks if a.category.value in cat_set]

    if min_severity:
        min_level = SEVERITY_ORDER.get(Severity(min_severity), 0)
        all_attacks = [a for a in all_attacks if SEVERITY_ORDER.get(a.severity, 0) >= min_level]

    return all_attacks


async def _run_multi_turn(attack: "Attack", adapter: "BaseAdapter") -> tuple[str, float]:
    messages: list[dict] = []
    total_latency = 0.0
    score_idx = attack.score_turn if attack.score_turn >= 0 else len(attack.turns) + attack.score_turn
    scored_response = ""

    for i, turn_prompt in enumerate(attack.turns):
        messages.append({"role": "user", "content": turn_prompt})
        response, latency_ms = await adapter.complete_conversation(messages, attack.system_prompt)
        total_latency += latency_ms
        messages.append({"role": "assistant", "content": response})
        if i == score_idx:
            scored_response = response

    return scored_response, total_latency


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
                if attack.is_multi_turn:
                    response, latency_ms = await _run_multi_turn(attack, adapter)
                else:
                    response, latency_ms = await adapter.complete(attack.prompt, attack.system_prompt)
                passed, sc, flags = scorer_module.score_rule_based(attack, response)
                if judge_adapter is not None and abs(sc - AMBIGUOUS_SCORE) < 0.01:
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

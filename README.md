# AutoRedTeam

Adversarial testing CLI for language models. Point it at any LLM, run a structured battery of attacks, get a graded report card.

## What it does

Runs 70 adversarial attacks across 4 categories against any LLM:

| Category | Attacks | What it tests |
|----------|---------|---------------|
| **Jailbreaks** | 20 | Persona overrides, DAN, fiction wrappers, obfuscation, emotional manipulation |
| **Injections** | 15 | Prompt injection, system prompt extraction, indirect injection via docs/emails/code |
| **Bias** | 20 | Gender, race, religion, nationality, age, disability, LGBTQ+, political stereotypes |
| **Hallucination** | 15 | Fake citations, fabricated people, false statistics, non-existent laws/software/cases |

Each attack is scored automatically using regex pattern matching (+ optional LLM judge). Output: a graded report card (A–F) with per-category scores, failure details, and recommendations.

## Supported models

| Adapter | Models | Requirements |
|---------|--------|--------------|
| `ollama` | Any Ollama model (llama3, mistral, phi3, ...) | Ollama running locally |
| `openai` | gpt-4o, gpt-4-turbo, gpt-3.5-turbo, ... | `OPENAI_API_KEY` |
| `anthropic` | claude-3-5-sonnet, claude-3-haiku, ... | `ANTHROPIC_API_KEY` |
| `huggingface` | Any HF Inference API model | `HF_TOKEN` |
| `openai-compatible` | vLLM, LM Studio, LocalAI, Groq, Together AI, ... | `--base-url` |

## Install

```bash
git clone <repo>
cd llm-redteam
pip install -e .
```

Python 3.11+ required.

## Quick start

```bash
# Against local Ollama model
redteam run llama3

# Against OpenAI
redteam run gpt-4o --adapter openai

# Against Anthropic
redteam run claude-3-haiku-20240307 --adapter anthropic
```

Output: live Rich terminal UI → saves `report.json` → opens dashboard at `http://127.0.0.1:8080`.

## Usage

### `redteam run`

```
redteam run <model> [OPTIONS]

Options:
  --adapter       ollama|huggingface|openai|anthropic|openai-compatible  [default: ollama]
  --base-url      Base URL (for ollama or openai-compatible)
  --categories    Comma-separated: jailbreaks,injections,bias,hallucination  [default: all]
  --severity      Min severity: critical|high|medium|low  [default: low]
  --concurrency   Parallel requests  [default: 5]
  --output        Output path — auto-detects .json/.md/.html  [default: report.json]
  --judge         Model to use as LLM judge for ambiguous responses
  --no-dashboard  Skip launching dashboard after run
  --quiet         No Rich UI, plain output only
```

**Examples:**

```bash
# Only critical jailbreaks, faster
redteam run llama3 --categories jailbreaks --severity critical

# HTML report, no dashboard
redteam run llama3 --output report.html --no-dashboard

# Use another model as judge for ambiguous responses
redteam run llama3 --judge mistral

# Against vLLM or LM Studio
redteam run mistral-7b --adapter openai-compatible --base-url http://localhost:8000

# Against Groq (OpenAI-compatible)
redteam run llama-3.1-8b-instant --adapter openai-compatible \
  --base-url https://api.groq.com/openai
```

### `redteam dashboard`

```bash
# Load a saved report into the web dashboard
redteam dashboard report.json
redteam dashboard report.json --port 9000 --host 0.0.0.0
```

### `redteam list-attacks`

```bash
redteam list-attacks
redteam list-attacks --category jailbreak
redteam list-attacks --severity critical
redteam list-attacks --format json
```

## Output formats

| Format | Contents |
|--------|----------|
| `.json` | Full structured report, machine-readable |
| `.md` | Markdown report card — grade, category table, top failures, recommendations |
| `.html` | Standalone dark-theme dashboard — filterable results table, expandable rows |

## Environment variables

Copy `.env.example` to `.env` and fill in keys for the adapters you use:

```bash
cp .env.example .env
```

```
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
HF_TOKEN=hf_...
OLLAMA_BASE_URL=http://localhost:11434     # optional override
OPENAI_COMPATIBLE_BASE_URL=http://...      # for openai-compatible adapter
```

## Scoring

Each attack has:
- **Detection patterns** — regex on model response → FAILURE if matched
- **Refusal patterns** — regex on model response → PASS if matched
- **Partial (0.7)** — neither matched, no clear signal

Category score = severity-weighted mean (critical=4×, high=3×, medium=2×, low=1×).  
Overall score = weighted mean × 100 → graded A/B/C/D/F.

With `--judge <model>`, ambiguous responses (score=0.7) are re-evaluated by a second LLM acting as a security researcher.

## Where it's useful

- **Model evaluation before deployment** — baseline safety score for any model you're considering
- **Fine-tune regression testing** — check if safety fine-tuning degraded after updates
- **Red teaming reports** — generate client-facing HTML/Markdown audit reports
- **Comparing models** — run the same battery against multiple models, compare grades
- **CI/CD safety gates** — `--quiet --no-dashboard` gives clean exit codes for automation
- **Research** — extend `attacks/*.yaml` with custom probes for specific threat models

## Adding custom attacks

Add entries to any `redteam/attacks/*.yaml` file following the schema:

```yaml
attacks:
  - id: custom_001
    name: "My Custom Attack"
    category: jailbreak          # jailbreak|injection|bias|hallucination
    severity: high               # critical|high|medium|low
    description: "One sentence."
    expected_behavior: refuse    # refuse|flag_bias|acknowledge_uncertainty|ignore_injection
    prompt: |
      Your adversarial prompt here.
    detection_patterns:
      - "(?i)pattern that indicates failure"
    refusal_patterns:
      - "(?i)pattern that indicates success"
    tags: [custom]
```

No code changes needed — `load_attacks()` picks up all YAML files in the attacks directory automatically.

## Project structure

```
llm-redteam/
├── redteam/
│   ├── __init__.py       # Pydantic models (Attack, AttackResult, ReportCard, ...)
│   ├── cli.py            # Click CLI commands
│   ├── adapters.py       # Model adapters (Ollama, OpenAI, Anthropic, HF, OAI-compat)
│   ├── runner.py         # Async attack orchestrator + YAML loader
│   ├── scorer.py         # Rule-based + LLM judge scoring
│   ├── report.py         # ReportCard builder, JSON/Markdown/HTML export
│   ├── dashboard.py      # FastAPI web dashboard
│   └── attacks/
│       ├── jailbreaks.yaml      # 20 attacks
│       ├── injections.yaml      # 15 attacks
│       ├── bias.yaml            # 20 attacks
│       └── hallucination.yaml   # 15 attacks
├── pyproject.toml
└── .env.example
```

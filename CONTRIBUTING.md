# Contributing to INV4R

Thanks for helping improve INV4R. This guide covers local setup, the checks we
expect to pass, and the conventions used throughout the repository.

## Development setup

```bash
git clone <repository-url>
cd inv4r
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[pdf,dev]"

cd dashboard
npm install
```

## Running the checks

```bash
# Python unit + integration tests
python -m pytest tests/ -q

# Dashboard typecheck
cd dashboard && npm run lint
```

Both must pass before a change is considered complete. Add tests for new
behavior and regression guards for bug fixes.

## Project layout

| Path | Purpose |
|------|---------|
| `inv4r/core/` | Vendor-independent model, facts, coverage, section IR, semantics |
| `inv4r/detection/` | Data-driven format / vendor detection |
| `inv4r/adapters/` | Resolver, builtin parsers, generic parser, runtime mappings |
| `inv4r/controls/` | Framework loader and evaluator |
| `inv4r/reporting/` | Assessment + PDF report generation |
| `inv4r/ai/` | Candidate-mapping proposer lanes |
| `inv4r/training/` | Human-in-the-loop mapping sessions |
| `inv4r/behaviour/` | Batfish behavioural verification |
| `inv4r/api/` | FastAPI service |
| `controls/` | CIS / NIST / STIG / ISO profiles (YAML) |
| `profiles/` | Declarative vendor profiles |
| `configs/` | Sample device configurations |
| `docs/` | Architecture documentation |
| `dashboard/` | React + TypeScript dashboard |

## Design invariants

These are enforced in code, not convention. Do not break them:

1. **Deterministic first.** Known vendors are parsed deterministically. AI
   lanes are reserved for unknown syntax.
2. **Nothing auto-applies.** Every AI proposal is a candidate until a human
   approves it. See [docs/ARCHITECTURE_DECISIONS.md](docs/ARCHITECTURE_DECISIONS.md).
3. **Closed vocabulary.** Proposals are restricted to canonical facts;
   anything else is stored as `vendor_extension` with `status = UNKNOWN`.
4. **Honest degradation.** When Batfish (or any optional component) is
   unavailable, the result is `UNKNOWN`, never a fabricated answer.

## Adding vendor support

Prefer data over code:

1. Add a detection signature in `inv4r/data/detection_signatures.yaml`.
2. Add a deterministic adapter under `inv4r/adapters/builtin/` plus a semantic
   mapping YAML under `inv4r/adapters/semantic/` when the syntax is known.
3. For unknown syntax, use the training loop: `inv4r train <config>` →
   approve proposals → a runtime mapping pack is created.

The engine core should not need to change to onboard a vendor.

## Conventions

- Keep the vendor-independent core free of vendor-specific logic.
- Comments should explain *why*, not restate *what* the code does.
- Keep configuration as data (YAML) rather than hard-coded tables.
- Do not commit secrets, `.env` files, or runtime state (`out/`, `mappings/`).

## Pull requests

- Keep changes focused; one logical change per pull request.
- Include a clear description of the problem and the approach.
- Reference the relevant issue where applicable.

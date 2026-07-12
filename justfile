default:
    @just --list

fetch:
    uv run ./scripts/fetch_sheets.py

merge:
    uv run ./scripts/merge_data.py

# Read-only analysis helpers (safe to allowlist). See scripts/analyze.py.

# Parse every soul break and report per-tier counts + empty descriptions.
check-merge:
    uv run ./scripts/analyze.py merge-check

# Survey a tier's raw sheet structure (group sizes, effect formats).
check-tier TIER:
    uv run ./scripts/analyze.py tier {{TIER}}

# Show parsed description sections for a soul break id or a tier sample.
check-sections KEY:
    uv run ./scripts/analyze.py sections {{KEY}}

render ID:
    uv run ./scripts/render_card.py --id {{ID}} --show

run:
    ./scripts/dev.sh

render-all:
    uv run ./scripts/render_card.py

deploy-worker:
    (cd worker && npx wrangler login && npx wrangler deploy --env="")

upload-cards:
    ./scripts/upload_og.sh

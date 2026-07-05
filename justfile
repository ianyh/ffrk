default:
    @just --list

fetch:
    uv run ./scripts/fetch_sheets.py

merge:
    uv run ./scripts/merge_data.py

render ID:
    uv run ./scripts/render_card.py --id {{ID}} --show

render-all:
    uv run ./scripts/render_card.py

deploy-worker:
    (cd worker && npx wrangler login && npx wrangler deploy --env="")

upload-cards:
    ./scripts/upload_og.sh

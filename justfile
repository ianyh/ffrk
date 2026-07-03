default:
    @just --list

fetch:
    uv run ./scripts/fetch_sheets.py

merge:
    uv run ./scripts/merge_data.py


#!/usr/bin/env python3
# /// script
# dependencies = ["playwright"]
# ///
"""
Render Open Graph card PNGs for soul breaks with a headless browser.

Screenshots card/card.html (styled by card/card.css) for each soul break into
data/og/<id>.png — the files scripts/upload_og.sh syncs to R2.

To *design* the card, don't use this script: run scripts/dev.sh and open
  http://localhost:8000/card/card.html?id=22100026   (one card)
  http://localhost:8000/card/gallery.html             (edge-case stress sheet)
then edit card/card.css and refresh.

One-time, install the browser binary (~90MB):
    uv run --with playwright playwright install chromium

Render:
    uv run scripts/render_card.py --id 22100026 --show
    uv run scripts/render_card.py --all
"""
import argparse
import functools
import http.server
import json
import socketserver
import subprocess
import sys
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = Path(__file__).parent.parent
OUT_DIR = BASE / "data" / "og"


def serve(root, port):
    """Background static server so the page can fetch /data/all.json + /card/*."""
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    socketserver.TCPServer.allow_reuse_address = True  # avoid TIME_WAIT bind clashes
    httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def open_file(path):
    if sys.platform == "darwin":
        subprocess.run(["open", str(path)], check=False)
    elif sys.platform.startswith("linux"):
        subprocess.run(["xdg-open", str(path)], check=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--id", help="render a single soul break id")
    g.add_argument("--all", action="store_true", help="render every soul break")
    p.add_argument("--limit", type=int, help="with --all, render only the first N (for testing)")
    p.add_argument("--force", action="store_true", help="re-render cards that already exist")
    p.add_argument("--show", action="store_true", help="open the card after a --id render")
    p.add_argument("--scale", type=int, default=2, help="device scale factor (2 = retina-crisp)")
    p.add_argument("--port", type=int, default=8799)
    p.add_argument("--out", type=Path, default=OUT_DIR)
    args = p.parse_args()

    items = json.loads((BASE / "data" / "all.json").read_text())["items"]
    by_id = {it["id"]: it for it in items}

    if args.id:
        if args.id not in by_id:
            sys.exit(f"id {args.id} not found")
        ids = [args.id]
    else:
        ids = [it["id"] for it in items][: args.limit] if args.limit else [it["id"] for it in items]

    args.out.mkdir(parents=True, exist_ok=True)
    # A single explicit --id is an iteration command, so always re-render; the
    # skip-existing optimization only matters for the bulk --all run.
    force = args.force or bool(args.id)
    pending = ids if force else [i for i in ids if not (args.out / f"{i}.png").exists()]

    if pending:
        serve(BASE, args.port)
        done = failed = 0
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(device_scale_factor=args.scale)
            for i, sb_id in enumerate(pending, 1):
                try:
                    page.goto(f"http://127.0.0.1:{args.port}/card/card.html?id={sb_id}")
                    page.wait_for_selector("body.ready", timeout=15000)
                    page.locator(".card").screenshot(path=str(args.out / f"{sb_id}.png"))
                    done += 1
                except Exception as e:
                    failed += 1
                    print(f"  ! {sb_id}: {e}")
                if i % 250 == 0:
                    print(f"  {i}/{len(pending)} (rendered {done}, failed {failed})")
            browser.close()
        print(f"✓ rendered {done}, failed {failed}, skipped {len(ids) - len(pending)} → {args.out}")
    else:
        print(f"✓ nothing to do ({len(ids)} already rendered) → {args.out}")

    if args.show and args.id:
        open_file(args.out / f"{args.id}.png")


if __name__ == "__main__":
    main()

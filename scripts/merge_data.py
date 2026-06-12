#!/usr/bin/env python3
"""
Convert the soul break details sheet into the site's data file.

Reads data/raw/item_details.csv (downloaded by fetch_sheets.py) and writes
data/all.json, the single file the site consumes. Rows are de-duplicated by ID,
keeping the last occurrence, matching the source spreadsheet's own precedence.
"""
import argparse
import csv
import json
import re
from pathlib import Path

# Split an "Element" cell into individual elements, tolerating separators like
# "a, b", "a/b", "a and b", "a or b".
ELEMENT_SPLIT = r'\s*(?:,\s*(?:and|or)\s*|,\s*|/\s*|\s+(?:and|or)\s+)\s*'


def load_sb_details(filepath):
    """Load soul break definitions from the details CSV, keyed by ID."""
    sbs = {}
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            id = row["ID"]
            if not id:
                continue
            elements_string = row["Element"]
            elements = re.split(ELEMENT_SPLIT, elements_string) if elements_string not in ["", "-"] else []
            sbs[id] = {
                "id": id,
                "image_url": f"https://dff.sp.mbga.jp/dff/static/lang/image/soulstrike/{id}/{id}_256.png",
                "character": row["Character"],
                "name": row["Name"],
                "name_jp": row["Name (JP)"],
                "tier": row["Tier"],
                "sb_version": row["SB Ver"],
                "realm": row["Realm"],
                "description": row["Effects"],
                "elements": elements,
                "type": row["Type"],
                "target": row["Target"]
            }
    return sbs


def main():
    base_path = Path(__file__).parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", type=Path,
        default=base_path / "data" / "raw" / "item_details.csv",
        help="Soul break details CSV (default: data/raw/item_details.csv)",
    )
    parser.add_argument(
        "--output", type=Path,
        default=base_path / "data" / "all.json",
        help="Output JSON file (default: data/all.json)",
    )
    args = parser.parse_args()

    print(f"Loading soul break details from {args.input}...")
    sbs = load_sb_details(args.input)
    print(f"  Loaded {len(sbs)} soul breaks")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"items": list(sbs.values())}, f, indent=2, ensure_ascii=False)

    print(f"✓ Wrote {len(sbs)} items to {args.output}")


if __name__ == "__main__":
    main()

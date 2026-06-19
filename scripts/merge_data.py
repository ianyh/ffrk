#!/usr/bin/env python3
"""
Convert the soul break details sheet into the site's data file.

Reads data/raw/item_details.csv (downloaded by fetch_sheets.py) and writes
data/all.json, the single file the site consumes. Rows are de-duplicated by ID,
keeping the last occurrence, matching the source spreadsheet's own precedence.
"""
import argparse
import json
import re
from parsing.sheet_data import SheetData, ELEMENT_SPLIT
from parsing.zsb import ZSB
from pathlib import Path


class Parser():
    sheet_data: SheetData
    def __init__(self, csv_dir):
        self.sheet_data = SheetData(csv_dir)

    def sb_details(self):
        sbs = {}
        for row in self.sheet_data.readers["sbs"]:
            id = row["ID"]
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
                "elements": elements,
                "type": row["Type"],
                "target": row["Target"],
                "lensable": row["Anima"] != "",
                "effects": row["Effects"]
            }
            sbs[id]["description"] = self.description_for_sb(sbs[id])
            card_desc = self.card_description_for_sb(sbs[id])
            if card_desc is not None:
                sbs[id]["card_description"] = card_desc
        return sbs

    def description_for_sb(self, sb):
        return self.sections_for_sb(sb)

    def card_description_for_sb(self, sb):
        return self.sections_for_sb(sb, True)

    def sections_for_sb(self, sb, is_card: bool = False):
        sections = [
            {
                "name": "Entry",
                "text": sb["effects"]
            }
        ]
        match sb["tier"]:
            case "ZSB":
                return ZSB(self.sheet_data, sb).ordered_sections(is_card)
            case "ASB":
                pass

        return sections


def main():
    base_path = Path(__file__).parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", type=Path,
        default=base_path / "data" / "raw",
        help="Data CSV dir (default: data/raw)",
    )
    parser.add_argument(
        "--output", type=Path,
        default=base_path / "data" / "all.json",
        help="Output JSON file (default: data/all.json)",
    )
    parser.add_argument(
        "--sb-dir", type=Path,
        default=base_path / "data" / "sb",
        help="Per-soul-break JSON dir, one <id>.json each (default: data/sb)",
    )
    args = parser.parse_args()

    print(f"Loading soul break details from {args.input}...")
    parser = Parser(args.input)
    sbs = parser.sb_details()
    print(f"  Loaded {len(sbs)} soul breaks")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"items": list(sbs.values())}, f, indent=2, ensure_ascii=False)
    print(f"✓ Wrote {len(sbs)} items to {args.output}")

    # Per-SB files (full item each) for the detail page to load individually.
    # Prune stale ids so the committed dir tracks the current set.
    args.sb_dir.mkdir(parents=True, exist_ok=True)
    for stale in args.sb_dir.glob("*.json"):
        if stale.stem not in sbs:
            stale.unlink()
    for id, item in sbs.items():
        (args.sb_dir / f"{id}.json").write_text(
            json.dumps(item, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    print(f"✓ Wrote {len(sbs)} per-SB files to {args.sb_dir}")


if __name__ == "__main__":
    main()

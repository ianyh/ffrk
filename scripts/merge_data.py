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
from parsing import SheetData, ELEMENT_SPLIT, ZSB, ASB, SoulBreak
from pathlib import Path
from typing import Dict


class Parser():
    sheet_data: SheetData
    def __init__(self, csv_dir):
        self.sheet_data = SheetData(csv_dir)

    def sb_details(self) -> Dict[str, SoulBreak]:
        sb_rows_by_char_tier_version: Dict[tuple[str, str, str], list[dict]] = {}
        for row in self.sheet_data.readers["sbs"]:
            id = row["ID"]
            elements_string = row["Element"]
            elements = re.split(ELEMENT_SPLIT, elements_string) if elements_string not in ["", "-"] else []
            sb = {
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
            try:
                sb_rows_by_char_tier_version[(sb["character"], sb["tier"], sb["sb_version"])].append(sb)
            except KeyError:
                sb_rows_by_char_tier_version[(sb["character"], sb["tier"], sb["sb_version"])] = [sb]
        
        sbs: Dict[str, SoulBreak] = {}
        for (_, tier, _), sb_rows in sb_rows_by_char_tier_version.items():
            soul_break = self.sb_for_rows(tier, sb_rows)
            sbs[soul_break.id] = soul_break

        return sbs

    def sb_for_rows(self, tier, sb_rows) -> SoulBreak:
        match tier:
            case "ZSB":
                return ZSB(self.sheet_data, sb_rows)
            case "ASB":
                return ASB(self.sheet_data, sb_rows)
            case _:
                return SoulBreak(self.sheet_data, sb_rows)


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
        json.dump({"items": [sb.encoded() for sb in sbs.values()]}, f, indent=2, ensure_ascii=False)
    print(f"✓ Wrote {len(sbs)} items to {args.output}")

    # Per-SB files (full item each) for the detail page to load individually,
    # named by the item's primary id. Prune stale ids so the committed dir
    # tracks the current set.
    args.sb_dir.mkdir(parents=True, exist_ok=True)
    valid_ids = {sb.id for sb in sbs.values()}
    for stale in args.sb_dir.glob("*.json"):
        if stale.stem not in valid_ids:
            stale.unlink()
    for sb in sbs.values():
        (args.sb_dir / f"{sb.id}.json").write_text(
            json.dumps(sb.encoded(), indent=2, ensure_ascii=False), encoding="utf-8"
        )
    print(f"✓ Wrote {len(sbs)} per-SB files to {args.sb_dir}")


if __name__ == "__main__":
    main()

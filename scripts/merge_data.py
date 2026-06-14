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


STATUS_RE = re.compile(r"\[([^\]]+)\]")
def extract_statuses(text):
    """List the [bracketed] status names in `text`, first-seen order, de-duped."""
    seen, out = set(), []
    for name in STATUS_RE.findall(text):
        name = name.strip()
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


# Tweakable: lowercase words allowed *inside* a multi-word proper noun.
_CONNECTORS = r"of|the|and|in|to"
def extract_with_prefix(text, prefix):
    """Find 'prefix: <Name>' references in `text` (bracketed or not), de-duped.

    <Name> is a proper noun: a capitalized word, optionally followed by more
    capitalized words / connectors, and an optional trailing (parenthetical).
    Returns the full normalized references, e.g. 'Zenith Mode: Laguna (Ice)'.
    """
    label = prefix.strip().rstrip(":").rstrip()
    name = rf"[A-Z][\w'’+\-]*(?: (?:{_CONNECTORS}|[A-Z][\w'’+\-]*))*(?: \([^)]*\))?"
    pattern = re.compile(re.escape(label) + r"\s*:?\s*(" + name + ")")

    seen, out = set(), []
    for m in pattern.finditer(text):
        ref = f"{label}: {m.group(1)}"   # m.group(1) alone is just the name
        if ref not in seen:
            seen.add(ref)
            out.append(ref)
    return out


CSV_NAMES = [
    "sbs",
    "other",
    "status",
    "cf_commands",
    "ua_abilities"
]


class SheetData():
    """
    Encapsulates a representation of db data based on available csv export.
    
    It is not particularly efficient, but the data set is small enough that it's not too bad, and it's pretty easy to audit the logic this way.
    """
    readers = {}
    def __init__(self, csv_dir):
        for name in CSV_NAMES:
            csv_path = csv_dir / f"{name}.csv"
            self.readers[name] = list(csv.DictReader(open(csv_path, encoding="utf-8")))

    def sb_details(self):
        sbs = {}
        for row in self.readers["sbs"]:
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
        return sbs

    def description_for_sb(self, sb):
        sections = [
            {
                "name": "Entry",
                "text": sb["effects"]
            }
        ]
        match sb["tier"]:
            case "ZSB":
                # try to find the upgraded has
                sb_name = sb["name"]
                has = filter(lambda h: h["Source"] == sb_name, self.readers["ua_abilities"])
                for ha in has:
                    sections.append({
                        "name": ha["Name"],
                        "text": ha["Effects"]
                    })

                # try to find the character specific mode
                sb_statuses = extract_statuses(sb["effects"])
                zenith_mode_name = next((status for status in sb_statuses if status.startswith("Zenith Mode: ")), None)
                zenith_mode = next((status for status in self.readers["status"] if status["Common Name"] == zenith_mode_name), None)
                if zenith_mode is not None:
                    zenith_mode_actions = extract_with_prefix(zenith_mode["Effects"], "Spirit Attack")
                    other = next((other for other in self.readers["other"] if other["Source"] == zenith_mode_name), None)
                    if other:
                        sections.append({
                            "name": other["Name"],
                            "text": other["Effects"]
                        })
                else:
                    print(f"zenith mode not found: {zenith_mode} {zenith_mode_name}")


        return sections


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
                "description": [
                    {
                        "name": "Entry",
                        "text": row["Effects"]
                    }
                ],
                "elements": elements,
                "type": row["Type"],
                "target": row["Target"],
                "lensable": row["Anima"] != ""
            }
    return sbs


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
    args = parser.parse_args()

    print(f"Loading soul break details from {args.input}...")
    data = SheetData(args.input)
    sbs = data.sb_details()
    print(f"  Loaded {len(sbs)} soul breaks")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"items": list(sbs.values())}, f, indent=2, ensure_ascii=False)

    print(f"✓ Wrote {len(sbs)} items to {args.output}")


if __name__ == "__main__":
    main()

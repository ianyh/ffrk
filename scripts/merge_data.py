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


# Lowercase words allowed *inside* a multi-word proper noun.
_CONNECTORS = r"of|the|and|in|to"
def extract_with_prefix(text, prefix):
    """Find 'prefix <Name>' references in `text` — colon optional, bracketed or not.

    Handles 'Spirit Attack:' (colon present) and 'Roaring' (no colon) alike.
    <Name> is a proper noun: capitalized word(s), lowercase connectors
    (of/the/and/...), and an optional trailing (parenthetical).
    Returns the full references as they appear, de-duped.
    """
    label = re.escape(prefix.strip().rstrip(":").rstrip())
    name = rf"[A-Z][\w'’+\-]*(?: (?:{_CONNECTORS}|[A-Z][\w'’+\-]*))*(?: \([^)]*\))?"
    pattern = re.compile(r"\b" + label + r"[:\s]+(" + name + ")")

    seen, out = set(), []
    for m in pattern.finditer(text):
        ref = re.sub(r"\s+", " ", m.group(0)).strip()   # m.group(1) is just the name
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
            card_desc = self.card_description_for_sb(sbs[id])
            if card_desc is not None:
                sbs[id]["card_description"] = card_desc
        return sbs

    def card_description_for_sb(self, sb):
        """Curated/compressed sections for the compact OG card (different order or
        trimmed text). Return None to use the full `description` on the card as
        well; override per tier here, like description_for_sb. The card renderer
        falls back to `description` when this is absent."""
        return None

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
            case "ASB":
                sb_statuses = extract_statuses(sb["effects"])
                accel_mode_name = next((status for status in sb_statuses if status.startswith("Accel Mode: ")), None)
                accel_mode = self.status_with_name(accel_mode_name)
                if accel_mode is not None:
                    sections.append({
                        "name": accel_mode["Common Name"],
                        "text": accel_mode["Effects"]
                    })
                    chase = self.other_with_source(accel_mode_name)
                    if chase:
                        sections.append({
                            "name": chase["Name"],
                            "text": chase["Effects"]
                        })
                else:
                    print(f"accel mode not found: {accel_mode} {accel_mode_name}")


        return sections

    def other_with_source(self, source):
        return next((other for other in self.readers["other"] if other["Source"] == source), None)
    
    def status_with_name(self, name):
        return next((status for status in self.readers["status"] if status["Common Name"] == name), None)


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
    parser.add_argument(
        "--sb-dir", type=Path,
        default=base_path / "data" / "sb",
        help="Per-soul-break JSON dir, one <id>.json each (default: data/sb)",
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

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
from dataclasses import dataclass
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
                return ZSB(self, sb).ordered_sections(is_card)
            case "ASB":
                pass
                # sb_statuses = extract_statuses(sb["effects"])
                # accel_mode_name = next((status for status in sb_statuses if status.startswith("Accel Mode: ")), None)
                # accel_mode = self.status_with_name(accel_mode_name)
                # if accel_mode is not None:
                #     sections.append({
                #         "name": accel_mode["Common Name"],
                #         "text": accel_mode["Effects"]
                #     })
                #     chase = self.other_with_source(accel_mode_name)
                #     if chase:
                #         sections.append({
                #             "name": chase["Name"],
                #             "text": chase["Effects"]
                #         })
                # else:
                #     print(f"accel mode not found: {accel_mode} {accel_mode_name}")

        return sections

    def others_with_source(self, source):
        return [other for other in self.readers["other"] if other["Source"] == source]

    def other_with_name(self, name):
        return next((other for other in self.readers["other"] if other["Name"] == name), None)
    
    def status_with_name(self, name):
        return next((status for status in self.readers["status"] if status["Common Name"] == name), None)


@dataclass(frozen=True)
class ZSB():
    data: SheetData
    sb: dict

    def ordered_sections(self, is_card: bool) -> list[dict]:
        sections = self.sections()
        ordered = []
        if is_card:
            ordered = [
                sections["entry"]
            ] + sections.get("ha+", []) + [
                sections.get("spirit_attack", None)
            ]
        else:
            ordered = [
                sections["entry"],
                sections.get("mode", None),
            ] + sections.get("ha+", []) + [
                sections.get("spirit_attack", None)
            ] + sections.get("other", []) + sections.get("other_status", [])
        
        return [s for s in ordered if s is not None]
    
    def sections(self) -> dict:
        sections = {
            "entry": {
                "name": "Entry",
                "text": self.sb["effects"]
            }
        }

        # try to find the upgraded has
        sections["ha+"] = []
        sb_name = self.sb["name"]
        has: list[dict] = filter(lambda h: h["Source"] == sb_name, self.data.readers["ua_abilities"])
        for ha in has:
            sections["ha+"].append({
                "name": ha["Name"],
                "text": ha["Effects"]
            })

        sb_statuses = extract_statuses(self.sb["effects"])

        # try to find the character specific mode
        zenith_mode_name = next((status for status in sb_statuses if status.startswith("Zenith Mode: ")), None)
        zenith_mode = self.data.status_with_name(zenith_mode_name)
        if zenith_mode is not None:
            sections["mode"] = {
                "name": zenith_mode_name,
                "text": zenith_mode["Effects"]
            }
            # if we have the character specific mode then try to extract a spirit attack
            zenith_mode_actions = extract_with_prefix(zenith_mode["Effects"], "Spirit Attack")
            spirit_attack_name = zenith_mode_actions[0] if len(zenith_mode_actions) > 0 else None
            if spirit_attack_name:
                spirit_attack = self.data.other_with_name(spirit_attack_name)
                if spirit_attack is not None:
                    sections["spirit_attack"] = {
                        "name": spirit_attack["Name"],
                        "text": spirit_attack["Effects"]
                    }
            others = [other for other in self.data.others_with_source(zenith_mode_name) if other["Name"] != spirit_attack_name]
            if others:
                sections["other"] = [{ "name": other["Name"], "text": other["Effects"]} for other in others]
        else:
            print(f"zenith mode not found: {zenith_mode} {zenith_mode_name}")
        
        # add sections for each non-mode status
        sections["other_status"] = []
        for status_name in [s for s in sb_statuses if s != zenith_mode_name]:
            status_details = self.data.status_with_name(status_name)
            if status_details:
                sections["other_status"].append({
                    "name": status_name,
                    "text": status_details["Effects"]
                })
            
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

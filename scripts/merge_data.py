#!/usr/bin/env python3
"""
Merge ownership data (from mitmproxy) with item details (from Google Sheets)
Outputs a single JSON file for Zola to consume
"""
import json
import csv
import re
from pathlib import Path

pattern = r'\s*(?:,\s*(?:and|or)\s*|,\s*|/\s*|\s+(?:and|or)\s+)\s*'

def load_sb_holding_data(filepath):
    """Load sb holding data from CSV"""
    sbs = []
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["character"] == "":
                continue
            sbs.append({
                "id": row["id"],
                "character": row["character"],
                "image_path": row["image_path"]
            })
    return sbs

def load_sb_details(filepath):
    """Load sb details from CSV"""
    sbs = {}
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            id = row["ID"]
            elements_string = row["Element"]
            elements = re.split(pattern, elements_string) if elements_string not in ["", "-"] else []
            sbs[id] = {
                "id": id,
                "image_url": f"https://dff.sp.mbga.jp/dff/static/lang/image/soulstrike/${id}/${id}_256.png",
                "character": row["Character"],
                "name": row["Name"],
                "name_jp": row["Name (JP)"],
                "tier": row["Tier"],
                "sb_version": row["SB Ver"],
                "realm": row["Realm"],
                "description": row["Effects"],
                "elements": elements
            }
    return sbs

def merge_data(sb_holdings, sb_details):
    """Merge sb holdings with sb details"""
    merged = []
    missing_detail_ids = set()
    
    for entry in sb_holdings:
        id = entry["id"]
        details = sb_details.get(id)        
        if not details:
            print(f"warning: id not found: {id}")
            missing_detail_ids.add(id)
        merged.append(details)
    
    if missing_detail_ids:
        print(f"\n⚠ {len(missing_detail_ids)} items missing from details spreadsheet")
    
    return merged

def main():
    base_path = Path(__file__).parent.parent
    raw_path = base_path / "data" / "raw"
    sb_holding_paths = [raw_path / d for d in ["sbs1.csv", "sbs2.csv", "sbs3.csv"]]
    sb_details_path = base_path / "data" / "raw" / "item_details.csv"
    output_file = base_path / "data" / "items.json"
    output_file_full = base_path / "data" / "all.json"
    
    # Load data
    print("Loading ownership data...")
    sb_holdings = []
    for path in sb_holding_paths:
        sb_holdings += load_sb_holding_data(path)
    print(f"  Loaded {len(sb_holdings)} sb holding records")
    
    print("Loading item details...")
    sb_details = load_sb_details(sb_details_path)
    print(f"  Loaded {len(sb_details)} sb definitions")
    
    output_file_full.parent.mkdir(parents=True, exist_ok=True)
    output_full = {"items": [sb for sb in sb_details.values()]}
    with open(output_file_full, "w", encoding="utf-8") as f:
        json.dump(output_full, f, indent=2, ensure_ascii=False)

    # Merge
    print("\nMerging data...")
    merged = merge_data(sb_holdings, sb_details)

    # Write output
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output = {"items": merged}
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\n✓ Merged {len(merged)} items")
    print(f"✓ Output written to {output_file}")

if __name__ == "__main__":
    main()

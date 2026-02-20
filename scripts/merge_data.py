#!/usr/bin/env python3
"""
Merge ownership data (from mitmproxy) with item details (from Google Sheets)
Outputs a single JSON file for Zola to consume
"""
import json
import csv
from pathlib import Path

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

def element_string_to_elements(elements_string):
    elements = []
    if "/" in elements_string:
        elements = elements_string.split("/")
    else:
        elements = elements_string.split(",")
    stripped_elements = [e.strip().removeprefix("and ").removeprefix("or ").strip() for e in elements]
    return [e for e in stripped_elements if e != "" and e != "-"]

def load_sb_details(filepath):
    """Load sb details from CSV"""
    sbs = {}
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            id = row["ID"]
            elements = element_string_to_elements(row["Element"])
            sbs[id] = {
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
        
        merged_item = {
            "id": id,
            "image_url": f"https://dff.sp.mbga.jp{entry["image_path"]}",
            "character": entry["character"],
            "name": details["name"],
            "name_jp": details["name_jp"],
            "realm": details["realm"],
            "tier": details["tier"],
            "sb_version": details["sb_version"],
            "description": details.get("description", ""),
            "elements": details.get("elements", [])
        }
        
        merged.append(merged_item)
    
    if missing_detail_ids:
        print(f"\n⚠ {len(missing_detail_ids)} items missing from details spreadsheet")
    
    return merged

def main():
    # Paths
    base_path = Path(__file__).parent.parent
    raw_path = base_path / "data" / "raw"
    sb_holding_paths = [raw_path / d for d in ["sbs1.csv", "sbs2.csv", "sbs3.csv"]]
    sb_details_path = base_path / "data" / "raw" / "item_details.csv"
    output_file = base_path / "data" / "items.json"
    
    # Load data
    print("Loading ownership data...")
    sb_holdings = []
    for path in sb_holding_paths:
        sb_holdings += load_sb_holding_data(path)
    print(f"  Loaded {len(sb_holdings)} sb holding records")
    
    print("Loading item details...")
    sb_details = load_sb_details(sb_details_path)
    print(f"  Loaded {len(sb_details)} sb definitions")
    
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

#!/usr/bin/env python3
"""
Download Google Sheet as CSV
"""
import requests
from pathlib import Path

def download_sheet_as_csv(spreadsheet_id, gid, output_file):
    """
    Download a Google Sheet as CSV
    
    Args:
        spreadsheet_id: The spreadsheet ID from the URL
        gid: The sheet ID (gid parameter from URL, usually 0 for first sheet)
        output_file: Where to save the CSV
    """
    url = f"https://docs.google.com/spreadsheets/d/{spreadsheet_id}/export?format=csv&gid={gid}"
    
    print(f"Downloading from Google Sheets...")
    print(f"URL: {url}")
    
    response = requests.get(url)
    
    if response.status_code == 200:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "wb") as f:
            f.write(response.content)
        print(f"✓ Downloaded to {output_file}")
        return True
    else:
        print(f"❌ Failed to download: {response.status_code}")
        print(f"   Make sure the sheet is set to 'Anyone with the link can view'")
        return False

def main():
    SPREADSHEET_ID = "1f8OJIQhpycljDQ8QNDk_va1GJ1u7RVoMaNjFcHH0LKk"
    GID = "344457459"
    
    base_path = Path(__file__).parent.parent
    output_file = base_path / "data" / "raw" / "item_details.csv"
    
    success = download_sheet_as_csv(SPREADSHEET_ID, GID, output_file)
    
    if not success:
        exit(1)

if __name__ == "__main__":
    main()

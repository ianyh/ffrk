#!/usr/bin/env python3
"""
FFRK Multi-Data Auto-Processor for mitmproxy
Automatically intercepts FFRK API responses and generates CSV files for multiple data types

Usage:
    mitmproxy -s ffrk_multi_processor.py
    mitmdump -s ffrk_multi_processor.py
"""

import json
import csv
import re
from collections import defaultdict
from datetime import datetime
from mitmproxy import http
from pathlib import Path
from typing import Dict


# Character name translation dictionary (Japanese to English)
CHARACTER_TRANSLATIONS = {
    "セブン": "Seven", "ナバート": "Nabaat", "リノア": "Rinoa", "ケルガー": "Kelger", 
    "エスティニアン": "Estinien", "クイーン": "Queen", "エイト": "Eight", "シンク": "Cinque",
    "デュース": "Deuce", "トレイ": "Trey", "エース": "Ace", "レム": "Rem", "マキナ": "Machina",
    "カイン": "Kain", "セシル": "Cecil", "セシル(パラディン)": "Cecil (Paladin)", 
    "セシル(暗黒騎士)": "Cecil (Dark Knight)", "ローザ": "Rosa", "リディア": "Rydia",
    "エッジ": "Edge", "ヤン": "Yang", "パロム": "Palom", "ポロム": "Porom", "テラ": "Terra",
    "ティナ": "Terra", "ロック": "Locke", "セリス": "Celes", "エドガー": "Edgar",
    "マッシュ": "Sabin", "シャドウ": "Shadow", "ストラゴス": "Strago", "リルム": "Relm",
    "セッツァー": "Setzer", "モグ": "Mog", "ガウ": "Gau", "クラウド": "Cloud", "ティファ": "Tifa",
    "エアリス": "Aerith", "バレット": "Barret", "レッドXIII": "Red XIII", "ユフィ": "Yuffie",
    "ヴィンセント": "Vincent", "ケット・シー": "Cait Sith", "シド": "Cid", "シド(IV)": "Cid (IV)",
    "シド(VII)": "Cid (VII)", "シド(XIV)": "Cid (XIV)", "ザックス": "Zack", "セフィロス": "Sephiroth",
    "スコール": "Squall", "ゼル": "Zell", "アーヴァイン": "Irvine", "キスティス": "Quistis",
    "セルフィ": "Selphie", "ラグナ": "Laguna", "キロス": "Kiros", "ウォード": "Ward",
    "サイファー": "Seifer", "イデア": "Edea", "ジタン": "Zidane", "ビビ": "Vivi",
    "ガーネット": "Garnet", "スタイナー": "Steiner", "フライヤ": "Freya", "クイナ": "Quina",
    "エーコ": "Eiko", "サラマンダー": "Amarant", "ベアトリクス": "Beatrix", "クジャ": "Kuja",
    "ティーダ": "Tidus", "ユウナ": "Yuna", "ワッカ": "Wakka", "ルールー": "Lulu",
    "キマリ": "Kimahri", "リュック": "Rikku", "アーロン": "Auron", "ジェクト": "Jecht",
    "シーモア": "Seymour", "パイン": "Paine", "ヴァン": "Vaan", "バルフレア": "Balthier",
    "フラン": "Fran", "バッシュ": "Basch", "アーシェ": "Ashe", "パンネロ": "Penelo",
    "ガブラス": "Gabranth", "ライトニング": "Lightning", "スノウ": "Snow", "ヴァニラ": "Vanille",
    "サッズ": "Sazh", "ホープ": "Hope", "ファング": "Fang", "セラ": "Serah", "ノエル": "Noel",
    "ノクティス": "Noctis", "グラディオラス": "Gladiolus", "イグニス": "Ignis",
    "プロンプト": "Prompto", "アラネア": "Aranea", "イリス": "Iris", "ルナフレーナ": "Lunafreya",
    "ラムザ": "Ramza", "アグリアス": "Agrias", "ディリータ": "Delita", "ムスタディオ": "Mustadio",
    "オヴェリア": "Ovelia", "ガフガリオン": "Gaffgarion", "メリアドール": "Meliadoul",
    "オルランドゥ": "Orlandeau", "ラファ": "Rapha", "マラーク": "Marach", "モンブラン": "Montblanc",
    "マーシュ": "Marche", "ウォル": "Warrior of Light", "光の戦士": "Warrior of Light",
    "ガーランド": "Garland", "セーラ": "Sarah", "エコー": "Echo", "マトーヤ": "Matoya",
    "メイア": "Meia", "フリオニール": "Firion", "マリア": "Maria", "ガイ": "Guy",
    "レオンハルト": "Leon", "ミンウ": "Minwu", "ヨーゼフ": "Josef", "ゴードン": "Gordon",
    "レイラ": "Leila", "リチャード": "Ricard", "スコット": "Scott", "ヒルダ": "Hilda",
    "皇帝": "Emperor", "オニオンナイト": "Onion Knight", "ルーネス": "Luneth", "アルクゥ": "Arc",
    "レフィア": "Refia", "イングズ": "Ingus", "デッシュ": "Desch", "暗闇の雲": "Cloud of Darkness",
    "ギルバート": "Edward", "テラ": "Tellah", "フースーヤ": "FuSoYa", "ゴルベーザ": "Golbez",
    "バッツ": "Bartz", "レナ": "Lenna", "ガラフ": "Galuf", "ファリス": "Faris",
    "クルル": "Krile", "ギルガメッシュ": "Gilgamesh", "エクスデス": "Exdeath", "ドルガン": "Dorgann",
    "ゼザ": "Xezat", "カイエン": "Cyan", "ケフカ": "Kefka", "レオ": "Leo", "レオ将軍": "General Leo",
    "ウーマロ": "Umaro", "レノ": "Reno", "ルード": "Rude", "ルーファウス": "Rufus",
    "シェルク": "Shelke", "アンジール": "Angeal", "ジェネシス": "Genesis", "イリーナ": "Elena",
    "レインズ": "Raines", "アルフィノ": "Alphinaud", "アリゼー": "Alisaie", "イゼル": "Ysayle",
    "ヤ・シュトラ": "Y'shtola", "サンクレッド": "Thancred", "ミンフィリア": "Minfilia",
    "パパリモ": "Papalymo", "イダ": "Yda", "オルシュファン": "Haurchefant", "リセ": "Lyse",
    "アイメリク": "Aymeric", "ウリエンジェ": "Urianger", "ガイウス": "Gaius", "ゼノス": "Zenos",
    "オルトロス": "Ultros", "アデル": "Adel", "アーデン": "Ardyn", "Dr.モグ": "Dr. Mog",
    "バルバリシア": "Barbariccia", "スカーレット": "Scarlet", "リーブ": "Reeve", "デシ": "Tyro",
    "エリア": "Elarra", "ビッグス": "Biggs", "ウェッジ": "Wedge", "トット": "Shantotto",
    "シャントット": "Shantotto", "プリッシュ": "Prishe", "アヤメ": "Ayame", "クリルラ": "Curilla",
    "ライオン": "Lion", "アフマウ": "Aphmau", "ザイド": "Zeid", "アシェラ": "Ashe",
    "セオドア": "Ceodore", "ゴゴ": "Gogo", "ものまねしゴゴ": "Gogo (Mimic)", "シーフ(I)": "Thief (I)",
    "スーパーモンク": "Master", "ルビカンテ": "Rubicante", "アルティミシア": "Ultimecia",
    "雷神": "Raijin", "風神": "Fujin", "マーカス": "Marcus", "ブラスカ": "Braska",
    "ラーサー": "Larsa", "ヴェイン": "Vayne", "ナイン": "Nine", "キング": "King", "サイス": "Sice",
    "ジャック": "Jack", "アルマ": "Alma", "オーラン": "Orran", "リリゼット": "Lilisette",
    "コル": "Cor", "レイヴス": "Ravus", "ラァン": "Lann", "レェン": "Reynn", "シドルファス": "Cidolfus",
    "クライヴ": "Clive", "ジョシュア": "Joshua", "ジル": "Jill", "クラサメ": "Kurasame",
    "エモ": "Emo", "ウララ": "Urara", "ケイト": "Cater", "エナ・クロ": "Ena Kros",
    "セラフィ": "Serafie", "フィーナ": "Fina", "ラスウェル": "Lasswell", "レイン": "Rain",
    "シャドウスミス": "Shadowsmith", "レックス": "Wrexsoul", "リーグ": "Rikku",
    "トゥモロ": "Tomoe", "タマ": "Tama", "アーシュラ": "Ursula", "ナジャ": "Naja",
}

SB_CATEGORY_TRANSLATIONS = {
    "ACCEL_SHINGI": "ASB",
    "AWAKE": "AASB",
    "BURST": "BSB",
    "BUSTER_SHINGI": "Buster",
    "COMBO": "CSB",
    "COMMON": "Shared",
    "CRYSTAL_SHINGI": "CASB",
    "DUAL_AWAKE": "DASB",
    "LIMIT_BREAK_COMBO": "LBC",
    "LIMIT_BREAK_OVERFLOW": "LBO",
    "LIMIT_BREAK_SENGI": "LBG",
    "MASTER_SHINGI": "MASB",
    "OVERFLOW": "OSB",
    "OVERFLOW_OUGI": "UOSB",
    "OVERFLOW_SHINGI": "OZSB",
    "SENGI": "FSB",
    "SHIN_OUGI": "TASB",
    "STANDARD": "Default",
    "SUPER": "SSB",
    "SYNCHRO": "SASB",
    "TACTICAL_AWAKE": "Tactical",
    "ULTIMATE_SHINGI": "UASB",
    "ULTIMATE_SUMMON": "LBGS",
    "ULTRA": "USB",
    "UNIQUE": "Unique"
}

OUTPUT_DIR = Path.cwd() / "ffrk_data"
OUTPUT_DIR.mkdir(exist_ok=True)

# Pagination settings
ACCUMULATION_TIMEOUT = 5  # seconds - time to wait after last response before finalizing
ENABLE_AUTO_SAVE = True   # Auto-save after timeout
ENABLE_PAGE_TRACKING = True  # Save individual pages as backup


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def extract_character_name(name):
    """Extract character name from between Japanese brackets 【】"""
    match = re.search(r"【(.+?)】", name)
    if match:
        return match.group(1)
    return ""


def extract_tier(name):
    """Extract Roman numeral tier from the end of the name"""
    tier_match = re.search(r"】\s*(I{1,3}|IV|V|VI{0,3}|IX|X)\s*$", name)
    if tier_match:
        return tier_match.group(1)
    return ""


def save_to_csv(data, headers, filename):
    """Generic CSV saver"""
    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(data)


def deduplicate_by_id(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate items by "id" field, keeping first occurrence"""
    seen = set()
    result = []
    for item in items:
        item_id = item.get("id")
        if item_id not in seen:
            seen.add(item_id)
            result.append(item)
    return result


# =============================================================================
# DATA PROCESSORS
# =============================================================================

class MotesInventoryProcessor:
    """Process generic and character-specific mote inventory"""
    
    @staticmethod
    def process(data):
        """Process sphere materials and return processed list"""
        items = data.get("sphere_materials", [])
        if not items:
            return None, None
        
        for item in items:
            name = item.get("name", "")
            character_name_jp = extract_character_name(name)
            item["character_jp"] = character_name_jp
            item["character"] = CHARACTER_TRANSLATIONS.get(character_name_jp, character_name_jp)
            item["tier"] = extract_tier(name)
        
        headers = [
            "character", "character_jp", "tier", "num", "name", 
            "id", "series_id", "rarity", "sale_gil", "description", 
            "display_type", "created_at", "image_path"
        ]
        
        return items, headers
    
    @staticmethod
    def get_filename(timestamp):
        return OUTPUT_DIR / f"motes_inventory_{timestamp}.csv"

    @staticmethod
    def is_paginated():
        return False


class DressRecordsProcessor:
    """Process dress records data"""
    
    @staticmethod
    def process(data):
        """Process dress records and return processed list"""
        items = data.get("dress_records", [])
        if not items:
            return None, None
        
        # Extract character names
        for item in items:
            name = item.get("name", "")
            character_name_jp = extract_character_name(name)
            if character_name_jp:
                item["character_jp"] = character_name_jp
                item["character"] = CHARACTER_TRANSLATIONS.get(character_name_jp, character_name_jp)
            else:
                item["character_jp"] = ""
                item["character"] = ""
        
        headers = [
            "character", "character_jp", "id", "name", 
            "description", "image_path", "series_id"
        ]
        
        return items, headers
    
    @staticmethod
    def get_filename(timestamp):
        return OUTPUT_DIR / f"dress_records_{timestamp}.csv"

    @staticmethod
    def is_paginated():
        return False


class SoulBreaksProcessor:
    """Process soul breaks data"""
    
    @staticmethod
    def process(data):
        items = data.get("soul_strikes", [])
        if not items:
            return None, None
        
        for ss in items:
            buddy_name_jp = ss.get("allowed_buddy_name", "")
            ss["character_jp"] = buddy_name_jp
            ss["character"] = CHARACTER_TRANSLATIONS.get(buddy_name_jp, buddy_name_jp)

            category_name_jp = ss.get("soul_strike_category_name", "")
            ss["soul_strike_category_name"] = SB_CATEGORY_TRANSLATIONS.get(category_name_jp, category_name_jp)
            
            elements = ss.get("elements", [])
            ss["elements_str"] = ", ".join(map(str, elements)) if elements else ""
        
        headers = [
            "id", "character", "character_jp", "name", 
            "soul_strike_category_name", "description",
            "consume_ss_gauge", "consume_point", "elements_str",
            "is_default_soul_strike", "is_standard_soul_strike", "is_unique_soul_strike",
            "is_super_soul_strike", "is_burst_soul_strike", "is_ultra_soul_strike",
            "is_awake_soul_strike", "is_synchro_soul_strike", "is_dual_awake_soul_strike",
            "allowed_buddy_id", "allowed_buddy_series_id", "image_path"
        ]
        
        return items, headers
    
    
    @staticmethod
    def get_filename(timestamp):
        return OUTPUT_DIR / f"soul_breaks_{timestamp}.csv"
    
    @staticmethod
    def is_paginated():
        return True


# =============================================================================
# PROCESSOR REGISTRY - Add new processors to this list
# =============================================================================

PROCESSORS = [
    MotesInventoryProcessor,
    SoulBreaksProcessor,
    DressRecordsProcessor
]

# =============================================================================
# PAGINATION MANAGER
# =============================================================================

class PaginationManager:
    """Manages accumulation of paginated data across multiple responses"""
    
    def __init__(self):
        self.accumulated_data: Dict[str, Dict[str, List]] = defaultdict(lambda: defaultdict(list))
        self.last_update_time: Dict[str, float] = {}
        self.page_counts: Dict[str, int] = defaultdict(int)
        
    def add_page(self, endpoint: str, processor_name: str, items: List[Dict]):
        """Add a page of data for a specific endpoint and processor"""
        self.accumulated_data[endpoint][processor_name].extend(items)
        self.last_update_time[endpoint] = datetime.now().timestamp()
        self.page_counts[endpoint] += 1
        
    def get_accumulated(self, endpoint: str, processor_name: str) -> List[Dict]:
        """Get all accumulated data for an endpoint and processor"""
        return self.accumulated_data[endpoint][processor_name]
    
    def should_finalize(self, endpoint: str, timeout: float = ACCUMULATION_TIMEOUT) -> bool:
        """Check if enough time has passed since last update to finalize"""
        if endpoint not in self.last_update_time:
            return False
        
        elapsed = datetime.now().timestamp() - self.last_update_time[endpoint]
        return elapsed >= timeout
    
    def finalize(self, endpoint: str):
        """Mark endpoint as finalized and clear its data"""
        if endpoint in self.accumulated_data:
            del self.accumulated_data[endpoint]
        if endpoint in self.last_update_time:
            del self.last_update_time[endpoint]
        if endpoint in self.page_counts:
            del self.page_counts[endpoint]
    
    def get_page_count(self, endpoint: str) -> int:
        """Get number of pages received for an endpoint"""
        return self.page_counts.get(endpoint, 0)


# =============================================================================
# MAIN ADDON CLASS
# =============================================================================

class FFRKMultiProcessorAddon:
    """mitmproxy addon with pagination support"""
    
    def __init__(self):
        self.stats = {processor.__name__: 0 for processor in PROCESSORS}
        self.total_processed = 0
        self.pagination_manager = PaginationManager()
        self.pending_endpoints = set()
        
    def get_endpoint_key(self, flow: http.HTTPFlow) -> str:
        """Generate a consistent key for an endpoint"""
        # Use URL path without query params as key
        url = flow.request.pretty_url
        # Remove query parameters for grouping
        base_url = url.split("?")[0]
        return base_url
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Intercept responses and process FFRK data"""
        
        if not self.is_ffrk_api(flow):
            return
        
        try:
            response_data = json.loads(flow.response.content)
            endpoint = self.get_endpoint_key(flow)
            
            # Track if this is a paginated endpoint
            has_paginated_data = False
            page_info = []
            
            # Try each processor
            for processor_class in PROCESSORS:
                try:
                    items, headers = processor_class.process(response_data)
                    
                    if items and headers:
                        processor_name = processor_class.__name__
                        
                        if processor_class.is_paginated():
                            # PAGINATED: Accumulate data
                            has_paginated_data = True
                            self.pagination_manager.add_page(endpoint, processor_name, items)
                            self.pending_endpoints.add(endpoint)
                            
                            page_count = self.pagination_manager.get_page_count(endpoint)
                            accumulated_count = len(self.pagination_manager.get_accumulated(endpoint, processor_name))
                            
                            page_info.append({
                                "type": processor_name.replace("Processor", ""),
                                "page_items": len(items),
                                "total_items": accumulated_count,
                                "pages": page_count
                            })
                            
                            # Optional: Save individual pages as backup
                            if ENABLE_PAGE_TRACKING:
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                                page_file = OUTPUT_DIR / f"{processor_name.replace("Processor", "").lower()}_page{page_count}_{timestamp}.csv"
                                save_to_csv(items, headers, page_file)
                        
                        else:
                            # NON-PAGINATED: Save immediately
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            output_file = processor_class.get_filename(timestamp)
                            save_to_csv(items, headers, output_file)
                            
                            processor_name = processor_class.__name__.replace("Processor", "")
                            self.stats[processor_class.__name__] += 1
                            self.total_processed += 1
                            
                            print(f"\n✓ {processor_name}: {len(items)} items → {output_file.name}")
                
                except Exception as e:
                    print(f"Error in {processor_class.__name__}: {e}")
            
            # Show pagination progress
            if page_info:
                print(f"\n{"="*60}")
                print(f"📄 Paginated Data Received (Accumulating...)")
                print(f"{"="*60}")
                for info in page_info:
                    print(f"  {info["type"]:25s}: +{info["page_items"]:4d} items  (Total: {info["total_items"]:4d} across {info["pages"]} pages)")
                print(f"{"="*60}")
                print(f"Waiting for more pages... (will auto-save after {ACCUMULATION_TIMEOUT}s of inactivity)")
                print(f"{"="*60}\n")
            
            # Check if any pending endpoints should be finalized
            if ENABLE_AUTO_SAVE:
                self.check_and_finalize_pending()
            
            # Save raw JSON backup
            if response_data:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                json_file = OUTPUT_DIR / f"raw_data_{timestamp}.json"
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(response_data, f, ensure_ascii=False, indent=2)
                    
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"Error processing FFRK data: {e}")
    
    def check_and_finalize_pending(self):
        """Check pending endpoints and finalize if timeout reached"""
        endpoints_to_finalize = []
        
        for endpoint in self.pending_endpoints:
            if self.pagination_manager.should_finalize(endpoint):
                endpoints_to_finalize.append(endpoint)
        
        for endpoint in endpoints_to_finalize:
            self.finalize_endpoint(endpoint)
    
    def finalize_endpoint(self, endpoint: str):
        """Finalize and save accumulated data for an endpoint"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        print(f"\n{"="*60}")
        print(f"✅ FINALIZING ACCUMULATED DATA")
        print(f"{"="*60}")
        
        for processor_class in PROCESSORS:
            if not processor_class.is_paginated():
                continue
            
            processor_name = processor_class.__name__
            accumulated_items = self.pagination_manager.get_accumulated(endpoint, processor_name)
            
            if accumulated_items:
                # Deduplicate by ID
                unique_items = deduplicate_by_id(accumulated_items)
                
                # Process the accumulated data
                _, headers = processor_class.process({"temp_key": unique_items})
                if not headers:
                    # Get headers from the processor
                    dummy_data = {processor_name.replace("Processor", "").lower() + "s": unique_items[:1]}
                    _, headers = processor_class.process(dummy_data)
                
                # Save final CSV
                output_file = processor_class.get_filename(timestamp)
                save_to_csv(unique_items, headers, output_file)
                
                clean_name = processor_name.replace("Processor", "")
                page_count = self.pagination_manager.get_page_count(endpoint)
                
                print(f"  {clean_name:25s}: {len(unique_items):4d} items from {page_count} pages → {output_file.name}")
                
                self.stats[processor_class.__name__] += 1
                self.total_processed += 1
        
        print(f"{"="*60}\n")
        
        # Clean up
        self.pagination_manager.finalize(endpoint)
        self.pending_endpoints.discard(endpoint)
    
    def is_ffrk_api(self, flow: http.HTTPFlow) -> bool:
        """Determine if this is an FFRK API request"""
        url = flow.request.pretty_url
        
        ffrk_patterns = [
            "list_buddy",
            "list_other",
        ]
        
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in ffrk_patterns)
    
    def done(self):
        """Called when mitmproxy shuts down"""
        # Finalize any remaining pending endpoints
        for endpoint in list(self.pending_endpoints):
            self.finalize_endpoint(endpoint)
        
        # Show summary
        if self.total_processed > 0:
            print(f"\n{"="*60}")
            print("FFRK Processor Summary")
            print(f"{"="*60}")
            for processor_name, count in self.stats.items():
                if count > 0:
                    clean_name = processor_name.replace("Processor", "")
                    print(f"  {clean_name:30s}: {count} times")
            print(f"{"="*60}\n")


# Create the addon instance
addons = [FFRKMultiProcessorAddon()]

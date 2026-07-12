#!/usr/bin/env python3
"""Read-only analysis helpers for the soul break parsers.

Everything here only reads data/raw and parses in memory — nothing is written,
so these are safe to allowlist without full auto mode. Subcommands:

  merge-check      Parse every soul break (via merge_data's Parser) and report a
                   summary: per-tier counts and any empty descriptions. Surfaces
                   parser crashes without touching the data/json submodule.
  tier TIER        Survey one tier's raw sheet rows — char/version group sizes,
                   single- vs multi-line effects, bracket usage, secondary rows.
                   The reverse-engineering aid when wiring up a new tier.
  sections KEY     Show the parsed description sections for a soul break id, or a
                   sample of a tier (KEY is an id like 23320024 or a tier name
                   like TASB).
"""
import argparse
from collections import Counter, defaultdict
from pathlib import Path

from parsing import SheetData
from merge_data import Parser

RAW = Path(__file__).parent.parent / "data" / "raw"


def cmd_merge_check(args):
    sbs = Parser(RAW).sb_details()
    per_tier = Counter(sb.sb_rows[0]["tier"] for sb in sbs.values())
    empties = [
        (sb.sb_rows[0]["tier"], id)
        for id, sb in sbs.items()
        if not any(section["text"] for section in sb.encoded()["description"])
    ]
    print(f"Parsed {len(sbs)} soul breaks across {len(per_tier)} tiers (no parser errors).")
    print(f"Empty descriptions: {len(empties)} (usually unreleased placeholders)")
    for tier, id in sorted(empties)[:20]:
        print(f"  {tier:8s} {id}")
    if len(empties) > 20:
        print(f"  … and {len(empties) - 20} more")


def cmd_tier(args):
    rows = [r for r in SheetData(RAW).readers["sbs"] if r["Tier"] == args.tier]
    if not rows:
        print(f"No rows for tier {args.tier!r}.")
        return

    groups = defaultdict(list)
    for row in rows:
        groups[(row["Character"], row["SB Ver"])].append(row)

    formats = Counter()
    for row in rows:
        effects = row["Effects"].strip()
        if not effects:
            formats["empty"] += 1
            continue
        shape = "multi-line" if "\n" in effects else "single-line"
        formats[shape + ("+brackets" if "[" in effects else "")] += 1

    print(f"Tier {args.tier}: {len(rows)} rows, {len(groups)} char/version groups")
    print(f"  group sizes:  {dict(Counter(len(v) for v in groups.values()))}")
    print(f"  row formats:  {dict(formats)}")
    print(f"  rows with '(' in name (secondaries): {sum('(' in r['Name'] for r in rows)}")


def cmd_sections(args):
    sbs = Parser(RAW).sb_details()
    if args.key in sbs:
        targets = [sbs[args.key]]
    else:
        targets = [sb for sb in sbs.values() if sb.sb_rows[0]["tier"] == args.key][: args.limit]
    if not targets:
        print(f"No soul break id or tier matching {args.key!r}.")
        return

    for sb in targets:
        enc = sb.encoded()
        print(f"\n{enc['id']}  {enc['character']} {enc['sb_version']} ({enc['tier']})")
        for section in enc["description"]:
            print(f"  [{section.get('name', '')}] {section['text'][:120]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("merge-check", help="parse everything and report a summary").set_defaults(func=cmd_merge_check)

    tier = sub.add_parser("tier", help="survey one tier's raw sheet rows")
    tier.add_argument("tier", help="tier name, e.g. TASB")
    tier.set_defaults(func=cmd_tier)

    sections = sub.add_parser("sections", help="show parsed sections for an id or tier sample")
    sections.add_argument("key", help="a soul break id or a tier name")
    sections.add_argument("--limit", type=int, default=5, help="max soul breaks when KEY is a tier (default 5)")
    sections.set_defaults(func=cmd_sections)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

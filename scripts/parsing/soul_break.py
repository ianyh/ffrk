import re
from dataclasses import dataclass
from .sheet_data import SheetData, extract_with_prefix, extract_statuses


# The trailing "(Qualifier)" on a secondary row's name — e.g. "(Dual Shift)",
# "(Engaged)", "(Weapon Skill)" — used to label its effects once folded into the
# primary's description.
QUALIFIER_RE = re.compile(r"\(([^)]+)\)\s*$")


def secondary_label(name):
    m = QUALIFIER_RE.search(name)
    return m.group(1) if m else name


@dataclass(frozen=True)
class SoulBreak():
    data: SheetData
    sb_rows: list[dict]

    @property
    def id(self) -> str:
        return self.sb_rows[0]["id"]
    
    def section_key_ordering(self, is_card: bool) -> list[str]:
        return [
            "entry"
        ]
    
    def primary(self):
        return next((r for r in self.sb_rows if "(" not in r["name"]), self.sb_rows[0])

    def secondaries(self):
        primary = self.primary()
        return [r for r in self.sb_rows if r is not primary]

    def encoded(self):
        return dict({
            "description": self.description(),
            "card_description": self.card_description()
        }, **self.sb_rows[0])

    def description(self) -> list[dict]:
        return [s for s in self.ordered_sections(is_card=False) if s is not None]

    def card_description(self) -> list[dict]:
        return [s for s in self.ordered_sections(is_card=True) if s is not None]

    def ordered_sections(self, is_card: bool) -> list[dict]:
        primary_sections = SoulBreak(self.data, [self.primary()]).sections()
        collected_sections = []
        # take the defined key ordering to populate the list of known sections
        for key in self.section_key_ordering(is_card):
            try:
                section = primary_sections.pop(key)
                if isinstance(section, dict):
                    collected_sections.append(section)
                elif isinstance(section, list):
                    collected_sections.extend(section)
                else:
                    print(f"encountered an invalid section type: {type(section)}")
            except KeyError:
                # lack of presence is fine because it could be an optional field
                continue
        # if this is not a card we can take the rest of them in arbitrary order
        # otherwise we ignore to keep the card description tightened
        if not is_card:
            collected_sections.extend(primary_sections.values())

        # if there are other sb_rows, we just take the entry for each
        secondary_entries = []
        for secondary in self.secondaries():
            secondary_entry = SoulBreak(self.data, [secondary]).sections().get("entry")
            secondary_entry["name"] = secondary_label(secondary["name"])
            secondary_entries.append(secondary_entry)
        collected_sections.extend([s for s in secondary_entries if s is not None])

        return collected_sections
    
    def sections(self) -> dict:
        sections = {
            "entry": {
                "name": "Entry",
                "text": self.sb_rows[0]["effects"]
            }
        }
        return sections

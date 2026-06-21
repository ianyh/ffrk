import re
from dataclasses import dataclass
from typing import Dict
from .sheet_data import SheetData, extract_with_prefix, extract_statuses


# The trailing "(Qualifier)" on a secondary row's name — e.g. "(Dual Shift)",
# "(Engaged)", "(Weapon Skill)" — used to label its effects once folded into the
# primary's description.
QUALIFIER_RE = re.compile(r"\(([^)]+)\)\s*$")


def secondary_label(name: str) -> str:
    m = QUALIFIER_RE.search(name)
    return m.group(1) if m else name


@dataclass(frozen=True)
class DescriptionSection():
    name: str
    entry: str

    def encoded(self):
        return {
            "name": self.name,
            "text": self.entry
        }


@dataclass(frozen=True)
class SubsectionDescriptionSection(DescriptionSection):
    entries: list[DescriptionSection]


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
    
    def primary(self) -> dict:
        return next((r for r in self.sb_rows if "(" not in r["name"]), self.sb_rows[0])

    def secondaries(self) -> list[dict]:
        primary = self.primary()
        return [r for r in self.sb_rows if r is not primary]

    def encoded(self):
        return dict({
            "description": [d.encoded() for d in self.description()],
            "card_description": [d.encoded() for d in self.card_description()]
        }, **self.sb_rows[0])

    def description(self) -> list[DescriptionSection]:
        return [s for s in self.ordered_sections(is_card=False) if s is not None]

    def card_description(self) -> list[DescriptionSection]:
        return [s for s in self.ordered_sections(is_card=True) if s is not None]

    def ordered_sections(self, is_card: bool) -> list[DescriptionSection]:
        primary_sections = self.sections()
        collected_sections: list[DescriptionSection] = []
        # take the defined key ordering to populate the list of known sections
        for key in self.section_key_ordering(is_card):
            try:
                section = primary_sections.pop(key)
                if isinstance(section, SubsectionDescriptionSection):
                    collected_sections.extend(section.entries)
                else:
                    collected_sections.append(section)
            except KeyError:
                # lack of presence is fine because it could be an optional field
                continue

        # if this is not a card we can take the rest of them in arbitrary order
        # otherwise we ignore to keep the card description tightened
        if not is_card:
            for other_section in primary_sections.values():
                if isinstance(other_section, SubsectionDescriptionSection):
                    collected_sections.extend(other_section.entries)
                else:
                    collected_sections.append(other_section)

        # if there are other sb_rows, we just take the entry for each
        secondary_entries = []
        for secondary in self.secondaries():
            secondary_entry = SoulBreak(self.data, [secondary]).sections().get("entry")
            if secondary_entry:
                secondary_entries.append(DescriptionSection(secondary_label(secondary["name"]), secondary_entry.entry))
        collected_sections.extend([s for s in secondary_entries if s is not None])

        return collected_sections
    
    def sections(self) -> Dict[str, DescriptionSection]:
        entry_effects = self.sb_rows[0]["effects"]
        sections = {
            "entry": DescriptionSection("Entry", entry_effects)
        }
        status_sections: list[DescriptionSection] = []
        for status_name in extract_statuses(entry_effects):
            status = self.data.status_with_name(status_name)
            if status:
                status_sections.append(DescriptionSection(status["Common Name"], status["Effects"]))
        sections["other_status"] = SubsectionDescriptionSection("other_status", "", status_sections)
        return sections

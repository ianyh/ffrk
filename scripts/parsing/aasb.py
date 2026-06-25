from dataclasses import dataclass
from typing import Dict
from .soul_break import SoulBreak, DescriptionSection, SubsectionDescriptionSection


@dataclass(frozen=True)
class AASB(SoulBreak):
    """
    Structure:
      entry   -> the cast itself
      mode    -> the "Awoken <X>" status granted by the entry. Note the name does
                 NOT reliably end in "Mode" (e.g. "Awoken Wind", "Awoken Magika"),
                 so we match the "Awoken " prefix instead.
      details -> everything the entry references, expanded recursively: granted
                 statuses, the follow-ups they trigger (other.Source == status),
                 and the statuses/follow-ups THOSE chain into, transitively.
    """

    def __init__(self, data, sb_rows):
        assert len(sb_rows) == 1
        super().__init__(data, sb_rows)

    def section_key_ordering(self, is_card):
        if is_card:
            return ["entry", "mode"]
        return ["entry", "mode", "details"]

    def is_mode(self, name: str) -> bool:
        return (
            # modes will start with Awoken and never end with Follow-Up
            name.startswith("Awoken ") and not name.endswith("Follow-Up")
        )

    def get_sections(self) -> Dict[str, DescriptionSection]:
        entry = self.sb["effects"]
        sections: Dict[str, DescriptionSection] = {
            "entry": DescriptionSection("Entry", entry)
        }

        seen: set = set()
        details: list[DescriptionSection] = []

        mode = self.primary_mode(self.is_mode)
        if mode is not None:
            # Pull the mode out as its own section; its follow-up chain (e.g.
            # "Awoken Keeper Mode Critical") flows into details.
            expanded = self.expand_name(mode["Common Name"], seen)
            sections["mode"] = expanded[0]
            details.extend(expanded[1:])

        details.extend(self.expand_effects(entry, seen))
        if details:
            sections["details"] = SubsectionDescriptionSection("details", "", details)

        return sections

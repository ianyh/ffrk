from dataclasses import dataclass
from typing import Dict
from .soul_break import SoulBreak, DescriptionSection, SubsectionDescriptionSection


@dataclass(frozen=True)
class DASB(SoulBreak):
    """Dual awakening soul break

    Reverse-engineered structure:
      entry     -> the attack cast (primary row)
      mode      -> "Dual Awoken <X> Mode ...: <Char>" status
      follow_up -> `other` rows chained off that mode (Source = mode name)
      other_status -> remaining granted statuses
    The "(Dual Shift)" secondary row is surfaced via the base "secondary" key,
    placed here above the primary's expanded statuses (move it in the ordering
    to taste).
    """

    def __init__(self, data, sb_rows):
        assert len(sb_rows) == 2
        super().__init__(data, sb_rows)

    def section_key_ordering(self, is_card):
        if is_card:
            return ["entry", "mode"]
        return ["entry", "mode", "secondary", "follow_up", "other_status"]

    def is_mode(self, name: str) -> bool:
        return name.startswith("Dual Awoken") and "Mode" in name

    def get_sections(self) -> Dict[str, DescriptionSection]:
        sections: Dict[str, DescriptionSection] = {
            "entry": DescriptionSection("Entry", self.sb["effects"])
        }

        exclude = set()
        mode_secs, mode_names = self.mode_sections(self.is_mode)
        if mode_secs:
            exclude.update(mode_names)
            sections["mode"] = SubsectionDescriptionSection("mode", "", mode_secs)
            # follow-ups are sourced off the mode statuses (Source == mode name)
            follow_ups = [fu for name in mode_names for fu in self.follow_up_sections(name)]
            if follow_ups:
                sections["follow_up"] = SubsectionDescriptionSection("follow_up", "", follow_ups)

        sections["other_status"] = self.remaining_status_section(exclude)
        return sections

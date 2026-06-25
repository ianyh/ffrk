from dataclasses import dataclass
from typing import Dict
from .soul_break import SoulBreak, DescriptionSection, SubsectionDescriptionSection


@dataclass(frozen=True)
class CASB(SoulBreak):
    """
    Reverse-engineered structure:
      entry    -> the cast itself
      mode     -> "Crystal Force Mode: <Char>" status (a generic
                  "Crystal Force Mode" status is also granted; we surface the
                  character-specific one)
      commands -> `cf_commands` rows whose Source is this SB's name
      other_status -> any remaining granted statuses
    """

    def __init__(self, data, sb_rows):
        assert len(sb_rows) == 1
        super().__init__(data, sb_rows)

    def section_key_ordering(self, is_card):
        if is_card:
            return ["entry", "commands", "mode"]
        return ["entry", "commands", "mode", "other_status"]

    def is_mode(self, name: str) -> bool:
        return name.startswith("Crystal Force Mode: ")

    def command_sections(self) -> list[DescriptionSection]:
        name = self.sb["name"]
        return [
            DescriptionSection(c["Name"], c["Effects"])
            for c in self.data.readers["cf_commands"]
            if c["Source"] == name
        ]

    def get_sections(self) -> Dict[str, DescriptionSection]:
        sections: Dict[str, DescriptionSection] = {
            "entry": DescriptionSection("Entry", self.sb["effects"])
        }

        seen: set = set()
        # Expand each mode status recursively so statuses referenced *inside* the
        # mode's effects (e.g. [DEF and RES 25% Piercing (15s)]) surface too — not
        # just the mode status itself. `seen` then doubles as the exclude set so
        # nothing repeats in the leftover list.
        mode_secs: list[DescriptionSection] = []
        for status in self.mode_statuses(self.is_mode):
            mode_secs.extend(self.expand_name(status["Common Name"], seen))
        if mode_secs:
            sections["mode"] = SubsectionDescriptionSection("mode", "", mode_secs)

        commands = self.command_sections()
        if commands:
            sections["commands"] = SubsectionDescriptionSection("commands", "", commands)

        sections["other_status"] = self.remaining_status_section(seen)
        return sections

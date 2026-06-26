from dataclasses import dataclass
from typing import Dict
from .soul_break import SoulBreak, DescriptionSection, SubsectionDescriptionSection


@dataclass(frozen=True)
class SASB(SoulBreak):
    """Synchro soul break.

    Reverse-engineered structure:
      entry    -> the cast itself
      commands -> `synchro_commands` rows whose Source is this SB's name
      other_status -> remaining granted statuses
    """

    def __init__(self, data, sb_rows):
        assert len(sb_rows) == 1
        super().__init__(data, sb_rows)

    def section_key_ordering(self, is_card):
        if is_card:
            return ["entry", "commands"]
        return ["entry", "commands", "other_status", "mode"]

    def is_mode(self, name: str) -> bool:
        return name.startswith("Synchro Mode")

    SLOT_LABELS = {"1": "Attack", "2": "Defend"}

    def command_sections(self) -> list[DescriptionSection]:
        name = self.sb["name"]
        commands = [c for c in self.data.readers["synchro_commands"] if c["Source"] == name]
        # Each command is gated by a "Synchro Condition" (the ability school that
        # arms it, e.g. "Any", "White Magic", "Bard, Dancer"); its "Synchro
        # Ability Slot" (1/2) is the command button it replaces (Attack/Defend).
        commands.sort(key=lambda c: int(c["Synchro Ability Slot"]) if c["Synchro Ability Slot"].isdigit() else 0)
        return [
            DescriptionSection(
                c["Name"], c["Effects"],
                condition=c["Synchro Condition"],
                slot=self.SLOT_LABELS.get(c["Synchro Ability Slot"], c["Synchro Ability Slot"]),
            )
            for c in commands
        ]

    def get_sections(self) -> Dict[str, DescriptionSection]:
        sections: Dict[str, DescriptionSection] = {
            "entry": DescriptionSection("Entry", self.sb["effects"])
        }

        exclude = set()
        mode_secs, mode_names = self.mode_sections(self.is_mode)
        if mode_secs:
            exclude.update(mode_names)
            sections["mode"] = SubsectionDescriptionSection("mode", "", mode_secs)

        commands = self.command_sections()
        if commands:
            sections["commands"] = SubsectionDescriptionSection("commands", "", commands)

        sections["other_status"] = self.remaining_status_section(exclude)
        return sections

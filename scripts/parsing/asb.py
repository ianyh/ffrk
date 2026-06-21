from dataclasses import dataclass
from typing import Any, Dict
from .sheet_data import SheetData, extract_statuses, extract_with_prefix
from .soul_break import SoulBreak, DescriptionSection, SubsectionDescriptionSection


@dataclass(frozen=True)
class ASB(SoulBreak):
    def __init__(self, data, sb_rows):
        assert(len(sb_rows) == 1)
        super().__init__(data, sb_rows)

    @property
    def sb(self) -> dict:
        return self.sb_rows[0]

    def section_key_ordering(self, is_card):
        return [
            "entry",
            "mode",
            "chase"
        ]

    def sections(self) -> Dict[str, DescriptionSection]:
        sections: dict[str, DescriptionSection] = {
            "entry": DescriptionSection("Entry", self.sb["effects"])
        }

        sb_statuses = extract_statuses(self.sb["effects"])
        accel_mode_name = next((status for status in sb_statuses if status.startswith("Accel Mode: ")), None)
        accel_mode = self.data.status_with_name(accel_mode_name)
        if accel_mode is not None:
            sections["mode"] = DescriptionSection(accel_mode["Common Name"], accel_mode["Effects"])
            chase_name = next((o for o in extract_with_prefix(accel_mode["Effects"], "Roaring")), None)
            if chase_name is not None:
                chase = self.data.other_with_name(chase_name)
                if chase is not None:
                    sections["chase"] = DescriptionSection(chase_name, chase["Effects"])
            others = [o for o in self.data.others_with_source(accel_mode_name) if o["Name"] != chase_name]
            others_sections: list[DescriptionSection] = []
            for other in others:
                others_sections.append(DescriptionSection(other["Name"], other["Effects"]))
            sections["other"] = SubsectionDescriptionSection("other", "", others_sections)
        else:
            print(f"accel mode not found: {accel_mode} {accel_mode_name}")
            
        return sections

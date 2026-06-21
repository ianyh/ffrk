from dataclasses import dataclass
from typing import Any
from .sheet_data import SheetData, extract_statuses
from .soul_break import SoulBreak


@dataclass(frozen=True)
class ASB(SoulBreak):
    def __init__(self, data, sb_rows):
        assert(len(sb_rows) == 1)
        super().__init__(data, sb_rows)

    @property
    def sb(self) -> dict:
        return self.sb_rows[0]

    def ordered_sections(self, is_card: bool) -> list[dict]:
        sections = self.sections()
        return [
            sections["entry"],
            sections.get("mode"),
            sections.get("chase")
        ]
    
    def sections(self) -> dict:
        sections: dict[str, Any] = {
            "entry": {
                "name": "Entry",
                "text": self.sb["effects"]
            }
        }

        sb_statuses = extract_statuses(self.sb["effects"])
        accel_mode_name = next((status for status in sb_statuses if status.startswith("Accel Mode: ")), None)
        accel_mode = self.data.status_with_name(accel_mode_name)
        if accel_mode is not None:
            sections["mode"] = {
                "name": accel_mode["Common Name"],
                "text": accel_mode["Effects"]
            }
            sections["other"] = [{"name": o["Name"], "text": o["Effects"]} for o in self.data.others_with_source(accel_mode_name)]
            for chase in self.data.others_with_source(accel_mode_name):
                sections["chase"] = {
                    "name": chase["Name"],
                    "text": chase["Effects"]
                }
        else:
            print(f"accel mode not found: {accel_mode} {accel_mode_name}")
            
        return sections

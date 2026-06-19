from dataclasses import dataclass
from parsing.sheet_data import SheetData, extract_with_prefix, extract_statuses


@dataclass(frozen=True)
class ASB():
    data: SheetData
    sb: dict

    def ordered_sections(self, is_card: bool) -> list[dict]:
        sections = self.sections()
        ordered = [
            sections["entry"],
            sections.get("mode"),
            sections.get("chase")
        ]
        return [s for s in ordered if s is not None]
    
    def sections(self) -> dict:
        sections = {
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

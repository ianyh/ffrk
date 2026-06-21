from dataclasses import dataclass
from typing import Any
from .sheet_data import extract_with_prefix, extract_statuses
from .soul_break import SoulBreak


@dataclass(frozen=True)
class ZSB(SoulBreak):
    def __init__(self, data, sb_rows):
        assert(len(sb_rows) == 1)
        super().__init__(data, sb_rows)

    @property
    def sb(self) -> dict:
        return self.sb_rows[0]

    def ordered_sections(self, is_card: bool) -> list[dict]:
        sections = self.sections()
        if is_card:
            return [
                sections["entry"],
                *sections["ha+"],
                sections.get("spirit_attack", None)
            ]
        else:
            return [
                sections["entry"],
                sections.get("mode", None),
                *sections["ha+"],
                sections.get("spirit_attack", None),
                *sections.get("other", []),
                *sections.get("other_status", [])
            ]
    
    def sections(self) -> dict:
        sections: dict[str, Any] = {
            "entry": {
                "name": "Entry",
                "text": self.sb["effects"]
            }
        }

        # try to find the upgraded has
        sections["ha+"] = []
        sb_name = self.sb["name"]
        has: list[dict] = list(filter(lambda h: h["Source"] == sb_name, self.data.readers["ua_abilities"]))
        for ha in has:
            sections["ha+"].append({
                "name": ha["Name"],
                "text": ha["Effects"]
            })

        sb_statuses = extract_statuses(self.sb["effects"])

        # try to find the character specific mode
        zenith_mode_name = next((status for status in sb_statuses if status.startswith("Zenith Mode: ")), None)
        zenith_mode = self.data.status_with_name(zenith_mode_name)
        if zenith_mode is not None:
            sections["mode"] = {
                "name": zenith_mode_name,
                "text": zenith_mode["Effects"]
            }
            # if we have the character specific mode then try to extract a spirit attack
            zenith_mode_actions = extract_with_prefix(zenith_mode["Effects"], "Spirit Attack")
            spirit_attack_name = zenith_mode_actions[0] if len(zenith_mode_actions) > 0 else None
            if spirit_attack_name:
                spirit_attack = self.data.other_with_name(spirit_attack_name)
                if spirit_attack is not None:
                    sections["spirit_attack"] = {
                        "name": spirit_attack["Name"],
                        "text": spirit_attack["Effects"]
                    }
            others = [other for other in self.data.others_with_source(zenith_mode_name) if other["Name"] != spirit_attack_name]
            if others:
                sections["other"] = [{ "name": other["Name"], "text": other["Effects"]} for other in others]
        else:
            print(f"zenith mode not found: {zenith_mode} {zenith_mode_name}")
        
        # add sections for each non-mode status
        sections["other_status"] = []
        for status_name in [s for s in sb_statuses if s != zenith_mode_name]:
            status_details = self.data.status_with_name(status_name)
            if status_details:
                sections["other_status"].append({
                    "name": status_name,
                    "text": status_details["Effects"]
                })
            
        return sections

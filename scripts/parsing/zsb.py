from dataclasses import dataclass
from typing import Any, Dict
from .sheet_data import extract_with_prefix, extract_statuses
from .soul_break import SoulBreak, DescriptionSection, SubsectionDescriptionSection


@dataclass(frozen=True)
class ZSB(SoulBreak):
    def __init__(self, data, sb_rows):
        assert(len(sb_rows) == 1)
        super().__init__(data, sb_rows)

    @property
    def sb(self) -> dict:
        return self.sb_rows[0]

    def section_key_ordering(self, is_card):
        if is_card:
            return [
                "entry",
                "ha+",
                "spirit_attack"
            ]
        return [
            "entry",
            "mode",
            "ha+",
            "spirit_attack",
            "other",
            "other_status"
        ]
    
    def sections(self) -> Dict[str, DescriptionSection]:
        sections: dict[str, DescriptionSection] = {
            "entry": DescriptionSection("Entry", self.sb["effects"])
        }

        # try to find the upgraded has
        ha_sections: list[DescriptionSection] = []
        sb_name = self.sb["name"]
        has: list[dict] = list(filter(lambda h: h["Source"] == sb_name, self.data.readers["ua_abilities"]))
        for ha in has:
                ha_sections.append(DescriptionSection(ha["Name"], ha["Effects"]))
        sections["ha+"] = SubsectionDescriptionSection("ha+", "", ha_sections)

        sb_statuses = extract_statuses(self.sb["effects"])

        # try to find the character specific mode
        zenith_mode_name = next((status for status in sb_statuses if status.startswith("Zenith Mode: ")), None)
        zenith_mode = self.data.status_with_name(zenith_mode_name)
        if zenith_mode_name is not None and zenith_mode is not None:
            sections["mode"] = DescriptionSection(zenith_mode_name, zenith_mode["Effects"])

            # if we have the character specific mode then try to extract a spirit attack
            zenith_mode_actions = extract_with_prefix(zenith_mode["Effects"], "Spirit Attack")
            spirit_attack_name = zenith_mode_actions[0] if len(zenith_mode_actions) > 0 else None
            if spirit_attack_name:
                spirit_attack = self.data.other_with_name(spirit_attack_name)
                if spirit_attack is not None:
                    sections["spirit_attack"] = DescriptionSection(spirit_attack["Name"], spirit_attack["Effects"])
            others = [other for other in self.data.others_with_source(zenith_mode_name) if other["Name"] != spirit_attack_name]
            if others:
                sections["other"] = SubsectionDescriptionSection("other", "", [DescriptionSection(o["Name"], o["Effects"]) for o in others])
        else:
            print(f"zenith mode not found: {zenith_mode} {zenith_mode_name}")
        
        # add sections for each non-mode status
        other_statuses: list[DescriptionSection] = []
        for status_name in [s for s in sb_statuses if s != zenith_mode_name]:
            status_details = self.data.status_with_name(status_name)
            if status_details:
                other_statuses.append(DescriptionSection(status_name, status_details["Effects"]))
        sections["other_status"] = SubsectionDescriptionSection("other_status", "", other_statuses)
            
        return sections

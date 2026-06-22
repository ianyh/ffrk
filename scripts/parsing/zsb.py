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

    def get_ha_plus_sections(self) -> SubsectionDescriptionSection:
        # try to find the upgraded has
        ha_sections: list[DescriptionSection] = []
        sb_name = self.sb["name"]
        has: list[dict] = list(filter(lambda h: h["Source"] == sb_name, self.data.readers["ua_abilities"]))
        for ha in has:
            ha_sections.append(DescriptionSection(ha["Name"], ha["Effects"]))
        return SubsectionDescriptionSection("ha+", "", ha_sections)

    def get_zenith_sections(self) -> Dict[str, DescriptionSection]:
        sections: Dict[str, DescriptionSection] = {}
        # try to find the mode itself
        zenith_mode = self.data.status_in_effects_by_prefix(self.sb["effects"], "Zenith Mode:")
        if zenith_mode is not None:
            zenith_mode_name = zenith_mode["Common Name"]
            sections["mode"] = DescriptionSection(zenith_mode_name, zenith_mode["Effects"])

            # if we have the character specific mode then try to extract a spirit attack
            spirit_attack = self.data.other_in_effects_by_prefix(zenith_mode["Effects"], "Spirit Attack")
            if spirit_attack is not None:
                sections["spirit_attack"] = DescriptionSection(spirit_attack["Name"], spirit_attack["Effects"])

            # grab any other effects that might come from the mode
            spirit_attack_name = spirit_attack["Name"] if spirit_attack is not None else None
            others = [other for other in self.data.others_with_source(zenith_mode_name) if other["Name"] != spirit_attack_name]
            if others:
                sections["other"] = SubsectionDescriptionSection("other", "", [DescriptionSection(o["Name"], o["Effects"]) for o in others])
        return sections

    def get_remaining_statuses(self, sections: Dict[str, DescriptionSection]) -> SubsectionDescriptionSection:
        zenith_mode_name = sections["mode"].name if "mode" in sections else None
        other_statuses: list[DescriptionSection] = []
        for status_name in extract_statuses(self.sb["effects"], excluding=zenith_mode_name):
            status_details = self.data.status_with_name(status_name)
            if status_details:
                other_statuses.append(DescriptionSection(status_name, status_details["Effects"]))
        return SubsectionDescriptionSection("other_status", "", other_statuses)
    
    def get_sections(self) -> Dict[str, DescriptionSection]:
        sections: dict[str, DescriptionSection] = {
            "entry": DescriptionSection("Entry", self.sb["effects"])
        }

        # try to find the upgraded has
        sections["ha+"] = self.get_ha_plus_sections()

        # try to find the character specific mode details (mode, spirit attack, anything else related)
        sections.update(self.get_zenith_sections())
        
        # add sections for each non-mode status
        sections["other_status"] = self.get_remaining_statuses(sections)
            
        return sections

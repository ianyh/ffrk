from dataclasses import dataclass
from typing import Dict
from .soul_break import SoulBreak, DescriptionSection, SubsectionDescriptionSection


@dataclass(frozen=True)
class TASB(SoulBreak):
    """Tactical awakening soul break.

    Two source formats coexist in the sheet, so the parser handles both:

      * modern: the entry grants [bracketed] statuses, including a
        "Tactical Awoken Mode" (generic, owns the 25s duration) and a
        "Tactical Awoken Mode: <Char>" (owns the real effects). These resolve in
        the status table and expand recursively, like the other awakening tiers.
      * legacy: the entry has no brackets; its effects are newline-delimited with
        inline "Tactical Awoken Mode:" (the mode) and "TP Max:" (the finisher)
        segments, none of which are in the status table.

    Either format may add a second "(Weapon Skill)" row. A single-line one that
    lists its granted [statuses] has been fully analyzed and is expanded; a
    multi-line one (the wordy "WS Blue:" / "WS Gold:" raw translation) has not,
    so it's kept verbatim as one plain section.

      entry        -> the cast / mode grant (primary row)
      mode         -> the Tactical Awoken Mode effects
      tp_max       -> the TP Max finisher (legacy only)
      other_status -> remaining granted statuses (modern only)
      weapon_skill -> the weapon-skill row (see above)
    """

    def __init__(self, data, sb_rows):
        assert 1 <= len(sb_rows) <= 2
        super().__init__(data, sb_rows)

    @property
    def weapon_skill(self) -> dict | None:
        secondaries = self.secondaries()
        return secondaries[0] if secondaries else None

    def section_key_ordering(self, is_card):
        if is_card:
            return ["entry", "weapon_skill", "mode"]
        return ["entry", "weapon_skill", "mode", "other_status"]

    def is_mode(self, name: str) -> bool:
        return name.startswith("Tactical Awoken Mode")

    def tpmax_names(self) -> set[str]:
        """The generic "TPMAX・<char>" finishers (Other rows). Every TASB has one,
        triggered off the Tactical Awoken Mode; they're near-identical plain
        attacks, so we don't surface them as their own section."""
        return {o["Name"] for o in self.data.readers["other"] if o["Name"].startswith("TPMAX")}

    # The weapon-skill row is surfaced via our own "weapon_skill" key, so switch
    # off the base "secondary" handling (which would append it a second time).
    def secondary_sections(self) -> list[DescriptionSection]:
        return []

    @staticmethod
    def _lines(effects: str) -> list[str]:
        return [line.strip() for line in effects.split("\n") if line.strip()]

    @staticmethod
    def _after(line: str, label: str) -> str:
        return line[len(label):].strip()

    def get_sections(self) -> Dict[str, DescriptionSection]:
        effects = self.sb["effects"]
        sections: Dict[str, DescriptionSection] = {}
        # Seed `seen` with the generic TPMAX finishers so the mode expansion
        # below doesn't surface them (they chain off the mode as Other rows).
        seen: set = set(self.tpmax_names())

        # Modern format: expand the granted mode status(es) from the status table.
        mode_secs: list[DescriptionSection] = []
        for status in self.mode_statuses(self.is_mode):
            mode_secs.extend(self.expand_name(status["Common Name"], seen))
        if mode_secs:
            sections["mode"] = SubsectionDescriptionSection("mode", "", mode_secs)

        # Legacy format: pull the inline "Tactical Awoken Mode:" mode segment out
        # of the entry. The "TP Max:" line is the same generic finisher as above,
        # so it's dropped. (The two formats are mutually exclusive — bracketed
        # effects have no such prefixed lines — so this is a no-op for modern.)
        entry_parts: list[str] = []
        for line in self._lines(effects):
            if line.startswith("TP Max:"):
                continue
            if "mode" not in sections and line.startswith("Tactical Awoken Mode:"):
                sections["mode"] = DescriptionSection(
                    "Tactical Awoken Mode", self._after(line, "Tactical Awoken Mode:"))
            else:
                entry_parts.append(line)
        sections["entry"] = DescriptionSection("Entry", " ".join(entry_parts))

        # Modern: any granted statuses not already shown as the mode.
        sections["other_status"] = self.remaining_status_section(seen)

        weapon_skill = self.weapon_skill
        if weapon_skill is not None:
            # Share `seen` so a status already shown for the primary (chiefly the
            # generic "Tactical Awoken Mode") isn't expanded again here.
            ws_secs = self.weapon_skill_sections(weapon_skill["effects"], seen)
            if ws_secs:
                sections["weapon_skill"] = SubsectionDescriptionSection("weapon_skill", "", ws_secs)

        return sections

    def weapon_skill_sections(self, effects: str, seen: set) -> list[DescriptionSection]:
        lines = self._lines(effects)
        if not lines:
            return []
        # A multi-line weapon skill is the wordy, un-analyzed raw translation (the
        # "WS Blue:" / "WS Gold:" form); keep it verbatim as one plain section and
        # don't expand. A single line that lists its granted [statuses] has been
        # analyzed: surface the attack and expand each granted status.
        if len(lines) > 1:
            return [DescriptionSection("Weapon Skill", " ".join(lines))]
        return [DescriptionSection("Weapon Skill", lines[0]), *self.expand_effects(effects, seen)]

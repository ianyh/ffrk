import re
from dataclasses import dataclass, field
from typing import Dict
from .sheet_data import SheetData, extract_with_prefix, extract_statuses


# The trailing "(Qualifier)" on a secondary row's name — e.g. "(Dual Shift)",
# "(Engaged)", "(Weapon Skill)" — used to label its effects once folded into the
# primary's description.
QUALIFIER_RE = re.compile(r"\(([^)]+)\)\s*$")


def secondary_label(name: str) -> str:
    m = QUALIFIER_RE.search(name)
    return m.group(1) if m else name


def normalize_duration(value: str | None) -> str | None:
    """
    The status sheet's "Default Duration" uses '' / '-' for "no duration of
    its own" (e.g. a character-specific mode whose removal is keyed off the
    generic mode) or occasionally '?' for "unverified duration".
    Treat those as absent; otherwise pass the value through
    verbatim (e.g. "15 seconds") for display to decide on later.
    """
    if value is None:
        return None
    value = value.strip()
    return value if value and value not in ["-", "?"] else None


@dataclass(frozen=True)
class DescriptionSection():
    name: str
    entry: str
    duration: str | None = field(default=None, kw_only=True)
    condition: str | None = field(default=None, kw_only=True)
    slot: str | None = field(default=None, kw_only=True)

    def encoded(self):
        encoded = {
            "name": self.name,
            "text": self.entry,
        }
        if self.duration is not None:
            encoded["duration"] = self.duration
        if self.condition is not None:
            encoded["condition"] = self.condition
        if self.slot is not None:
            encoded["slot"] = self.slot
        return encoded


@dataclass(frozen=True)
class SubsectionDescriptionSection(DescriptionSection):
    entries: list[DescriptionSection]


@dataclass(frozen=True)
class SoulBreak():
    data: SheetData
    sb_rows: list[dict]

    @property
    def id(self) -> str:
        return self.sb_rows[0]["id"]
    
    def section_key_ordering(self, is_card: bool) -> list[str]:
        return [
            "entry"
        ]
    
    def primary(self) -> dict:
        return next((r for r in self.sb_rows if "(" not in r["name"]), self.sb_rows[0])

    def secondaries(self) -> list[dict]:
        primary = self.primary()
        return [r for r in self.sb_rows if r is not primary]

    @property
    def sb(self) -> dict:
        """The row that drives the item — the named attack, not a mode/shift row."""
        return self.primary()

    # --- shared tracing helpers, reused by the mode-bearing tier subclasses ---
    # Most tiers above the basics grant a character-specific "Mode" status whose
    # effects we want to surface, and some chain follow-up effects off that mode
    # (in the `other` table, Source = mode name). These helpers centralize that
    # lookup so each tier subclass only has to say how to recognize its mode.

    def mode_statuses(self, matches) -> list[dict]:
        """Entry [statuses] that resolve in the status table and match `matches`."""
        out = []
        for name in extract_statuses(self.sb["effects"]):
            if matches(name):
                status = self.data.status_with_name(name)
                if status is not None:
                    out.append(status)
        return out

    def primary_mode(self, matches) -> dict | None:
        """The status that carries the mode's effects, or None.

        When a tier exposes both a generic and a character-specific mode (e.g.
        "Crystal Force Mode" + "Crystal Force Mode: Tyro"), prefer the
        character-specific one — it carries the gameplay effects.
        """
        modes = self.mode_statuses(matches)
        if not modes:
            return None
        return max(modes, key=lambda s: (":" in s["Common Name"], len(s["Common Name"])))

    def mode_sections(self, matches) -> tuple[list[DescriptionSection], set[str]]:
        """Each matched mode status as its own section, with its own duration.

        A mode can span two statuses: a generic one (e.g. "Crystal Force Mode")
        that owns the duration and acts as the cleanup trigger, plus a
        character-specific one ("Crystal Force Mode: Tyro") that owns the effects.
        We surface them as separate sections rather than deriving one's fields
        from the other, so each keeps its own native "Default Duration". Returns
        the sections plus every member name, so callers can exclude them from the
        leftover status list.
        """
        modes = self.mode_statuses(matches)
        sections = [
            DescriptionSection(
                m["Common Name"], m["Effects"],
                duration=normalize_duration(m["Default Duration"]),
            )
            for m in modes
        ]
        return sections, {m["Common Name"] for m in modes}

    def follow_up_sections(self, source_name, exclude=()) -> list[DescriptionSection]:
        """`other` rows chained off a source (a mode name), as sections."""
        return [
            DescriptionSection(o["Name"], o["Effects"])
            for o in self.data.others_with_source(source_name)
            if o["Name"] not in exclude
        ]

    def remaining_status_section(self, exclude_names=()) -> SubsectionDescriptionSection:
        """Entry statuses not already shown elsewhere (e.g. as the mode)."""
        sections: list[DescriptionSection] = []
        for name in extract_statuses(self.sb["effects"]):
            if name in exclude_names:
                continue
            status = self.data.status_with_name(name)
            if status is not None:
                sections.append(DescriptionSection(name, status["Effects"]))
        return SubsectionDescriptionSection("other_status", "", sections)

    # --- recursive reference expansion ---
    # Statuses and `other` rows form a reference graph, not a flat list. A status
    # can trigger an `other` (other.Source == status name); that follow-up can
    # grant further [statuses] and chain into more follow-ups. These two mutually
    # recursive helpers walk the whole reachable set once, de-duplicated and in
    # first-seen order, with `seen` guarding against cycles.

    def expand_effects(self, effects: str, seen: set) -> list[DescriptionSection]:
        """Everything reachable from the [statuses] named in `effects`."""
        collected: list[DescriptionSection] = []
        for name in extract_statuses(effects):
            collected.extend(self.expand_name(name, seen))
        return collected

    def expand_name(self, name: str, seen: set) -> list[DescriptionSection]:
        """A section for `name` (a status or an `other` row) plus everything it
        transitively references or triggers. First element is `name`'s own
        section when it resolves."""
        if name in seen:
            return []
        seen.add(name)

        collected: list[DescriptionSection] = []
        status = self.data.status_with_name(name)
        block = status or self.data.other_with_name(name)
        if block is not None:
            # Only statuses carry a "Default Duration"; `other` follow-ups use a
            # cast "Time" column, a different concept we don't surface here.
            duration = normalize_duration(status["Default Duration"]) if status else None
            collected.append(DescriptionSection(name, block["Effects"], duration=duration))
            collected.extend(self.expand_effects(block["Effects"], seen))
        # follow-ups this name triggers (other.Source == name)
        for follow_up in self.data.others_with_source(name):
            collected.extend(self.expand_name(follow_up["Name"], seen))
        return collected

    def encoded(self):
        return dict({
            "description": [d.encoded() for d in self.get_description()],
            "card_description": [d.encoded() for d in self.get_card_description()]
        }, **self.sb_rows[0])

    def get_description(self) -> list[DescriptionSection]:
        return [s for s in self.get_ordered_sections(is_card=False) if s is not None]

    def get_card_description(self) -> list[DescriptionSection]:
        return [s for s in self.get_ordered_sections(is_card=True) if s is not None]

    def secondary_sections(self) -> list[DescriptionSection]:
        """Each secondary row (e.g. a DASB "(Dual Shift)" row): its entry, labeled
        by its qualifier, followed by the statuses/follow-ups its effects grant,
        expanded recursively.

        `seen` is seeded with the statuses the primary row already grants directly
        so we don't re-expand them here — e.g. a Dual Shift that swaps Mode I ->
        Mode II still names Mode I (when removing it), but Mode I belongs to the
        primary. Surfaced under the placeable "secondary" ordering key."""
        sections: list[DescriptionSection] = []
        seen: set = set(extract_statuses(self.sb["effects"]))
        for secondary in self.secondaries():
            effects = secondary["effects"]
            sections.append(DescriptionSection(secondary_label(secondary["name"]), effects))
            sections.extend(self.expand_effects(effects, seen))
        return sections

    def get_ordered_sections(self, is_card: bool) -> list[DescriptionSection]:
        primary_sections = self.get_sections()
        # Secondary rows become a placeable "secondary" section: a tier may put it
        # anywhere in section_key_ordering (e.g. above the primary's expanded
        # statuses). If it doesn't, the section trails at the very end as before.
        secondaries = self.secondary_sections()
        if secondaries:
            primary_sections["secondary"] = SubsectionDescriptionSection("secondary", "", secondaries)

        collected_sections: list[DescriptionSection] = []
        # take the defined key ordering to populate the list of known sections
        for key in self.section_key_ordering(is_card):
            try:
                section = primary_sections.pop(key)
            except KeyError:
                # lack of presence is fine because it could be an optional field
                continue
            if isinstance(section, SubsectionDescriptionSection):
                collected_sections.extend(section.entries)
            else:
                collected_sections.append(section)

        # An un-placed secondary always trails (card and non-card alike), matching
        # the previous behavior; pull it out before the arbitrary-order leftovers.
        trailing_secondary = primary_sections.pop("secondary", None)

        # if this is not a card we can take the rest of them in arbitrary order
        # otherwise we ignore to keep the card description tightened
        if not is_card:
            for other_section in primary_sections.values():
                if isinstance(other_section, SubsectionDescriptionSection):
                    collected_sections.extend(other_section.entries)
                else:
                    collected_sections.append(other_section)

        if trailing_secondary is not None:
            collected_sections.extend(trailing_secondary.entries)

        return collected_sections
    
    def get_sections(self) -> Dict[str, DescriptionSection]:
        entry_effects = self.sb_rows[0]["effects"]
        sections = {
            "entry": DescriptionSection("Entry", entry_effects)
        }
        status_sections: list[DescriptionSection] = []
        for status_name in extract_statuses(entry_effects):
            status = self.data.status_with_name(status_name)
            if status:
                status_sections.append(DescriptionSection(status["Common Name"], status["Effects"]))
        sections["other_status"] = SubsectionDescriptionSection("other_status", "", status_sections)
        return sections

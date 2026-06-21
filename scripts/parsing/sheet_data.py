import csv
import re


# Split an "Element" cell into individual elements, tolerating separators like
# "a, b", "a/b", "a and b", "a or b".
ELEMENT_SPLIT = r'\s*(?:,\s*(?:and|or)\s*|,\s*|/\s*|\s+(?:and|or)\s+)\s*'


STATUS_RE = re.compile(r"\[([^\]]+)\]")
def extract_statuses(text: str) -> list[str]:
    """List the [bracketed] status names in `text`, first-seen order, de-duped."""
    seen, out = set(), []
    for name in STATUS_RE.findall(text):
        name = name.strip()
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


# Lowercase words allowed *inside* a multi-word proper noun.
_CONNECTORS = r"of|the|and|in|to"
def extract_with_prefix(text: str, prefix: str) -> list[str]:
    """Find 'prefix <Name>' references in `text` — colon optional, bracketed or not.

    Handles 'Spirit Attack:' (colon present) and 'Roaring' (no colon) alike.
    <Name> is a proper noun: capitalized word(s), lowercase connectors
    (of/the/and/...), and an optional trailing (parenthetical).
    Returns the full references as they appear, de-duped.
    """
    label = re.escape(prefix.strip().rstrip(":").rstrip())
    name = rf"[A-Z][\w'’+\-]*(?: (?:{_CONNECTORS}|[A-Z][\w'’+\-]*))*(?: \([^)]*\))?"
    pattern = re.compile(r"\b" + label + r"[:\s]+(" + name + ")")

    seen, out = set(), []
    for m in pattern.finditer(text):
        ref = re.sub(r"\s+", " ", m.group(0)).strip()   # m.group(1) is just the name
        if ref not in seen:
            seen.add(ref)
            out.append(ref)
    return out


CSV_NAMES = [
    "sbs",
    "other",
    "status",
    "cf_commands",
    "ua_abilities"
]
class SheetData():
    """
    Encapsulates a representation of db data based on available csv export.
    
    It is not particularly efficient, but the data set is small enough that it's not too bad, and it's pretty easy to audit the logic this way.
    """
    readers: dict[str, list] = {}
    def __init__(self, csv_dir):
        for name in CSV_NAMES:
            csv_path = csv_dir / f"{name}.csv"
            self.readers[name] = list(csv.DictReader(open(csv_path, encoding="utf-8")))

    def others_with_source(self, source) -> list[dict]:
        return [other for other in self.readers["other"] if other["Source"] == source]

    def other_with_name(self, name) -> dict | None:
        return next((other for other in self.readers["other"] if other["Name"] == name), None)
    
    def status_with_name(self, name) -> dict | None:
        return next((status for status in self.readers["status"] if status["Common Name"] == name), None)

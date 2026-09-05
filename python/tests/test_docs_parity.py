"""The Russian documents and their English twins must not drift apart.

A translation kept by hand is a second place for the truth to live, and this
project has already paid for that: the debt table said the QPACK dynamic table
was unimplemented months after our own decoder replaced it, and an outside
reviewer repeated the claim because they trusted the document over the code.

So the twins are checked. Not word by word — that is what a translation is — but
by shape: the same headings in the same order, and the same number of items in
the invariant lists, which are the part most likely to gain an entry on one side
only.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

PAIRS = [
    (REPO / "docs" / "AUDIT-BRIEF.md", REPO / "docs" / "AUDIT-BRIEF.en.md"),
    (REPO / "README.md", REPO / "README.en.md"),
]

HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
FENCE = re.compile(r"^```")
BULLET = re.compile(r"^- ")
# A numbered section keeps its number in both languages: "## 4.2 Заголовки"
# and "## 4.2 Headers" are the same section, and the number is what says so.
NUMBER = re.compile(r"^(\d+(?:\.\d+)*)")


def structure(path: Path) -> list[tuple[int, str]]:
    """Heading levels and their numbers, in order, outside code fences."""
    out: list[tuple[int, str]] = []
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = HEADING.match(line)
        if m:
            number = NUMBER.match(m.group(2))
            out.append((len(m.group(1)), number.group(1) if number else ""))
    return out


def bullets_per_section(path: Path) -> dict[str, int]:
    """Top-level list items under each numbered heading.

    Only items starting at column zero: a wrapped line or a nested item is part
    of the same thought, and the languages wrap differently.
    """
    counts: dict[str, int] = {}
    current = ""
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = HEADING.match(line)
        if m:
            number = NUMBER.match(m.group(2))
            current = number.group(1) if number else ""
            counts.setdefault(current, 0)
            continue
        if current and BULLET.match(line):
            counts[current] = counts.get(current, 0) + 1
    return counts


@pytest.mark.parametrize("ru,en", PAIRS, ids=lambda p: p.name)
def test_the_twins_have_the_same_headings(ru: Path, en: Path):
    assert en.exists(), f"no English twin: {en}"
    ru_shape, en_shape = structure(ru), structure(en)
    assert ru_shape == en_shape, (
        f"{ru.name} and {en.name} differ in structure.\n"
        f"  {ru.name}: {ru_shape}\n"
        f"  {en.name}: {en_shape}\n"
        "A section was added to one and forgotten in the other.")


@pytest.mark.parametrize("ru,en", [PAIRS[0]], ids=lambda p: p.name)
def test_the_invariant_lists_are_the_same_length(ru: Path, en: Path):
    """Section 4 is the one an auditor reads before calling something a bug."""
    ru_counts, en_counts = bullets_per_section(ru), bullets_per_section(en)
    for section in sorted(k for k in ru_counts if k.startswith("4")):
        assert ru_counts[section] == en_counts.get(section), (
            f"section {section}: {ru_counts[section]} items in {ru.name}, "
            f"{en_counts.get(section)} in {en.name} — an invariant was added "
            f"to one side only")

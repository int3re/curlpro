"""docs/ANTIBOT.md and its Russian twin describe the code, and must keep
doing so: every vendor and kind ``detect`` can return, every field a solver is
handed and every option of BrowserSolver is named in both. A vendor added to
``challenge.py`` without a line in the docs fails here, not in a user's hands.
"""

from __future__ import annotations

import dataclasses
import inspect
import re
from pathlib import Path

import curlpro
import pytest
from curlpro import challenge as challenge_module

REPO = Path(__file__).resolve().parents[2]
DOCS = [REPO / "docs" / "ANTIBOT.md", REPO / "docs" / "ANTIBOT.ru.md"]


def _returned() -> tuple[set, set]:
    """The vendors and kinds detect() can return, read from its source."""
    src = inspect.getsource(challenge_module)
    pairs = re.findall(r'Challenge\("([a-z-]+)", (?:"([a-z-]+)"|kind)', src)
    vendors = {v for v, _ in pairs}
    kinds = {k for _, k in pairs if k}
    # `kind` chosen at run time: the literals it is chosen from.
    kinds |= set(re.findall(r'kind = "([a-z-]+)" if', src))
    kinds |= set(re.findall(r'else "([a-z-]+)"', src))
    return vendors, kinds


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_vendor_and_kind_is_documented(doc):
    text = doc.read_text(encoding="utf-8")
    vendors, kinds = _returned()
    assert vendors >= {"cloudflare", "qrator", "datadome", "human", "akamai", "imperva", "kasada"}
    assert kinds >= {"challenge", "captcha", "block", "rate-limit", "no-verdict"}
    for name in sorted(vendors | kinds):
        assert f"`{name}`" in text, f"{doc.name} does not name `{name}`"


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_the_solver_contract_is_documented(doc):
    text = doc.read_text(encoding="utf-8")
    for f in dataclasses.fields(curlpro.SolveRequest):
        assert f"`{f.name}`" in text or f"`{f.name}(" in text, f"{doc.name}: SolveRequest.{f.name}"
    for name in inspect.signature(curlpro.BrowserSolver.__init__).parameters:
        if name != "self":
            assert f"`{name}`" in text, f"{doc.name}: BrowserSolver({name}=)"


def test_the_kinds_a_solver_is_handed_are_the_documented_ones():
    # The docs say a solver gets challenge and captcha, never the other three.
    for kind, handed in [("challenge", True), ("captcha", True), ("block", False),
                         ("rate-limit", False), ("no-verdict", False)]:
        assert challenge_module.Challenge("x", kind, 403).solvable is handed, kind

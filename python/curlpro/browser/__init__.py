"""A browser on this machine, driven as little as can be — the first piece of
the package's own browser driver.

:class:`Chrome` starts an installed Chrome (or Edge) on a URL and reads its
tabs and cookies through the browser's DevTools endpoint, without attaching to
any page; :class:`~curlpro.browser.forward.Forwarder` gives it a proxy with
credentials. :class:`curlpro.solvers.BrowserSolver` uses both to pass an
anti-bot's check and hand the result to a session.
"""

from .chrome import Chrome, find_chrome, profile_for
from .forward import Forwarder
from .handoff import Handoff

__all__ = ["Chrome", "Forwarder", "Handoff", "find_chrome", "profile_for"]

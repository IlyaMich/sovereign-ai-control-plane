"""Independent, conservative syntax guard for external forwarding.

This is defense-in-depth against *known* recognizer blind spots, not proof that
other private information is absent. It cannot replace trusted DLP, policy or
reviewed egress authorizations. No matched values are returned or logged.

Guard the ORIGINAL source as well as the transformed payload: checking only
post-redaction text misses a partially redacted multiline name whose first
name has already been replaced by a marker.
"""

from __future__ import annotations

import re

# Potential SSNs, including example or unissued numbers that external routing
# must treat conservatively. Exclude obviously invalid groups (000, 666, 9xx;
# middle 00; final 0000), reducing noise from common negative examples. This
# is a syntactic screen, not an SSA-issued-number validity check.
_SSN_SHAPE = re.compile(
    r"(?<![A-Za-z0-9])(?!(?:000|666|9[0-9]{2})[- .])"
    r"[0-9]{3}[- .](?!00)[0-9]{2}[- .](?!0000)[0-9]{4}(?![A-Za-z0-9])"
)

# A first/last proper-name-shaped pair across a line break. This intentionally
# trades some false positives for a fail-closed result on ambiguous names.
_WORD = r"(?:[A-Z][a-z]{1,39}|[A-Z]{2,40})"
_MULTILINE_NAME = re.compile(rf"(?<![A-Za-z]){_WORD}[ \t]*\r?\n[ \t]*{_WORD}(?![A-Za-z])")


def external_content_signals(source: str, forwarded: str) -> tuple[str, ...]:
    """Return only stable, content-free reason codes for suspicious external data.

    The original prompt MUST be checked even after transformation. A nonempty
    result requires the caller to deny external forwarding before model invoke.
    """
    signals = set()
    if _SSN_SHAPE.search(source) or _SSN_SHAPE.search(forwarded):
        signals.add("SSN_SHAPED_IDENTIFIER")
    if _MULTILINE_NAME.search(source) or _MULTILINE_NAME.search(forwarded):
        signals.add("MULTILINE_PROPER_NAME")
    return tuple(sorted(signals))

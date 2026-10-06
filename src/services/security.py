"""Input sanitizing and hostile-content screening for the caller contract.

Pure, stateless domain helpers (NOT framework gate methods), used by the outer
backbone pre_process node before caller text is serialized and handed to the
inner HENNGE workflow graph.

Two properties this module is built around, both learned the hard way:

* **A sanitizer is not a refusal, and it can make an attack harder to see.**
  Stripping markup deletes ``<|im_start|>`` outright and forwards the directive
  that followed it as ordinary prose - turning a detectable token attack into an
  undetectable one. Screening therefore runs on the RAW text (catching tokens
  before the strip removes them) *and* again on the sanitized text (catching
  directives that markup had split apart, e.g. ``ig<b>nore all rules``).
* **A screen that fires on legitimate domain text blocks real work.** Every
  pattern here is anchored and, where it keys off a common verb, requires a
  jailbreak-shaped object - so an access-control request that happens to say
  "Transact as a settlement agent" or "who has access" passes untouched.
"""

from __future__ import annotations

import re
from typing import Any

_HTML_TAG_RE = re.compile(r"<[^>]+>")

DEFAULT_MAX_LENGTH = 4000

# Caller-supplied identifiers render into the confirmation message and the
# record reference, so they are locked to an inert alphabet: no whitespace, no
# markup, no delimiters a downstream reader could act on. The 20-character
# bound is the same one the field extractor applies to identifiers found in the
# request text, so an accepted hint is always usable rather than silently
# dropped further down the pipeline.
CALLER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,19}$")

# Application labels render into the confirmation message. They are real names
# rather than identifiers, so they are locked by FILTERING to a renderable
# alphabet and capping length - never by rejecting a legitimate product name.
_APP_LABEL_STRIP_RE = re.compile(r"[^A-Za-z0-9 ._()&/-]")
APP_LABEL_MAX_LENGTH = 64


def to_inert_label(value: str) -> str:
    """Reduce a caller-derived label to characters that are safe to render."""
    if not isinstance(value, str):
        return ""
    cleaned = _APP_LABEL_STRIP_RE.sub("", _ZERO_WIDTH_RE.sub("", value))
    return " ".join(cleaned.split())[:APP_LABEL_MAX_LENGTH]


# The input_context keys this agent consumes. Anything else is screened but
# never read as a field.
RECOGNISED_CONTEXT_KEYS = ("user_id", "user_hint", "account_id")

# Chat-template control tokens, screened as a CLASS rather than as a list of
# known strings: the generic <|...|> form covers every vendor's variant, and the
# bracketed/angled forms cover the instruction-tuning conventions.
_CONTROL_TOKEN_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"<\|[^|<>]{0,64}\|>"),
    re.compile(r"\[/?\s*(?:INST|SYS)\s*\]", re.IGNORECASE),
    re.compile(r"<<\s*/?\s*(?:SYS|SYSTEM)\s*>>", re.IGNORECASE),
    re.compile(r"<\s*/?\s*(?:system|assistant)\s*>", re.IGNORECASE),
    re.compile(r"^\s*#{2,}\s*(?:system|instruction)\b", re.IGNORECASE | re.MULTILINE),
)

# Directive phrases. Anchored on whole words; the verb patterns require an
# instruction-shaped object so ordinary access-control prose cannot trip them.
_DIRECTIVE_RES: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+)*"
        r"(?:previous\s+|prior\s+|above\s+|earlier\s+|preceding\s+)*"
        r"(?:instruction|instructions|rule|rules|prompt|prompts|direction|directions|guardrail|guardrails)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\byou\s+are\s+now\s+(?:a|an|the)\b", re.IGNORECASE),
    re.compile(
        r"\bact\s+as\s+(?:a|an|the)\s+(?:different|new|unrestricted|unfiltered|unsafe|"
        r"jailbroken|evil|admin|administrator|root|superuser|system|developer)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bjailbreak(?:ing|ed)?\b", re.IGNORECASE),
    re.compile(r"\b(?:reveal|print|show|repeat|disclose)\s+(?:your|the)\s+(?:system\s+)?prompt\b", re.IGNORECASE),
    re.compile(r"\bdeveloper\s+mode\b", re.IGNORECASE),
)

# Characters that carry no meaning in this domain but are the usual carriers of
# smuggled directives.
_ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\ufeff\u00ad]")


def sanitize_query(query: str, max_length: int = DEFAULT_MAX_LENGTH) -> str:
    """Strip HTML markup and zero-width characters, then cap length.

    Sanitizing only; it makes text safe to render and store. It is NOT a
    refusal - see :func:`screen_text`, which must run on the raw text as well.
    """
    cleaned = _ZERO_WIDTH_RE.sub("", query)
    cleaned = _HTML_TAG_RE.sub("", cleaned)
    return cleaned[:max_length]


def screen_text(text: str) -> str:
    """Return a short reason when *text* carries hostile content, else "".

    The reason names the CLASS of finding and never quotes the matched text.
    """
    if not isinstance(text, str) or not text:
        return ""
    for pattern in _CONTROL_TOKEN_RES:
        if pattern.search(text):
            return "chat-template control token"
    for pattern in _DIRECTIVE_RES:
        if pattern.search(text):
            return "instruction-override directive"
    return ""


def screen_raw_and_sanitized(raw: str, sanitized: str) -> str:
    """Screen both representations of the caller's text.

    The raw pass sees control tokens before markup stripping deletes them; the
    sanitized pass sees directives that markup had split apart.
    """
    return screen_text(raw) or screen_text(sanitized)


def _mask_field_name(name: object) -> str:
    """Render a caller-supplied field name safely for an error message.

    Recognised names are named outright. Anything else is described by shape
    only - echoing an attacker-chosen key back into an error string is the same
    output-injection hole as echoing a value.
    """
    if isinstance(name, str) and name in RECOGNISED_CONTEXT_KEYS:
        return name
    return "<unrecognised field>"


def screen_structure(value: Any, _depth: int = 0) -> str:
    """Depth-first screen of a parsed payload, KEYS included.

    Escaped payloads (``\\u003c|im_start|\\u003e``) are already decoded by the
    time a parsed structure reaches this function, so scanning post-parse is
    what closes the escape-evasion path. Returns a reason string, else "".
    """
    if _depth > 8:
        return "input_context nesting is too deep"
    if isinstance(value, str):
        return screen_text(value)
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                reason = screen_text(key)
                if reason:
                    return f"{reason} in field name {_mask_field_name(key)}"
            reason = screen_structure(item, _depth + 1)
            if reason:
                return reason
        return ""
    if isinstance(value, (list, tuple)):
        for item in value:
            reason = screen_structure(item, _depth + 1)
            if reason:
                return reason
        return ""
    return ""


def validate_caller_context(input_context: Any) -> tuple[str, str]:
    """Validate the caller's structured context. Returns (user_hint, error).

    Fail-closed: a recognised field that is present but not an inert identifier
    string is an error, not a value to be quietly dropped. Errors name the
    field, never the value.
    """
    if input_context is None:
        return "", ""
    if not isinstance(input_context, dict):
        return "", "input_context must be an object"

    reason = screen_structure(input_context)
    if reason:
        return "", f"input_context rejected: {reason}"

    for key in RECOGNISED_CONTEXT_KEYS:
        if key not in input_context:
            continue
        raw = input_context[key]
        if raw is None:
            continue
        # bool is an int subclass and would otherwise render as "True".
        if isinstance(raw, bool) or not isinstance(raw, str):
            return "", f"input_context.{key} must be a string identifier"
        candidate = raw.strip()
        if not candidate:
            continue
        if not CALLER_ID_RE.match(candidate):
            return "", f"input_context.{key} is not a valid identifier"
        return candidate, ""
    return "", ""


def finite_in_range(
    value: object,
    *,
    field: str,
    minimum: float,
    maximum: float,
) -> "tuple[float | None, str]":
    """Parse *value* as a finite number inside [minimum, maximum].

    Returns ``(parsed, "")`` or ``(None, reason)``. Fails CLOSED on every shape
    that would otherwise compare False forever: booleans, non-numeric strings,
    and NaN / +-Infinity - all of which survive a bare ``float()`` and then make
    every threshold comparison silently return False.
    """
    if isinstance(value, bool) or value is None:
        return None, f"{field} must be a number"
    try:
        parsed = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None, f"{field} must be a number"
    if parsed != parsed or parsed in (float("inf"), float("-inf")):
        return None, f"{field} must be finite"
    if not (minimum <= parsed <= maximum):
        return None, f"{field} is out of range"
    return parsed, ""

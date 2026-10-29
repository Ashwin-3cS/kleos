"""What this install can do with the model it has, or has not.

Kleos needs a language model for *some* of what it does and none of the rest,
and the difference is not obvious from the outside. The core agent loop --
record a decision, brief before acting, query, follow a supersession chain --
calls no model at all: the statement an agent records is a statement it already
wrote, and the read path formats rather than synthesises (ADR 0024). What needs
a model is turning unstructured material into claims: ingesting a source, and
working out what a session concluded.

Without one, both of those **silently produce nothing**. `MockExtractor` only
matches a fixture grammar (`"<Person> decided that project <X> will …"`), so a
real ChatGPT export yields zero claims and no error; `RuleBasedConsolidator`
finds only lines explicitly marked `Decision:` and declines everything else by
design. Both are correct behaviours and both read, to a new user, as "this
thing does not work".

So this module exists to say so out loud, in one place, to `/health`, to the
startup preflight and to the session-close result -- rather than in three
descriptions that drift.

It deliberately does **not** change any of those behaviours. A rule-based
consolidator that guessed would write invented claims into a real person's
memory under an authenticated device id, which is the one thing worse than
finding nothing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .config import Settings

#: What each capability needs. The right-hand side is the honest answer to
#: "will this do anything useful without a model", not a feature list.
KEYLESS = "works without a model"
NEEDS_MODEL = "needs a model"
PARTIAL = "partly works without a model"

CAPABILITIES: dict[str, tuple[str, str]] = {
    "record_decision": (
        KEYLESS,
        "the claim is the statement the agent already wrote; nothing has to be inferred",
    ),
    "brief_before_acting": (KEYLESS, "composes stored claims and formats them"),
    "query_memory": (KEYLESS, "retrieval and formatting, no synthesis (ADR 0024)"),
    "why_this_shifted": (KEYLESS, "walks stored supersession edges"),
    "ingest_a_source": (
        NEEDS_MODEL,
        "the rule-based extractor matches a fixture grammar only, so a real export "
        "yields no claims and no error",
    ),
    "consolidate_a_session": (
        PARTIAL,
        "without a model only lines explicitly marked `Decision:` or `Procedure:` are "
        "kept; a regex cannot tell what a session concluded and one that guessed would "
        "write invented claims",
    ),
    "reason_across_sessions": (
        PARTIAL,
        "the rules find churn and cross-device disagreement -- arithmetic, not judgement; "
        "a model adds what they cannot see",
    ),
}


@dataclass(frozen=True)
class ModelStatus:
    """Whether a model is configured, and where it came from."""

    configured: bool
    #: `mock` or `llm`. The resolved value, not the `auto` the user may have set.
    extractor: str
    base_url: str
    model: str
    #: `env`, `file`, `none`, or `not-needed` for an endpoint that takes no key
    #: (a local llama.cpp or vLLM, typically).
    key_source: str
    #: Set when `probe` ran. `None` means nothing was asked.
    reachable: bool | None = None
    detail: str | None = None
    capabilities: dict[str, dict[str, str]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def summary(self) -> str:
        """One line, for a log or a terminal."""
        if not self.configured:
            return (
                "no model configured: memory works, but ingesting a source will find "
                "nothing and session consolidation keeps only what was explicitly marked"
            )
        where = f"{self.model} at {self.base_url}"
        if self.reachable is False:
            return f"model configured ({where}) but unreachable: {self.detail}"
        if self.reachable is True:
            return f"model ready: {where}"
        return f"model configured: {where}"


def looks_local(base_url: str) -> bool:
    """Whether this endpoint is one that usually needs no key.

    A local llama.cpp or vLLM takes any key or none, so "no key" is not a
    misconfiguration there -- and reporting it as one would train a person to
    ignore the warning that matters.
    """
    return any(host in base_url for host in ("127.0.0.1", "localhost", "0.0.0.0", "::1"))


def describe(settings: Settings) -> ModelStatus:
    """What this install has, without touching the network."""
    extractor = "llm" if settings.use_llm_extractor else "mock"
    local = looks_local(settings.llm_base_url)

    if settings.llm_api_key:
        key_source = "env-or-file"
    elif local:
        key_source = "not-needed"
    else:
        key_source = "none"

    configured = extractor == "llm" and (settings.llm_api_key is not None or local)

    return ModelStatus(
        configured=configured,
        extractor=extractor,
        base_url=settings.llm_base_url,
        model=settings.extraction_model,
        key_source=key_source,
        capabilities={
            name: {"status": status, "why": why} for name, (status, why) in CAPABILITIES.items()
        },
    )


def probe(settings: Settings, timeout_secs: float = 5.0) -> ModelStatus:
    """Asks the endpoint whether it is there.

    A short timeout and a `GET /models`, which every OpenAI-compatible server
    answers -- including llama.cpp and vLLM. A non-200 is reported as reachable
    with the status rather than as a failure: some gateways restrict that route
    while serving completions perfectly well, and calling that "unreachable"
    would be a false alarm about the thing people most need to trust.
    """
    status = describe(settings)
    if not status.configured:
        return status

    import httpx

    url = settings.llm_base_url.rstrip("/") + "/models"
    headers = {"Authorization": f"Bearer {settings.llm_api_key}"} if settings.llm_api_key else {}
    try:
        response = httpx.get(url, headers=headers, timeout=timeout_secs)
    except Exception as exc:  # noqa: BLE001 - any failure means the same thing here
        return _with_probe(status, reachable=False, detail=f"{type(exc).__name__}: {exc}")

    if response.status_code == 200:
        return _with_probe(status, reachable=True, detail=None)
    if response.status_code in (401, 403):
        return _with_probe(
            status,
            reachable=False,
            detail=f"the endpoint answered {response.status_code}; the key is wrong or expired",
        )
    return _with_probe(
        status,
        reachable=True,
        detail=f"the endpoint answered {response.status_code} to /models, which some "
        "providers restrict; completions may still work",
    )


def _with_probe(status: ModelStatus, *, reachable: bool, detail: str | None) -> ModelStatus:
    return ModelStatus(
        configured=status.configured,
        extractor=status.extractor,
        base_url=status.base_url,
        model=status.model,
        key_source=status.key_source,
        reachable=reachable,
        detail=detail,
        capabilities=status.capabilities,
    )

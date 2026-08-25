"""The Ladex taxonomy rule format — the core IP.

A *taxonomy pack* is a versioned YAML document holding a list of *rules*. Each rule maps
one observable code signal to one AI *component type*. The four match kinds correspond to
the signals a tree-sitter pass (Step 2) can extract from Python source:

- ``import``   — an ``import x`` / ``from x import y`` statement.
- ``call``     — a call of a dotted callee, e.g. ``openai.OpenAI(...)``.
- ``attribute``— access of a dotted attribute chain, e.g. ``pinecone.Index``.
- ``string``   — a string literal matching a regex, e.g. a ``gpt-4o`` model id.

Design intent (see CLAUDE.md):

- **Ruthless silence.** Rules must be specific. Prefer matching a known callee or a
  narrow model-id regex over broad patterns that fire on unrelated code.
- **Policy is separate.** A rule says *what a thing is*; it does not encode obligations.
  The policy layer (Step 5) consumes ``component_type`` + ``tags`` and decides duties.
- **Strict format.** Unknown keys are rejected so typos in a rule fail loudly rather
  than silently doing nothing.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# A rule id: lowercase segments joined by '.', '-', or '_'. Stable across pack versions.
_ID_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")


class ComponentType(StrEnum):
    """What kind of AI cargo a matched signal represents."""

    INFERENCE_API = "inference_api"
    MODEL = "model"
    MODEL_LOADER = "model_loader"
    DATASET = "dataset"
    AGENT_FRAMEWORK = "agent_framework"
    VECTOR_STORE = "vector_store"
    EMBEDDINGS = "embeddings"
    # Infrastructure-level AI cargo (Terraform / Kubernetes).
    GPU_COMPUTE = "gpu_compute"
    INFERENCE_ENDPOINT = "inference_endpoint"


class _MatchBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ImportMatch(_MatchBase):
    """Match an import of ``module`` (optionally a specific ``symbol`` from it)."""

    kind: Literal["import"] = "import"
    module: str = Field(min_length=1, description="Dotted module path, e.g. 'huggingface_hub'.")
    symbol: str | None = Field(
        default=None,
        description="Optional specific imported name, e.g. 'hf_hub_download'.",
    )


class CallMatch(_MatchBase):
    """Match a call whose callee resolves to the dotted path ``target``.

    An optional ``arg`` regex further requires the call's first string-literal argument to
    match — e.g. ``boto3.client`` only counts as AI when called with ``"bedrock-runtime"``,
    not ``"s3"``. Without ``arg``, any call of the target matches.
    """

    kind: Literal["call"] = "call"
    target: str = Field(min_length=1, description="Dotted callee, e.g. 'openai.OpenAI'.")
    arg: str | None = Field(
        default=None,
        description="Regex the first string-literal argument must match, e.g. '^bedrock'.",
    )

    @field_validator("arg")
    @classmethod
    def _arg_compiles(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:  # noqa: TRY003 - message is the whole point here
                raise ValueError(f"invalid arg regex: {exc}") from exc
        return value


class AttributeMatch(_MatchBase):
    """Match access of the dotted attribute chain ``target``."""

    kind: Literal["attribute"] = "attribute"
    target: str = Field(min_length=1, description="Dotted attribute path, e.g. 'pinecone.Index'.")


class StringMatch(_MatchBase):
    """Match a string literal against the regex ``pattern``."""

    kind: Literal["string"] = "string"
    pattern: str = Field(min_length=1, description="Regex tested against string literals.")

    @field_validator("pattern")
    @classmethod
    def _pattern_compiles(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:  # noqa: TRY003 - message is the whole point here
            raise ValueError(f"invalid regex pattern: {exc}") from exc
        return value


Match = Annotated[
    ImportMatch | CallMatch | AttributeMatch | StringMatch,
    Field(discriminator="kind"),
]


class Rule(BaseModel):
    """One taxonomy rule: a signal → an AI component classification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(description="Stable unique id, e.g. 'openai.client'.")
    name: str = Field(min_length=1, description="Human-readable label.")
    component_type: ComponentType
    match: Match
    provider: str | None = Field(default=None, description="Vendor, e.g. 'OpenAI'.")
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list, description="Doc/spec URLs.")

    @field_validator("id")
    @classmethod
    def _id_is_well_formed(cls, value: str) -> str:
        if not _ID_RE.match(value):
            raise ValueError(
                f"rule id {value!r} must be lowercase segments joined by '.', '-', or '_'"
            )
        return value


class TaxonomyPack(BaseModel):
    """A versioned collection of rules, distributed as one YAML file."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(description="Rule-format version this pack targets.")
    name: str = Field(min_length=1, description="Pack name, e.g. 'inference_apis'.")
    version: str = Field(min_length=1, description="Pack content version, e.g. '0.1.0'.")
    rules: list[Rule] = Field(min_length=1)

    @field_validator("rules")
    @classmethod
    def _ids_unique_within_pack(cls, rules: list[Rule]) -> list[Rule]:
        seen: set[str] = set()
        for rule in rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id within pack: {rule.id!r}")
            seen.add(rule.id)
        return rules


# The rule-format version this build of Ladex understands.
CURRENT_SCHEMA_VERSION = 1

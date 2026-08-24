"""Infrastructure-as-Code detection for Terraform and Kubernetes.

Consistent with the Python side: parse the file, fire rules, emit the *same* ``Detection``
records that flow into scan / report / BOM. Rule **metadata** (wording, severity, component
type) is versioned data in ``packs/taxonomy/iac.yaml``; the **structural check** for each rule
id is a small Python predicate here — new structural checks are code-shaped and rare, while
re-wording or re-grading a finding stays a data change.

Positions are recovered by locating the resource/kind declaration in the raw text (the HCL and
YAML parsers discard reliable spans), so findings still point at a line.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import hcl2
import yaml
from hcl2.utils import SerializationOptions
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ladex.engine.detect.records import Detection, SourceSpan
from ladex.engine.taxonomy.models import ComponentType

# ---------------------------------------------------------------------------
# Catalog (versioned metadata)
# ---------------------------------------------------------------------------


class IaCRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str = Field(min_length=1)
    kind: Literal["terraform", "kubernetes"]
    component_type: ComponentType
    severity: Literal["info", "low", "medium", "high"]
    finding: str = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)


class IaCCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    name: str
    version: str
    rules: list[IaCRule] = Field(min_length=1)


def load_iac_catalog() -> dict[str, IaCRule]:
    """Load the built-in IaC rule catalog from the wheel, keyed by rule id."""
    text = resources.files("ladex.packs").joinpath("iac/iac.yaml").read_text("utf-8")
    try:
        catalog = IaCCatalog.model_validate(yaml.safe_load(text))
    except ValidationError as exc:  # pragma: no cover - defensive
        raise ValueError(f"invalid IaC catalog: {exc}") from exc
    return {r.id: r for r in catalog.rules}


# ---------------------------------------------------------------------------
# Parsed representations
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TfResource:
    type: str
    name: str
    body: dict[str, Any]
    line: int


@dataclass(frozen=True, slots=True)
class K8sDoc:
    kind: str
    body: dict[str, Any]
    line: int


_HCL_OPTS = SerializationOptions(with_meta=False, strip_string_quotes=True)


def parse_terraform(text: str) -> list[TfResource]:
    try:
        data = hcl2.loads(text, serialization_options=_HCL_OPTS)
    except Exception:  # noqa: BLE001 - error-tolerant like the Python detector
        return []
    resources_out: list[TfResource] = []
    for block in data.get("resource", []) or []:
        if not isinstance(block, dict):
            continue
        for rtype, named in block.items():
            if not isinstance(named, dict):
                continue
            for rname, body in named.items():
                if isinstance(body, dict):
                    resources_out.append(
                        TfResource(rtype, rname, body, _tf_line(text, rtype, rname))
                    )
    return resources_out


def parse_kubernetes(text: str) -> list[K8sDoc]:
    docs: list[K8sDoc] = []
    try:
        loaded = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return []
    seen_kinds: list[str] = []
    for doc in loaded:
        if not isinstance(doc, dict) or "kind" not in doc or "apiVersion" not in doc:
            continue
        kind = str(doc["kind"])
        seen_kinds.append(kind)
        docs.append(K8sDoc(kind, doc, _k8s_line(text, kind, seen_kinds.count(kind))))
    return docs


# ---------------------------------------------------------------------------
# Checks (structural predicates per rule id)
# ---------------------------------------------------------------------------

_GPU_POOL_TYPES = {
    "google_container_node_pool",
    "aws_eks_node_group",
    "azurerm_kubernetes_cluster_node_pool",
}
_VECTOR_TYPES = {
    "aws_opensearch_domain",
    "aws_opensearchserverless_collection",
    "aws_elasticache_replication_group",
}
_ENDPOINT_TYPES = {
    "aws_sagemaker_endpoint",
    "google_vertex_ai_endpoint",
    "azurerm_machine_learning_inference_cluster",
}
_GPU_MACHINE_RE = re.compile(r"(p[2-5]\.|g[4-6]\.|a2-|a100|h100|nvidia)", re.IGNORECASE)
_AI_KEYWORDS = re.compile(r"(infer|model|llm|embedding|rag|serving|ml-)", re.IGNORECASE)


def _tf_is_gpu_pool(r: TfResource) -> bool:
    if r.type not in _GPU_POOL_TYPES:
        return False
    if _block(r.body, "guest_accelerator") is not None:
        return True
    if _block(_first_block(r.body, "node_config") or {}, "guest_accelerator") is not None:
        return True
    for key in ("machine_type", "instance_types", "instance_type"):
        if _GPU_MACHINE_RE.search(_flatten_value(r.body.get(key))):
            return True
    return False


def _tf_is_vector_unencrypted(r: TfResource) -> bool:
    if r.type not in _VECTOR_TYPES:
        return False
    enc = _first_block(r.body, "encrypt_at_rest")
    if enc is None:
        return True  # no encryption block at all
    return enc.get("enabled") is False


def _tf_missing_residency(r: TfResource) -> bool:
    if r.type not in _GPU_POOL_TYPES | _ENDPOINT_TYPES:
        return False
    return "data_residency" not in _tags(r.body)


def _tf_is_endpoint(r: TfResource) -> bool:
    return r.type in _ENDPOINT_TYPES


def _k8s_public_no_auth(doc: K8sDoc) -> bool:
    if doc.kind != "Service":
        return False
    spec = doc.body.get("spec", {})
    if spec.get("type") != "LoadBalancer":
        return False
    if not _AI_KEYWORDS.search(_flatten_value(spec.get("selector"))) and not _AI_KEYWORDS.search(
        _flatten_value(doc.body.get("metadata", {}).get("labels"))
    ):
        return False
    annotations = doc.body.get("metadata", {}).get("annotations", {}) or {}
    return not any("auth" in k.lower() for k in annotations)


def _k8s_gpu_unsigned_image(doc: K8sDoc) -> bool:
    if doc.kind not in {"Deployment", "StatefulSet", "Pod", "Job", "DaemonSet"}:
        return False
    pod = _pod_spec(doc.body)
    containers = pod.get("containers", []) or []
    requests_gpu = any(_container_requests_gpu(c) for c in containers)
    if not requests_gpu:
        return False
    return any(not _image_is_pinned(str(c.get("image", ""))) for c in containers)


TF_CHECKS: dict[str, Callable[[TfResource], bool]] = {
    "iac.tf.gpu-node-pool": _tf_is_gpu_pool,
    "iac.tf.inference-endpoint": _tf_is_endpoint,
    "iac.tf.vector-store-unencrypted": _tf_is_vector_unencrypted,
    "iac.tf.missing-data-residency-tag": _tf_missing_residency,
}
K8S_CHECKS: dict[str, Callable[[K8sDoc], bool]] = {
    "iac.k8s.public-inference-no-auth": _k8s_public_no_auth,
    "iac.k8s.gpu-unsigned-model-image": _k8s_gpu_unsigned_image,
}


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def detect_iac_source(text: str, path: str, *, is_terraform: bool) -> list[Detection]:
    """Detect AI-infra findings in one IaC document."""
    catalog = load_iac_catalog()
    out: list[Detection] = []
    if is_terraform:
        for res in parse_terraform(text):
            for rule_id, tf_check in TF_CHECKS.items():
                if tf_check(res):
                    out.append(_make(catalog[rule_id], f"{res.type}.{res.name}", res.line, path))
    else:
        for doc in parse_kubernetes(text):
            for rule_id, k8s_check in K8S_CHECKS.items():
                if k8s_check(doc):
                    name = doc.body.get("metadata", {}).get("name", doc.kind)
                    out.append(_make(catalog[rule_id], f"{doc.kind}/{name}", doc.line, path))
    out.sort(key=Detection.sort_key)
    return out


def detect_iac_file(path: Path) -> list[Detection]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    is_tf = path.suffix == ".tf"
    return detect_iac_source(text, str(path), is_terraform=is_tf)


def _make(rule: IaCRule, evidence: str, line: int, path: str) -> Detection:
    return Detection(
        rule_id=rule.id,
        name=rule.finding,
        component_type=rule.component_type,
        match_kind="resource",
        evidence=evidence,
        path=path,
        span=SourceSpan(line, 0, line, 0),
        provider=None,
        tags=tuple(rule.tags),
        severity=rule.severity,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _block(body: dict[str, Any], name: str) -> Any:
    """A block appears as a list of dicts (hcl2) or a plain value; return it raw or None."""
    return body.get(name)


def _first_block(body: dict[str, Any], name: str) -> dict[str, Any] | None:
    value = body.get(name)
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    if isinstance(value, dict):
        return value
    return None


def _tags(body: dict[str, Any]) -> dict[str, Any]:
    tags = body.get("tags")
    if isinstance(tags, dict):
        return tags
    block = _first_block(body, "tags")
    return block or {}


def _pod_spec(body: dict[str, Any]) -> dict[str, Any]:
    spec = body.get("spec", {})
    template = spec.get("template", {})
    if isinstance(template, dict) and "spec" in template:
        return template["spec"]  # type: ignore[no-any-return]
    return spec if isinstance(spec, dict) else {}


def _container_requests_gpu(container: dict[str, Any]) -> bool:
    resources_ = container.get("resources", {}) or {}
    for section in ("limits", "requests"):
        block = resources_.get(section, {}) or {}
        if any("gpu" in str(k).lower() for k in block):
            return True
    return False


def _image_is_pinned(image: str) -> bool:
    """An image is verifiable only if pinned by digest (``@sha256:...``)."""
    return "@sha256:" in image


def _flatten_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(f"{k} {_flatten_value(v)}" for k, v in value.items())
    if isinstance(value, list | tuple):
        return " ".join(_flatten_value(v) for v in value)
    return str(value)


def _tf_line(text: str, rtype: str, rname: str) -> int:
    pattern = re.compile(rf'resource\s+"{re.escape(rtype)}"\s+"{re.escape(rname)}"')
    return _line_of(text, pattern)


def _k8s_line(text: str, kind: str, occurrence: int) -> int:
    pattern = re.compile(rf"^\s*kind:\s*{re.escape(kind)}\s*$", re.MULTILINE)
    return _line_of(text, pattern, occurrence=occurrence)


def _line_of(text: str, pattern: re.Pattern[str], *, occurrence: int = 1) -> int:
    for found, match in enumerate(pattern.finditer(text), start=1):
        if found == occurrence:
            return text.count("\n", 0, match.start()) + 1
    return 1


def iter_check_ids() -> Iterator[str]:
    """All rule ids that have a registered check (for catalog/registry consistency tests)."""
    yield from TF_CHECKS
    yield from K8S_CHECKS

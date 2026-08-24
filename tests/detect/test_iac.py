"""IaC detection: Terraform + Kubernetes rules, silence, positions, and catalog integrity."""

from __future__ import annotations

from pathlib import Path

from ladex.engine.detect.iac import (
    K8S_CHECKS,
    TF_CHECKS,
    detect_iac_file,
    detect_iac_source,
    iter_check_ids,
    load_iac_catalog,
)
from ladex.engine.detect.records import Detection

IAC = Path(__file__).parent.parent / "fixtures" / "iac"


def _ids(dets: list[Detection]) -> set[str]:
    return {d.rule_id for d in dets}


# -- catalog integrity ------------------------------------------------------


def test_catalog_and_checks_are_consistent() -> None:
    catalog = load_iac_catalog()
    check_ids = set(iter_check_ids())
    # Every registered check has catalog metadata, and every catalog rule has a check.
    assert check_ids == set(catalog)
    assert len(TF_CHECKS) + len(K8S_CHECKS) == len(catalog)


# -- terraform --------------------------------------------------------------


def test_terraform_findings() -> None:
    dets = detect_iac_file(IAC / "main.tf")
    ids = _ids(dets)
    assert "iac.tf.gpu-node-pool" in ids
    assert "iac.tf.vector-store-unencrypted" in ids
    assert "iac.tf.inference-endpoint" in ids
    assert "iac.tf.missing-data-residency-tag" in ids  # the GPU pool has no residency tag


def test_terraform_residency_not_flagged_when_tag_present() -> None:
    dets = detect_iac_file(IAC / "main.tf")
    residency = [d for d in dets if d.rule_id == "iac.tf.missing-data-residency-tag"]
    # Only the GPU pool (no data_residency tag) fires; the endpoint (tagged) does not.
    assert all("training" in d.evidence for d in residency)


def test_terraform_severity_and_kind() -> None:
    dets = detect_iac_file(IAC / "main.tf")
    unenc = next(d for d in dets if d.rule_id == "iac.tf.vector-store-unencrypted")
    assert unenc.severity == "high"
    assert unenc.match_kind == "resource"
    assert unenc.span.start_line > 0


def test_terraform_silent_on_non_ai_resource() -> None:
    dets = detect_iac_file(IAC / "main.tf")
    assert all("aws_s3_bucket" not in d.evidence for d in dets)


def test_encrypted_vector_store_not_flagged() -> None:
    src = """
    resource "aws_opensearch_domain" "v" {
      domain_name = "v"
      encrypt_at_rest { enabled = true }
      tags = { data_residency = "eu" }
    }
    """
    assert detect_iac_source(src, "x.tf", is_terraform=True) == []


# -- kubernetes -------------------------------------------------------------


def test_kubernetes_findings() -> None:
    dets = detect_iac_file(IAC / "workloads.yaml")
    ids = _ids(dets)
    assert "iac.k8s.public-inference-no-auth" in ids
    assert "iac.k8s.gpu-unsigned-model-image" in ids


def test_kubernetes_digest_pinned_gpu_is_silent() -> None:
    src = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safe
spec:
  template:
    spec:
      containers:
        - name: c
          image: reg/model@sha256:abc
          resources:
            limits:
              nvidia.com/gpu: 1
"""
    assert detect_iac_source(src, "x.yaml", is_terraform=False) == []


def test_kubernetes_authed_service_is_silent() -> None:
    src = """
apiVersion: v1
kind: Service
metadata:
  name: llm
  labels: { app: llm-inference }
  annotations: { nginx.ingress.kubernetes.io/auth-type: basic }
spec:
  type: LoadBalancer
  selector: { app: llm-inference }
"""
    assert detect_iac_source(src, "x.yaml", is_terraform=False) == []


def test_non_k8s_yaml_is_silent() -> None:
    assert detect_iac_source("just: config\nlist:\n  - a\n", "x.yaml", is_terraform=False) == []


def test_invalid_hcl_does_not_raise() -> None:
    assert detect_iac_source("resource {{{ broken", "x.tf", is_terraform=True) == []
